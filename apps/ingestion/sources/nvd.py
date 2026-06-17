"""
NVD CVE Ingestion Source.

Fetches CVEs from the NIST NVD API v2 (https://services.nvd.nist.gov/rest/json/cves/2.0).

Modes:
  - Incremental (default): fetches CVEs modified since last_sync_time (up to 30-day window).
  - Bulk (initial): when no prior sync exists, fetches a configurable 30-day window.

Rate limits (unauthenticated):
  - 5 requests / 30 seconds — strictly enforced
  - Each page returns up to 2000 results (resultsPerPage default)

Stores per CVE:
  - cve_id, description, published_date, last_modified_date
  - cvss_score (v3 preferred, v2 fallback), base_score_v3, cvss_v2_score
  - severity_v3, vector_string
  - references  (list of {url, source, tags} dicts)
  - affected_products  (list of CPE strings)
"""
import datetime
import logging
import time
from typing import Any, Dict, List

from dateutil.relativedelta import relativedelta
from django.utils import timezone

from apps.intelligence.models import Vulnerability
from apps.ingestion.models import SourceStatus
from .base import BaseIngestionSource

logger = logging.getLogger(__name__)

# NVD unauthenticated: 5 requests per 30 seconds.
# We sleep 6.5s between each page to stay safely under the limit.
_NVD_REQUEST_DELAY_SECONDS = 6.5
_NVD_PAGE_SIZE = 2000


def _fmt_nvd_date(dt: datetime.datetime) -> str:
    """Format a datetime as NVD API v2 requires: 2021-08-04T00:00:00.000+00:00"""
    utc = dt.astimezone(datetime.timezone.utc)
    return utc.strftime('%Y-%m-%dT%H:%M:%S.000+00:00')


class NVDIntegrationSource(BaseIngestionSource):
    """
    NVD CVE Ingestion Source.
    Fetches CVEs incrementally from the NIST NVD API v2.
    """
    source_name = "NVD CVE"
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.api_key = __import__('os').environ.get('NVD_API_KEY')
        super().__init__()

    def _setup_auth(self):
        if self.api_key:
            self.session.headers.update({'apiKey': self.api_key})

    # ------------------------------------------------------------------
    # fetch_data: returns ALL CVEs for the date window via pagination
    # ------------------------------------------------------------------
    def fetch_data(self, start_date: datetime.datetime = None, end_date: datetime.datetime = None) -> List[Dict]:
        """
        Fetch all CVE entries for a date window, handling NVD pagination.

        Args:
            start_date: override the window start (used by bulk fetch command).
            end_date:   override the window end.

        Returns:
            List of raw NVD vulnerability dicts.
        """
        now = timezone.now()

        if start_date is None:
            last_sync = self.db_source.last_sync_time
            if not last_sync:
                # First run: fetch the previous 30 days
                start_date = now - relativedelta(days=30)
            else:
                start_date = last_sync

        if end_date is None:
            end_date = start_date + relativedelta(days=30)
            if end_date > now:
                end_date = now

        start_str = _fmt_nvd_date(start_date)
        end_str   = _fmt_nvd_date(end_date)

        logger.info('[NVD] Fetching CVEs modified %s → %s', start_str[:10], end_str[:10])

        all_vulns = []
        start_index = 0

        while True:
            params = {
                'lastModStartDate': start_str,
                'lastModEndDate':   end_str,
                'startIndex':       start_index,
                'resultsPerPage':   _NVD_PAGE_SIZE,
            }

            logger.info('[NVD] Page startIndex=%d …', start_index)
            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code in (403, 429):
                raise self.RateLimitExceeded(f'NVD rate limit: HTTP {response.status_code}')

            if response.status_code == 404:
                # NVD returns 404 for empty windows — treat as zero results
                logger.info('[NVD] 404 for window — no CVEs found')
                break

            response.raise_for_status()
            payload = response.json()

            page_vulns = payload.get('vulnerabilities', [])
            all_vulns.extend(page_vulns)

            total_results   = payload.get('totalResults', 0)
            results_per_page = payload.get('resultsPerPage', _NVD_PAGE_SIZE)

            logger.info('[NVD] Got %d/%d CVEs (page size=%d)',
                        len(all_vulns), total_results, results_per_page)

            # Advance to next page
            start_index += results_per_page
            if start_index >= total_results:
                break   # All pages fetched

            # Respect rate limit between pages
            logger.debug('[NVD] Sleeping %.1fs for rate limit …', _NVD_REQUEST_DELAY_SECONDS)
            time.sleep(_NVD_REQUEST_DELAY_SECONDS)

        return all_vulns

    # ------------------------------------------------------------------
    # parse_data: normalize raw NVD dicts
    # ------------------------------------------------------------------
    def parse_data(self, data: List[Dict]) -> List[Dict]:
        items = []

        for entry in data:
            cve = entry.get('cve', {})
            cve_id = cve.get('id')
            if not cve_id:
                continue

            # ---- Description (English preferred) ----
            description = ''
            for d in cve.get('descriptions', []):
                if d.get('lang') == 'en':
                    description = d.get('value', '')
                    break

            # ---- Published / last-modified dates ----
            published_str     = cve.get('published', '')
            last_modified_str = cve.get('lastModified', '')

            def _parse_dt(s):
                if not s:
                    return None
                for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
                    try:
                        naive = datetime.datetime.strptime(s[:26], fmt)
                        return naive.replace(tzinfo=datetime.timezone.utc)
                    except ValueError:
                        continue
                return None

            published_dt     = _parse_dt(published_str)
            last_modified_dt = _parse_dt(last_modified_str)

            # ---- CVSS Scores ----
            metrics   = cve.get('metrics', {})
            cvss3_list = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
            cvss2_list = metrics.get('cvssMetricV2',  [])

            base_score_v3 = None
            severity_v3   = ''
            vector_string = ''
            cvss_v2_score = None

            if cvss3_list:
                cvss_data     = cvss3_list[0].get('cvssData', {})
                base_score_v3 = cvss_data.get('baseScore')
                severity_v3   = cvss_data.get('baseSeverity', '')
                vector_string = cvss_data.get('vectorString', '')

            if cvss2_list:
                cvss2_data    = cvss2_list[0].get('cvssData', {})
                cvss_v2_score = cvss2_data.get('baseScore')
                if not vector_string:
                    vector_string = cvss2_data.get('vectorString', '')

            # Use v3 score if available, fall back to v2
            cvss_score = base_score_v3 if base_score_v3 is not None else cvss_v2_score

            # ---- References ----
            references = [
                {
                    'url':    ref.get('url', ''),
                    'source': ref.get('source', ''),
                    'tags':   ref.get('tags', []),
                }
                for ref in cve.get('references', [])
                if ref.get('url')
            ]

            # ---- Affected products (CPE strings) ----
            affected_products = []
            for config in cve.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe = cpe_match.get('criteria', '')
                        if cpe and cpe not in affected_products:
                            affected_products.append(cpe)

            items.append({
                'cve_id':            cve_id,
                'description':       description,
                'published_date':    published_dt,
                'last_modified_date':last_modified_dt,
                'cvss_score':        cvss_score,
                'base_score_v3':     base_score_v3,
                'cvss_v2_score':     cvss_v2_score,
                'severity_v3':       severity_v3,
                'vector_string':     vector_string,
                'references':        references,
                'affected_products': affected_products,
            })

        return items

    # ------------------------------------------------------------------
    # process_item: upsert into Vulnerability table
    # ------------------------------------------------------------------
    def process_item(self, item: Dict):
        cve_id = item.get('cve_id')
        if not cve_id:
            return

        try:
            vuln, created = Vulnerability.objects.get_or_create(
                cve_id=cve_id,
                defaults={
                    'description':       item.get('description', ''),
                    'cvss_score':        item.get('cvss_score'),
                    'base_score_v3':     item.get('base_score_v3'),
                    'cvss_v2_score':     item.get('cvss_v2_score'),
                    'severity_v3':       item.get('severity_v3', ''),
                    'vector_string':     item.get('vector_string', ''),
                    'published_date':    item.get('published_date'),
                    'last_modified_date':item.get('last_modified_date'),
                    'references':        item.get('references', []),
                    'affected_products': item.get('affected_products', []),
                }
            )

            if not created:
                # Always refresh mutable NVD fields on update
                vuln.cvss_score         = item.get('cvss_score')
                vuln.base_score_v3      = item.get('base_score_v3')
                vuln.cvss_v2_score      = item.get('cvss_v2_score')
                vuln.severity_v3        = item.get('severity_v3', '')
                vuln.vector_string      = item.get('vector_string', '')
                vuln.last_modified_date = item.get('last_modified_date')
                # Only update references/products when NVD provides them
                if item.get('references'):
                    vuln.references = item['references']
                if item.get('affected_products'):
                    vuln.affected_products = item['affected_products']
                if not vuln.description and item.get('description'):
                    vuln.description = item['description']
                if not vuln.published_date and item.get('published_date'):
                    vuln.published_date = item['published_date']
                vuln.save()

            logger.debug('[NVD] %s CVE %s (refs=%d, cpes=%d)',
                         'Created' if created else 'Updated', cve_id,
                         len(item.get('references', [])),
                         len(item.get('affected_products', [])))

        except Exception as e:
            logger.error('[NVD] Error processing %s: %s', cve_id, e)
