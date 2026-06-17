import requests
from typing import Any, Dict, List
from django.utils import timezone
import datetime
from apps.intelligence.models import Vulnerability
from .base import BaseIngestionSource
import logging

logger = logging.getLogger(__name__)

class CISAKEVIngestionSource(BaseIngestionSource):
    """
    CISA Known Exploited Vulnerabilities Catalog Ingestion Source.
    Fetches the JSON catalog and updates Vulnerability objects.
    """
    source_name = "CISA KEV"
    base_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def fetch_data(self) -> Any:
        response = self.session.get(self.base_url)
        response.raise_for_status()
        return response.json().get('vulnerabilities', [])

    def parse_data(self, data: Any) -> List[Dict]:
        # Data is already a list of dicts with the info we need
        return data

    def process_item(self, item: Dict):
        """
        Save CISA KEV data into Vulnerability models.
        """
        cve_id = item.get('cveID')
        
        if not cve_id:
            logger.warning(f"[{self.source_name}] Invalid item missing CVE ID: {item}")
            return
            
        try:
            # Parse dates
            added_date = item.get('dateAdded')
            due_date = item.get('dueDate')
            
            def _parse_date(date_str):
                if date_str:
                    try:
                        return datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
                    except ValueError:
                        pass
                return None
                
            kev_added = _parse_date(added_date)
            kev_due = _parse_date(due_date)
            
            # Upsert the Vulnerability
            vuln, created = Vulnerability.objects.get_or_create(
                cve_id=cve_id,
                defaults={
                    'description': item.get('shortDescription', ''),
                    'is_kev': True,
                    'kev_added_date': kev_added,
                    'kev_due_date': kev_due,
                    'kev_action': item.get('requiredAction', '')
                }
            )
            
            if not created:
                # Update existing
                vuln.is_kev = True
                vuln.kev_added_date = kev_added
                vuln.kev_due_date = kev_due
                vuln.kev_action = item.get('requiredAction', '')
                if not vuln.description and item.get('shortDescription'):
                    vuln.description = item.get('shortDescription')
                vuln.save()
                
            logger.debug(f"[{self.source_name}] Processed Vulnerability {cve_id} (Created: {created})")
            
        except Exception as e:
            logger.error(f"[{self.source_name}] Error processing item {item}: {e}")
