"""Verification management command for NVD import audit."""
from django.core.management.base import BaseCommand
from django.db.models import Count


class Command(BaseCommand):
    help = 'Verify NVD import: field coverage, sample data, source status.'

    def handle(self, *args, **options):
        from apps.intelligence.models import Vulnerability, IndicatorOfCompromise
        from apps.ingestion.models import Source

        # ---- Vulnerability field coverage ----
        # Note: SQLite does not support JSONField __len__ in WHERE clauses.
        # Evaluate field population Python-side across the full table.
        all_vulns = list(Vulnerability.objects.only(
            'is_kev', 'base_score_v3', 'cvss_v2_score',
            'references', 'affected_products', 'published_date', 'vector_string'
        ))
        total    = len(all_vulns)
        kev      = sum(1 for v in all_vulns if v.is_kev)
        with_v3  = sum(1 for v in all_vulns if v.base_score_v3 is not None)
        with_v2  = sum(1 for v in all_vulns if v.cvss_v2_score is not None)
        with_ref = sum(1 for v in all_vulns if v.references)
        with_cpe = sum(1 for v in all_vulns if v.affected_products)
        with_pub = sum(1 for v in all_vulns if v.published_date is not None)
        with_vec = sum(1 for v in all_vulns if v.vector_string)


        self.stdout.write('\n=== VULNERABILITY FIELD COVERAGE ===')
        self.stdout.write(f'Total Vulnerabilities:      {total}')
        self.stdout.write(f'CISA KEV flagged:           {kev}')
        self.stdout.write(f'Has CVSS v3 score:          {with_v3}')
        self.stdout.write(f'Has CVSS v2 score:          {with_v2}')
        self.stdout.write(f'Has references (>0 URLs):   {with_ref}')
        self.stdout.write(f'Has affected products(CPE): {with_cpe}')
        self.stdout.write(f'Has published_date:         {with_pub}')
        self.stdout.write(f'Has vector_string:          {with_vec}')

        self.stdout.write('\n=== SEVERITY DISTRIBUTION (NVD v3) ===')
        for row in (Vulnerability.objects
                    .exclude(severity_v3='')
                    .values('severity_v3')
                    .annotate(c=Count('id'))
                    .order_by('-c')):
            self.stdout.write(f"  {row['severity_v3']:<12} {row['c']}")

        self.stdout.write('\n=== SAMPLE CVE (highest CVSS v3) ===')
        sample = (Vulnerability.objects
                  .filter(base_score_v3__isnull=False)
                  .order_by('-base_score_v3')
                  .first())
        if sample:
            self.stdout.write(f'  CVE ID:         {sample.cve_id}')
            self.stdout.write(f'  Description:    {sample.description[:120]}')
            self.stdout.write(f'  CVSS v3:        {sample.base_score_v3}  ({sample.severity_v3})')
            self.stdout.write(f'  CVSS v2:        {sample.cvss_v2_score}')
            self.stdout.write(f'  Vector:         {sample.vector_string}')
            self.stdout.write(f'  Published:      {sample.published_date}')
            self.stdout.write(f'  Last Modified:  {sample.last_modified_date}')
            self.stdout.write(f'  References:     {len(sample.references)} URLs')
            if sample.references:
                ref = sample.references[0]
                self.stdout.write(f'    [0].url:      {ref.get("url", "")}')
                self.stdout.write(f'    [0].source:   {ref.get("source", "")}')
                self.stdout.write(f'    [0].tags:     {ref.get("tags", [])}')
            self.stdout.write(f'  Affected CPEs:  {len(sample.affected_products)}')
            if sample.affected_products:
                self.stdout.write(f'    [0]:          {sample.affected_products[0]}')
            self.stdout.write(f'  KEV flagged:    {sample.is_kev}')

        self.stdout.write('\n=== SAMPLE KEV + NVD CROSS-LINKED ===')
        cross = (Vulnerability.objects
                 .filter(is_kev=True, base_score_v3__isnull=False)
                 .order_by('-base_score_v3')
                 .first())
        if cross:
            self.stdout.write(f'  CVE ID:         {cross.cve_id}')
            self.stdout.write(f'  CVSS v3:        {cross.base_score_v3}  ({cross.severity_v3})')
            self.stdout.write(f'  KEV due date:   {cross.kev_due_date}')
            self.stdout.write(f'  KEV action:     {cross.kev_action[:80]}')
            self.stdout.write(f'  References:     {len(cross.references)} URLs')
            self.stdout.write(f'  CPEs:           {len(cross.affected_products)}')
        else:
            self.stdout.write('  (no KEV + NVD overlap yet in current window)')

        self.stdout.write('\n=== IOC COUNTS ===')
        ioc_total = IndicatorOfCompromise.objects.count()
        self.stdout.write(f'Total IOCs: {ioc_total}')
        for row in (IndicatorOfCompromise.objects
                    .values('type')
                    .annotate(c=Count('id'))
                    .order_by('-c')):
            self.stdout.write(f"  {row['type']:<12} {row['c']}")

        self.stdout.write('\n=== SOURCE STATUS ===')
        for s in Source.objects.all().order_by('name'):
            self.stdout.write(f'  [{s.name}]')
            self.stdout.write(f'    status:     {s.last_sync_status}')
            self.stdout.write(f'    total:      {s.total_items_ingested}')
            self.stdout.write(f'    last_sync:  {s.last_sync_time}')
            if s.error_message:
                self.stdout.write(f'    error:      {s.error_message[:100]}')
