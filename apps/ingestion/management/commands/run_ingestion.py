"""
Management command to run ingestion sources synchronously (no Celery/Redis required).

Usage:
    python manage.py run_ingestion                         # all available sources
    python manage.py run_ingestion --source cisa           # CISA KEV only
    python manage.py run_ingestion --source otx            # OTX only
    python manage.py run_ingestion --source nvd            # NVD (incremental, last 30d)
    python manage.py run_ingestion --source nvd --bulk-days 30 --bulk-offset-days 0
                                                           # NVD bulk: specific window
    python manage.py run_ingestion --source abuse          # AbuseIPDB
"""
import datetime
import logging

from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run one or all ingestion sources synchronously without Celery.'

    SOURCES = {
        'otx':   ('AlienVault OTX', 'apps.ingestion.sources.otx',        'OTXIngestionSource'),
        'abuse': ('AbuseIPDB',       'apps.ingestion.sources.abuseipdb',  'AbuseIPDBIngestionSource'),
        'cisa':  ('CISA KEV',        'apps.ingestion.sources.cisa',       'CISAKEVIngestionSource'),
        'nvd':   ('NVD CVE',         'apps.ingestion.sources.nvd',        'NVDIntegrationSource'),
    }

    def add_arguments(self, parser):
        parser.add_argument(
            '--source',
            type=str,
            choices=list(self.SOURCES.keys()),
            help='Specific source to run. Runs all if omitted.',
        )
        parser.add_argument(
            '--bulk-days',
            type=int,
            default=None,
            help='(NVD only) Number of days to fetch in one window.',
        )
        parser.add_argument(
            '--bulk-offset-days',
            type=int,
            default=0,
            help='(NVD only) How many days ago the window ends. Default 0 = now.',
        )

    def handle(self, *args, **options):
        source_key  = options.get('source')
        bulk_days   = options.get('bulk_days')
        bulk_offset = options.get('bulk_offset_days', 0)

        targets = {source_key: self.SOURCES[source_key]} if source_key else self.SOURCES

        for key, (display_name, module_path, class_name) in targets.items():
            self.stdout.write(f'\n[{display_name}] Starting ingestion…')
            try:
                import importlib
                module      = importlib.import_module(module_path)
                SourceClass = getattr(module, class_name)
                source      = SourceClass()

                # NVD bulk-fetch mode
                if key == 'nvd' and bulk_days is not None:
                    end_date   = timezone.now() - datetime.timedelta(days=bulk_offset)
                    start_date = end_date - datetime.timedelta(days=bulk_days)
                    self.stdout.write(
                        f'  Bulk window: {start_date.date()} → {end_date.date()} ({bulk_days}d)'
                    )
                    raw  = source.fetch_data(start_date=start_date, end_date=end_date)
                    items = source.parse_data(raw)
                    self.stdout.write(f'  Parsed {len(items)} CVEs, writing to DB…')
                    for item in items:
                        source.process_item(item)
                    # Update source metadata manually (run() not called)
                    from apps.ingestion.models import SourceStatus
                    source.db_source.last_sync_status    = SourceStatus.SUCCESS
                    source.db_source.last_sync_time      = timezone.now()
                    source.db_source.total_items_ingested += len(items)
                    source.db_source.error_message       = ''
                    source.db_source.save()
                    self.stdout.write(
                        self.style.SUCCESS(f'[{display_name}] ✓ Bulk import complete: {len(items)} CVEs')
                    )
                else:
                    source.run()
                    self.stdout.write(self.style.SUCCESS(f'[{display_name}] ✓ Completed'))

            except ValueError as e:
                # Missing API key — skip gracefully
                self.stdout.write(self.style.WARNING(f'[{display_name}] SKIPPED: {e}'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'[{display_name}] FAILED: {e}'))
                logger.exception('run_ingestion failed for %s', display_name)
