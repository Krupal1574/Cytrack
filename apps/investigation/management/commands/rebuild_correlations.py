"""
Management command to manually rebuild all CorrelationReport rows.

Usage:
    python manage.py rebuild_correlations
    python manage.py rebuild_correlations --ioc <uuid>
    python manage.py rebuild_correlations --dry-run
"""
from django.core.management.base import BaseCommand, CommandError
from apps.investigation.services import CorrelationService


class Command(BaseCommand):
    help = 'Rebuild CorrelationReport cache for all IOCs or a specific one.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--ioc',
            type=str,
            dest='ioc_id',
            help='UUID of a specific IOC to rebuild. Rebuilds all if omitted.',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            dest='dry_run',
            help='Compute scores without writing to the database.',
        )

    def handle(self, *args, **options):
        ioc_id = options.get('ioc_id')
        dry_run = options.get('dry_run')

        if ioc_id:
            self._rebuild_single(ioc_id, dry_run)
        else:
            self._rebuild_all(dry_run)

    def _rebuild_single(self, ioc_id: str, dry_run: bool):
        from apps.intelligence.models import IndicatorOfCompromise

        try:
            ioc = IndicatorOfCompromise.objects.prefetch_related(
                'source_nodes', 'threat_actors', 'vulnerabilities', 'pulses'
            ).get(id=ioc_id)
        except IndicatorOfCompromise.DoesNotExist:
            raise CommandError(f'IOC with id {ioc_id!r} does not exist.')

        if dry_run:
            data = CorrelationService.compute(ioc)
            self.stdout.write(
                self.style.WARNING(
                    f'[DRY RUN] IOC {ioc.value}: risk={data["risk_score"]}, '
                    f'sources={data["source_count"]}, actors={data["actor_count"]}'
                )
            )
        else:
            report = CorrelationService.build_report(ioc)
            self.stdout.write(
                self.style.SUCCESS(
                    f'Rebuilt report for {ioc.value}: risk={report.risk_score}'
                )
            )

    def _rebuild_all(self, dry_run: bool):
        from apps.intelligence.models import IndicatorOfCompromise

        iocs = IndicatorOfCompromise.objects.prefetch_related(
            'source_nodes', 'threat_actors', 'vulnerabilities', 'pulses'
        ).all()

        total = iocs.count()
        self.stdout.write(f'Processing {total} IOC(s)...')

        built = 0
        failed = 0

        for ioc in iocs:
            try:
                if dry_run:
                    data = CorrelationService.compute(ioc)
                    self.stdout.write(
                        f'  [DRY] {ioc.value}: risk={data["risk_score"]}'
                    )
                else:
                    CorrelationService.build_report(ioc)
                built += 1
            except Exception as exc:
                self.stderr.write(f'  FAILED {ioc.value}: {exc}')
                failed += 1

        label = '[DRY RUN] ' if dry_run else ''
        self.stdout.write(
            self.style.SUCCESS(
                f'{label}Done. Built: {built}, Failed: {failed}'
            )
        )
