import logging
from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(queue='correlation', bind=True, max_retries=3)
def rebuild_all_correlations(self):
    """
    Rebuild CorrelationReport for every IOC in the database.
    Scheduled every 6 hours via django_celery_beat.
    Also triggered by source post-sync signal (countdown=30s).
    """
    try:
        from apps.investigation.services import CorrelationService
        result = CorrelationService.build_all()
        logger.info('[tasks] rebuild_all_correlations: %s', result)
        return result
    except Exception as exc:
        logger.error('[tasks] rebuild_all_correlations failed: %s', exc)
        raise self.retry(exc=exc, countdown=120)


@shared_task(queue='correlation', bind=True, max_retries=3)
def rebuild_single_correlation(self, ioc_id: str):
    """
    Rebuild CorrelationReport for a single IOC.
    Triggered by the post_save signal on IndicatorOfCompromise.
    """
    try:
        from apps.intelligence.models import IndicatorOfCompromise
        from apps.investigation.services import CorrelationService

        ioc = IndicatorOfCompromise.objects.prefetch_related(
            'source_nodes', 'threat_actors', 'vulnerabilities', 'pulses'
        ).get(id=ioc_id)

        report = CorrelationService.build_report(ioc)
        logger.debug('[tasks] Rebuilt report for IOC %s — risk=%s', ioc.value, report.risk_score)
        return {'ioc_id': ioc_id, 'risk_score': report.risk_score}

    except IndicatorOfCompromise.DoesNotExist:
        logger.warning('[tasks] IOC %s not found — skipping rebuild', ioc_id)
        return None
    except Exception as exc:
        logger.error('[tasks] rebuild_single_correlation failed for %s: %s', ioc_id, exc)
        raise self.retry(exc=exc, countdown=30)
