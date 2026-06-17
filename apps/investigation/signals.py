"""
Signal handlers for the investigation app.

Triggers a CorrelationReport rebuild when:
  1. An IndicatorOfCompromise instance is saved (create or update).
  2. A Source sync completes successfully (post-ingestion).

Both signals dispatch Celery tasks to avoid blocking the request/ingestion cycle.
"""
import logging
from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)


@receiver(post_save, sender='intelligence.IndicatorOfCompromise')
def rebuild_report_on_ioc_save(sender, instance, **kwargs):
    """
    Rebuild the CorrelationReport for an IOC whenever it is saved.
    Dispatched asynchronously via Celery to avoid blocking.
    """
    try:
        from apps.investigation.tasks import rebuild_single_correlation
        rebuild_single_correlation.delay(str(instance.id))
    except Exception as exc:
        # Signal handlers must never raise — log and continue
        logger.warning(
            '[investigation.signals] Redis unavailable — skipping correlation rebuild for IOC %s: %s',
            instance.value, exc
        )


@receiver(post_save, sender='ingestion.Source')
def rebuild_all_on_source_success(sender, instance, **kwargs):
    """
    After a Source finishes a successful sync, trigger a full correlation rebuild.
    We check last_sync_status == 'success' to avoid rebuilding on every field touch.
    """
    from apps.ingestion.models import SourceStatus
    if instance.last_sync_status == SourceStatus.SUCCESS:
        try:
            from apps.investigation.tasks import rebuild_all_correlations
            # countdown=30 gives ingestion a moment to finish writing all IOCs
            rebuild_all_correlations.apply_async(countdown=30)
        except Exception as exc:
            logger.warning(
                '[investigation.signals] Redis unavailable — skipping full rebuild after source %s sync: %s',
                instance.name, exc
            )
