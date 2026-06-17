import logging
from celery import shared_task
from .scoring import ThreatScoringEngine

logger = logging.getLogger(__name__)

@shared_task(queue='scoring', bind=True, max_retries=3)
def recalculate_threat_scores(self):
    """Periodic task to recalculate all threat actor scores based on IOC decay."""
    try:
        ThreatScoringEngine.update_all_scores()
    except Exception as exc:
        logger.error(f"Failed to recalculate threat scores: {exc}")
        self.retry(exc=exc, countdown=60)
