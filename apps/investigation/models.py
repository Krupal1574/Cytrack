import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _
from apps.intelligence.models import IndicatorOfCompromise


class CorrelationReport(models.Model):
    """
    Materialized correlation snapshot for a single IOC.

    This is a cached compute result produced by CorrelationService.
    It is rebuilt:
      - Every 6 hours via Celery
      - When the related IOC is updated (via Django signal)
      - When ingestion completes (via Django signal)
      - Manually via `manage.py rebuild_correlations`

    The investigation API serves this model by default.
    Pass ?live=true to bypass the cache and invoke CorrelationService directly.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    ioc = models.OneToOneField(
        IndicatorOfCompromise,
        on_delete=models.CASCADE,
        related_name='correlation_report',
        db_index=True
    )

    # --- Composite Scores (0–100) ---
    risk_score = models.IntegerField(
        default=0,
        help_text=_('Composite risk score 0–100')
    )
    source_overlap_score = models.IntegerField(
        default=0,
        help_text=_('Score contribution from source overlap (0–30)')
    )
    confidence_score = models.IntegerField(
        default=0,
        help_text=_('Score derived from IOC confidence field (0–25)')
    )
    correlation_score = models.IntegerField(
        default=0,
        help_text=_('Score reflecting actor/CVE relationship depth (0–45)')
    )

    # --- Relationship Counts (denormalized for fast reads) ---
    source_count = models.IntegerField(default=0)
    actor_count = models.IntegerField(default=0)
    vulnerability_count = models.IntegerField(default=0)
    pulse_count = models.IntegerField(default=0)

    # --- Evidence Chain ---
    evidence = models.JSONField(
        default=list,
        help_text=_('Human-readable list of evidence strings explaining the score')
    )

    # --- Timing ---
    last_computed = models.DateTimeField(
        auto_now=True,
        help_text=_('When this report was last recomputed')
    )

    class Meta:
        ordering = ['-risk_score']
        verbose_name = 'Correlation Report'
        verbose_name_plural = 'Correlation Reports'

    def __str__(self):
        return f'Report for {self.ioc} — risk={self.risk_score}'
