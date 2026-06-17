"""
CorrelationService — Source of Truth for IOC Correlation.

This service is responsible for computing the full correlation profile of an
IndicatorOfCompromise. It is the authoritative calculation engine. The
CorrelationReport model is a cached snapshot of this service's output.

Score Composition
-----------------
Source Overlap (0–30)
    max_sources = 5; score = min(source_count / max_sources, 1.0) * 30

Confidence (0–25)
    score = (ioc.confidence / 100) * 25

Severity (0–15)
    critical=15, high=10, medium=5, low=2

KEV Bonus (+10)
    Any related vulnerability has is_kev=True

Active Actor Bonus (+10)
    Any related threat actor has threat_score >= 75

Recency Bonus (+10)
    last_seen within 7 days

Total maximum: 100 points
"""

import logging
from datetime import timedelta
from django.utils import timezone

from apps.intelligence.models import IndicatorOfCompromise, Vulnerability, ThreatActor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Score weights
# ---------------------------------------------------------------------------
MAX_SOURCE_SCORE = 30
MAX_SOURCES = 5

MAX_CONFIDENCE_SCORE = 25

SEVERITY_SCORES = {
    'critical': 15,
    'high': 10,
    'medium': 5,
    'low': 2,
}

KEV_BONUS = 10
ACTIVE_ACTOR_BONUS = 10
RECENCY_BONUS = 10
RECENCY_DAYS = 7

ACTIVE_ACTOR_THRESHOLD = 75


class CorrelationService:
    """
    Computes threat correlation profiles for IOC instances.

    Usage
    -----
    # Compute and persist:
    report = CorrelationService.build_report(ioc)

    # Compute only (no DB write):
    data = CorrelationService.compute(ioc)

    # Rebuild all:
    CorrelationService.build_all()
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def build_report(cls, ioc: IndicatorOfCompromise):
        """
        Compute the correlation profile for `ioc` and persist/update
        the CorrelationReport cache row.

        Returns the saved CorrelationReport instance.
        """
        # Import here to avoid circular imports
        from apps.investigation.models import CorrelationReport

        data = cls.compute(ioc)

        report, _ = CorrelationReport.objects.update_or_create(
            ioc=ioc,
            defaults={
                'risk_score': data['risk_score'],
                'source_overlap_score': data['source_overlap_score'],
                'confidence_score': data['confidence_score'],
                'correlation_score': data['correlation_score'],
                'source_count': data['source_count'],
                'actor_count': data['actor_count'],
                'vulnerability_count': data['vulnerability_count'],
                'pulse_count': data['pulse_count'],
                'evidence': data['evidence'],
            }
        )
        logger.debug(
            '[CorrelationService] Built report for IOC %s: risk=%s',
            ioc.value, report.risk_score
        )
        return report

    @classmethod
    def compute(cls, ioc: IndicatorOfCompromise) -> dict:
        """
        Compute the full correlation profile without persisting to the DB.

        Returns a dict suitable for both the CorrelationReport model fields
        and for direct API serialization (?live=true mode).
        """
        evidence = []

        # --- Fetch related data via prefetch (caller may have already done this) ---
        sources = list(ioc.source_nodes.all())
        actors = list(ioc.threat_actors.all())
        vulnerabilities = list(ioc.vulnerabilities.all())
        pulses = list(ioc.pulses.all()) if hasattr(ioc, 'pulses') else []

        # --- Source Overlap (0–30) ---
        source_count = len(sources)
        source_overlap_score = int(min(source_count / MAX_SOURCES, 1.0) * MAX_SOURCE_SCORE)
        if source_count > 0:
            source_names = ', '.join(s.name for s in sources)
            evidence.append(
                f'Reported by {source_count} independent source(s): {source_names}'
            )

        # --- Confidence (0–25) ---
        confidence_score = int((ioc.confidence / 100) * MAX_CONFIDENCE_SCORE)

        # --- Severity (0–15) ---
        severity_score = SEVERITY_SCORES.get(ioc.severity, 2)
        if ioc.severity in ('critical', 'high'):
            evidence.append(f'Severity classified as {ioc.severity.upper()}')

        # --- KEV Bonus (+10) ---
        kev_vulns = [v for v in vulnerabilities if v.is_kev]
        kev_bonus = KEV_BONUS if kev_vulns else 0
        if kev_vulns:
            kev_ids = ', '.join(v.cve_id for v in kev_vulns)
            evidence.append(
                f'Associated with {len(kev_vulns)} CISA KEV vulnerability(s): {kev_ids}'
            )

        # --- Active Actor Bonus (+10) ---
        high_actors = [a for a in actors if a.threat_score >= ACTIVE_ACTOR_THRESHOLD]
        actor_bonus = ACTIVE_ACTOR_BONUS if high_actors else 0
        if high_actors:
            actor_names = ', '.join(a.name for a in high_actors)
            evidence.append(
                f'Linked to high-threat actor(s) (score ≥{ACTIVE_ACTOR_THRESHOLD}): {actor_names}'
            )
        elif actors:
            evidence.append(
                f'Associated with threat actor(s): {", ".join(a.name for a in actors)}'
            )

        # --- Recency Bonus (+10) ---
        now = timezone.now()
        last_seen = ioc.last_seen or ioc.created_at
        days_since = (now - last_seen).days if last_seen else 999
        recency_bonus = RECENCY_BONUS if days_since <= RECENCY_DAYS else 0
        if recency_bonus:
            evidence.append(f'Last seen {days_since} day(s) ago (active indicator)')

        # --- Compute sub-scores ---
        # correlation_score = severity + kev + actor + recency (max 45)
        correlation_score = severity_score + kev_bonus + actor_bonus + recency_bonus

        # --- Final risk score (capped at 100) ---
        risk_score = min(source_overlap_score + confidence_score + correlation_score, 100)

        # --- Audit confidence from AbuseIPDB if available ---
        abuse_source = next((s for s in sources if 'AbuseIPDB' in s.name), None)
        if abuse_source and ioc.confidence >= 80:
            evidence.append(f'AbuseIPDB abuse confidence: {ioc.confidence}%')

        return {
            'risk_score': risk_score,
            'source_overlap_score': source_overlap_score,
            'confidence_score': confidence_score,
            'correlation_score': correlation_score,
            'source_count': source_count,
            'actor_count': len(actors),
            'vulnerability_count': len(vulnerabilities),
            'pulse_count': len(pulses),
            'evidence': evidence,
            # Rich relationship data for API responses
            'sources': sources,
            'actors': actors,
            'vulnerabilities': vulnerabilities,
            'pulses': pulses,
        }

    @classmethod
    def build_all(cls):
        """
        Rebuild CorrelationReport for every IOC in the database.
        Called by the Celery periodic task and the management command.
        """
        iocs = IndicatorOfCompromise.objects.prefetch_related(
            'source_nodes', 'threat_actors', 'vulnerabilities', 'pulses'
        ).all()

        built = 0
        failed = 0
        for ioc in iocs:
            try:
                cls.build_report(ioc)
                built += 1
            except Exception as exc:
                logger.error(
                    '[CorrelationService] Failed to build report for IOC %s: %s',
                    ioc.value, exc
                )
                failed += 1

        logger.info(
            '[CorrelationService] build_all complete: built=%s, failed=%s',
            built, failed
        )
        return {'built': built, 'failed': failed}
