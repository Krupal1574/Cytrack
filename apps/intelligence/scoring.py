import logging
from django.utils import timezone
from datetime import timedelta
from apps.intelligence.models import IndicatorOfCompromise, ThreatActor

logger = logging.getLogger(__name__)

class ThreatScoringEngine:
    """
    Calculates threat scores for IOCs and Threat Actors.
    Score is 0-100.
    """
    
    # Base severity score out of 100
    SEVERITY_WEIGHTS = {
        'critical': 100,
        'high': 75,
        'medium': 50,
        'low': 25
    }

    @classmethod
    def calculate_ioc_score(cls, ioc: IndicatorOfCompromise) -> int:
        """
        Calculates an abstract 'score' for an IOC based on:
        - Base severity weight (40%)
        - Confidence (30%)
        - Number of distinct sources (20%)
        - Recency / Time Decay (10%)
        """
        # 1. Severity (0-40 points)
        severity_base = cls.SEVERITY_WEIGHTS.get(ioc.severity, 25)
        score_severity = (severity_base / 100.0) * 40
        
        # 2. Confidence (0-30 points)
        score_confidence = (ioc.confidence / 100.0) * 30
        
        # 3. Source Count (0-20 points)
        # Assuming max benefit at 3+ sources
        source_count = ioc.source_nodes.count()
        score_sources = min((source_count / 3.0) * 20, 20)
        
        # 4. Recency (0-10 points)
        # Decays over 30 days
        now = timezone.now()
        last_seen = ioc.last_seen or ioc.created_at
        days_old = (now - last_seen).days
        
        if days_old < 0:
            days_old = 0
            
        decay_factor = max(0, 1 - (days_old / 30.0))
        score_recency = decay_factor * 10
        
        final_score = int(score_severity + score_confidence + score_sources + score_recency)
        return min(max(final_score, 0), 100)

    @classmethod
    def update_threat_actor_score(cls, actor: ThreatActor):
        """
        Update a threat actor's score based on the highest scored IOCs they are associated with.
        """
        iocs = actor.iocs.all()
        if not iocs.exists():
            actor.threat_score = 50
            actor.save(update_fields=['threat_score'])
            return

        # Calculate average of top 5 highest scoring IOCs
        scores = sorted([cls.calculate_ioc_score(ioc) for ioc in iocs], reverse=True)[:5]
        avg_score = sum(scores) / len(scores)
        
        actor.threat_score = int(avg_score)
        actor.save(update_fields=['threat_score'])
        logger.debug(f"Updated ThreatActor '{actor.name}' score to {actor.threat_score}")

    @classmethod
    def update_all_scores(cls):
        """Batch update scores for actors. Called via Celery."""
        logger.info("Starting Threat Actor score recalculation.")
        for actor in ThreatActor.objects.prefetch_related('iocs').all():
            cls.update_threat_actor_score(actor)
        logger.info("Finished Threat Actor score recalculation.")
