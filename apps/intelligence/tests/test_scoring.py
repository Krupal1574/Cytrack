import pytest
from django.utils import timezone
from datetime import timedelta
from apps.intelligence.models import IndicatorOfCompromise, ThreatActor, IndicatorType
from apps.intelligence.scoring import ThreatScoringEngine

from apps.ingestion.models import Source

@pytest.mark.django_db
class TestScoringEngine:
    @pytest.fixture(autouse=True)
    def setup_sources(self):
        self.source_otx, _ = Source.objects.get_or_create(name='OTX')
        self.source_abuseipdb, _ = Source.objects.get_or_create(name='AbuseIPDB')
        self.source_vt, _ = Source.objects.get_or_create(name='VT')

    def test_ioc_score_calculation(self):
        # High severity, high confidence, many sources
        ioc1 = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4,
            value="192.168.1.100",
            severity='critical',
            confidence=100
        )
        ioc1.source_nodes.add(self.source_otx, self.source_abuseipdb, self.source_vt)
        score1 = ThreatScoringEngine.calculate_ioc_score(ioc1)
        assert score1 > 90

        # Low severity, low confidence, 1 source
        ioc2 = IndicatorOfCompromise.objects.create(
            type=IndicatorType.DOMAIN,
            value="example.com",
            severity='low',
            confidence=20
        )
        ioc2.source_nodes.add(self.source_otx)
        score2 = ThreatScoringEngine.calculate_ioc_score(ioc2)
        assert score2 < 40

        # Recency decay (30+ days old)
        ioc3 = IndicatorOfCompromise.objects.create(
            type=IndicatorType.MD5,
            value="e59ff97941044f85df5297e1c302d260",
            severity='critical',
            confidence=100,
            last_seen=timezone.now() - timedelta(days=40)
        )
        ioc3.source_nodes.add(self.source_otx, self.source_abuseipdb, self.source_vt)
        score3 = ThreatScoringEngine.calculate_ioc_score(ioc3)
        assert score3 < score1 # Lost the 10 recency points

    def test_threat_actor_scoring(self):
        actor = ThreatActor.objects.create(name="APT28")
        
        # High score IOC
        ioc1 = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4,
            value="10.0.0.1",
            severity='critical',
            confidence=90
        )
        ioc1.source_nodes.add(self.source_otx, self.source_abuseipdb)
        actor.iocs.add(ioc1)
        
        # Low score IOC
        ioc2 = IndicatorOfCompromise.objects.create(
            type=IndicatorType.DOMAIN,
            value="bad-site.ru",
            severity='low',
            confidence=10
        )
        ioc2.source_nodes.add(self.source_otx)
        actor.iocs.add(ioc2)
        
        # Test update_all_scores
        ThreatScoringEngine.update_all_scores()
        
        actor.refresh_from_db()
        # Average of the two
        s1 = ThreatScoringEngine.calculate_ioc_score(ioc1)
        s2 = ThreatScoringEngine.calculate_ioc_score(ioc2)
        assert actor.threat_score == int((s1 + s2) / 2)
