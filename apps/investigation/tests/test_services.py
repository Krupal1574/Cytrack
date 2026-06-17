"""
Unit tests for CorrelationService.

Tests verify:
- Score math for each individual component
- Evidence chain generation
- Source overlap score
- KEV bonus
- Active actor bonus
- Recency bonus
- build_report() persists a CorrelationReport row
- build_all() processes all IOCs
"""
import pytest
from django.utils import timezone
from datetime import timedelta

from apps.intelligence.models import IndicatorOfCompromise, IndicatorType, ThreatActor, Vulnerability
from apps.ingestion.models import Source
from apps.investigation.models import CorrelationReport
from apps.investigation.services import CorrelationService, MAX_SOURCE_SCORE, MAX_SOURCES


@pytest.fixture
def base_sources(db):
    s1, _ = Source.objects.get_or_create(name='OTX')
    s2, _ = Source.objects.get_or_create(name='AbuseIPDB')
    s3, _ = Source.objects.get_or_create(name='NVD')
    return [s1, s2, s3]


@pytest.fixture
def simple_ioc(db):
    return IndicatorOfCompromise.objects.create(
        type=IndicatorType.IPV4,
        value='1.2.3.4',
        severity='high',
        confidence=80,
    )


@pytest.mark.django_db
class TestCorrelationServiceCompute:

    def test_source_overlap_score_zero_sources(self, simple_ioc):
        data = CorrelationService.compute(simple_ioc)
        assert data['source_overlap_score'] == 0
        assert data['source_count'] == 0

    def test_source_overlap_score_partial(self, simple_ioc, base_sources):
        simple_ioc.source_nodes.add(base_sources[0])  # 1 source
        data = CorrelationService.compute(simple_ioc)
        expected = int((1 / MAX_SOURCES) * MAX_SOURCE_SCORE)
        assert data['source_overlap_score'] == expected
        assert data['source_count'] == 1

    def test_source_overlap_score_maxes_at_five(self, simple_ioc, base_sources):
        # Add more than MAX_SOURCES sources
        for s in base_sources:
            simple_ioc.source_nodes.add(s)
        # Add 2 more sources to exceed MAX_SOURCES
        s4, _ = Source.objects.get_or_create(name='CISA')
        s5, _ = Source.objects.get_or_create(name='VT')
        s6, _ = Source.objects.get_or_create(name='Extra')
        simple_ioc.source_nodes.add(s4, s5, s6)
        data = CorrelationService.compute(simple_ioc)
        assert data['source_overlap_score'] == MAX_SOURCE_SCORE  # capped at 30

    def test_confidence_score_max(self, simple_ioc):
        simple_ioc.confidence = 100
        simple_ioc.save()
        data = CorrelationService.compute(simple_ioc)
        assert data['confidence_score'] == 25

    def test_confidence_score_zero(self, simple_ioc):
        simple_ioc.confidence = 0
        simple_ioc.save()
        data = CorrelationService.compute(simple_ioc)
        assert data['confidence_score'] == 0

    def test_kev_bonus_applied(self, simple_ioc):
        vuln = Vulnerability.objects.create(cve_id='CVE-2025-9999', is_kev=True, cvss_score=9.8)
        simple_ioc.vulnerabilities.add(vuln)
        data = CorrelationService.compute(simple_ioc)
        # correlation_score contains kev_bonus (10) + severity + recency
        assert data['vulnerability_count'] == 1
        assert any('CISA KEV' in e for e in data['evidence'])
        # correlation_score must be at least 10 (kev_bonus)
        assert data['correlation_score'] >= 10

    def test_kev_bonus_not_applied_without_kev(self, simple_ioc):
        vuln = Vulnerability.objects.create(cve_id='CVE-2025-1111', is_kev=False, cvss_score=5.0)
        simple_ioc.vulnerabilities.add(vuln)
        data = CorrelationService.compute(simple_ioc)
        assert not any('KEV' in e for e in data['evidence'])

    def test_actor_bonus_applied_for_high_threat(self, simple_ioc):
        actor = ThreatActor.objects.create(name='APT99', threat_score=85)
        simple_ioc.threat_actors.add(actor)
        data = CorrelationService.compute(simple_ioc)
        assert data['actor_count'] == 1
        assert any('high-threat' in e for e in data['evidence'])
        assert data['correlation_score'] >= 10  # actor bonus

    def test_actor_bonus_not_applied_below_threshold(self, simple_ioc):
        actor = ThreatActor.objects.create(name='LowThreat', threat_score=40)
        simple_ioc.threat_actors.add(actor)
        data = CorrelationService.compute(simple_ioc)
        # low actor still mentioned in evidence, but no bonus
        assert data['actor_count'] == 1
        assert not any('high-threat' in e for e in data['evidence'])

    def test_recency_bonus_applied_within_7_days(self, simple_ioc):
        simple_ioc.last_seen = timezone.now() - timedelta(days=3)
        simple_ioc.save()
        data = CorrelationService.compute(simple_ioc)
        assert any('active indicator' in e for e in data['evidence'])

    def test_recency_bonus_not_applied_after_7_days(self, simple_ioc):
        simple_ioc.last_seen = timezone.now() - timedelta(days=30)
        simple_ioc.save()
        data = CorrelationService.compute(simple_ioc)
        assert not any('active indicator' in e for e in data['evidence'])

    def test_risk_score_capped_at_100(self, simple_ioc, base_sources):
        # Max out all components
        simple_ioc.confidence = 100
        simple_ioc.severity = 'critical'
        simple_ioc.last_seen = timezone.now()
        simple_ioc.save()
        for s in base_sources:
            simple_ioc.source_nodes.add(s)
        actor = ThreatActor.objects.create(name='MaxActor', threat_score=99)
        simple_ioc.threat_actors.add(actor)
        vuln = Vulnerability.objects.create(cve_id='CVE-2025-MAX', is_kev=True, cvss_score=10.0)
        simple_ioc.vulnerabilities.add(vuln)

        data = CorrelationService.compute(simple_ioc)
        assert data['risk_score'] <= 100

    def test_risk_score_minimum_zero(self, db):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.DOMAIN,
            value='minimal.example.com',
            severity='low',
            confidence=0,
        )
        data = CorrelationService.compute(ioc)
        assert data['risk_score'] >= 0


@pytest.mark.django_db
class TestCorrelationServiceBuildReport:

    def test_build_report_creates_correlation_report(self, simple_ioc, base_sources):
        simple_ioc.source_nodes.add(base_sources[0])
        report = CorrelationService.build_report(simple_ioc)

        assert report.pk is not None
        assert report.ioc == simple_ioc
        assert report.source_count == 1
        assert isinstance(report.evidence, list)

    def test_build_report_updates_existing(self, simple_ioc, base_sources):
        CorrelationService.build_report(simple_ioc)
        simple_ioc.source_nodes.add(base_sources[0], base_sources[1])
        report = CorrelationService.build_report(simple_ioc)

        # Only one report should exist
        assert CorrelationReport.objects.filter(ioc=simple_ioc).count() == 1
        assert report.source_count == 2

    def test_build_all_processes_all_iocs(self, db):
        ioc1 = IndicatorOfCompromise.objects.create(type=IndicatorType.IPV4, value='10.0.0.1', severity='high', confidence=70)
        ioc2 = IndicatorOfCompromise.objects.create(type=IndicatorType.DOMAIN, value='threat.io', severity='low', confidence=30)

        result = CorrelationService.build_all()
        assert result['built'] == 2
        assert result['failed'] == 0
        assert CorrelationReport.objects.count() == 2
