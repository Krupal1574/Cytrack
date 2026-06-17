"""
Relationship tests — verify M2M links flow correctly into CorrelationReport.

Tests:
- IOC ↔ Source M2M → source_count and source_overlap_score
- IOC ↔ ThreatActor M2M → actor_count and actor bonus
- IOC ↔ Vulnerability M2M → vulnerability_count and KEV bonus
- IOC ↔ ThreatPulse M2M (via pulse.iocs) → pulse_count
- Multiple actors, multiple vulns, mixed KEV
- Score ordering: multi-source IOC ranks higher than single-source
"""
import pytest
from apps.intelligence.models import (
    IndicatorOfCompromise, IndicatorType,
    ThreatActor, Vulnerability, ThreatPulse
)
from apps.ingestion.models import Source
from apps.investigation.models import CorrelationReport
from apps.investigation.services import CorrelationService


@pytest.fixture
def sources(db):
    s1, _ = Source.objects.get_or_create(name='OTX')
    s2, _ = Source.objects.get_or_create(name='AbuseIPDB')
    s3, _ = Source.objects.get_or_create(name='NVD')
    return s1, s2, s3


@pytest.mark.django_db
class TestM2MRelationshipsFlowIntoReport:

    def test_source_m2m_reflected_in_source_count(self, db, sources):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4, value='2.2.2.2', severity='high', confidence=70
        )
        ioc.source_nodes.add(sources[0], sources[1])

        report = CorrelationService.build_report(ioc)
        assert report.source_count == 2
        assert report.source_overlap_score > 0

    def test_actor_m2m_reflected_in_actor_count(self, db):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4, value='3.3.3.3', severity='critical', confidence=80
        )
        a1 = ThreatActor.objects.create(name='ActorA', threat_score=90)
        a2 = ThreatActor.objects.create(name='ActorB', threat_score=55)
        ioc.threat_actors.add(a1, a2)

        report = CorrelationService.build_report(ioc)
        assert report.actor_count == 2

    def test_vulnerability_m2m_reflected_in_vuln_count(self, db):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.DOMAIN, value='vuln-test.com', severity='medium', confidence=60
        )
        v1 = Vulnerability.objects.create(cve_id='CVE-2025-0001', is_kev=False, cvss_score=7.5)
        v2 = Vulnerability.objects.create(cve_id='CVE-2025-0002', is_kev=True, cvss_score=9.8)
        ioc.vulnerabilities.add(v1, v2)

        report = CorrelationService.build_report(ioc)
        assert report.vulnerability_count == 2
        # KEV bonus should be included in correlation_score
        assert report.correlation_score >= 10

    def test_kev_evidence_in_report(self, db):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4, value='4.4.4.4', severity='critical', confidence=85
        )
        v = Vulnerability.objects.create(cve_id='CVE-2025-KEV', is_kev=True, cvss_score=9.9)
        ioc.vulnerabilities.add(v)

        report = CorrelationService.build_report(ioc)
        assert any('CVE-2025-KEV' in e for e in report.evidence)
        assert any('CISA KEV' in e for e in report.evidence)

    def test_pulse_m2m_reflected_in_pulse_count(self, db, sources):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.DOMAIN, value='pulse-test.com', severity='high', confidence=70
        )
        pulse = ThreatPulse.objects.create(
            name='Test Pulse',
            external_id='otx-pulse-001',
            source=sources[0]
        )
        pulse.iocs.add(ioc)

        report = CorrelationService.build_report(ioc)
        assert report.pulse_count == 1

    def test_multi_source_ranks_higher_than_single_source(self, db, sources):
        ioc_single = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4, value='5.5.5.1', severity='high', confidence=70
        )
        ioc_single.source_nodes.add(sources[0])

        ioc_multi = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4, value='5.5.5.2', severity='high', confidence=70
        )
        ioc_multi.source_nodes.add(sources[0], sources[1], sources[2])

        report_single = CorrelationService.build_report(ioc_single)
        report_multi = CorrelationService.build_report(ioc_multi)

        assert report_multi.risk_score > report_single.risk_score

    def test_high_actor_increases_correlation_score(self, db):
        ioc_no_actor = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4, value='6.6.6.1', severity='high', confidence=70
        )
        ioc_with_actor = IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4, value='6.6.6.2', severity='high', confidence=70
        )
        actor = ThreatActor.objects.create(name='DangerousAPT', threat_score=95)
        ioc_with_actor.threat_actors.add(actor)

        r1 = CorrelationService.build_report(ioc_no_actor)
        r2 = CorrelationService.build_report(ioc_with_actor)

        assert r2.correlation_score > r1.correlation_score

    def test_report_is_onetoone_per_ioc(self, db):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.MD5, value='abc123abc123abc123abc123abc12345', severity='low', confidence=30
        )
        CorrelationService.build_report(ioc)
        CorrelationService.build_report(ioc)  # second call should update, not create

        assert CorrelationReport.objects.filter(ioc=ioc).count() == 1
