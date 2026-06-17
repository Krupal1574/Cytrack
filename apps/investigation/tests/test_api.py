"""
API integration tests for the investigation endpoints.

Tests:
- GET /api/v1/investigation/ioc/<uuid>/ — cached mode
- GET /api/v1/investigation/ioc/<uuid>/?live=true — live mode
- GET /api/v1/investigation/ip/<ip>/
- GET /api/v1/investigation/domain/<domain>/
- GET /api/v1/investigation/hash/<hash>/
- 404 handling for all endpoints
- Authentication enforcement
- Response schema validation (cache_age_seconds, last_correlation_timestamp, is_live, risk_score)
"""
import pytest
from rest_framework.test import APIClient
from apps.accounts.models import User
from apps.intelligence.models import IndicatorOfCompromise, IndicatorType, ThreatActor, Vulnerability
from apps.ingestion.models import Source
from apps.investigation.models import CorrelationReport
from apps.investigation.services import CorrelationService


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def viewer_user(db):
    return User.objects.create_user(
        username='investigator',
        email='inv@example.com',
        password='password123',
        role='viewer'
    )


@pytest.fixture
def test_source(db):
    s, _ = Source.objects.get_or_create(name='OTX')
    return s


@pytest.fixture
def test_ioc(db, test_source):
    ioc = IndicatorOfCompromise.objects.create(
        type=IndicatorType.IPV4,
        value='185.220.101.50',
        severity='critical',
        confidence=90,
    )
    ioc.source_nodes.add(test_source)
    return ioc


@pytest.fixture
def test_ioc_with_report(test_ioc):
    return CorrelationService.build_report(test_ioc)


@pytest.mark.django_db
class TestInvestigationAuth:
    def test_unauthenticated_ioc_returns_401(self, api_client, test_ioc):
        url = f'/api/v1/investigation/ioc/{test_ioc.id}/'
        response = api_client.get(url)
        assert response.status_code == 401

    def test_unauthenticated_ip_returns_401(self, api_client):
        response = api_client.get('/api/v1/investigation/ip/1.2.3.4/')
        assert response.status_code == 401


@pytest.mark.django_db
class TestInvestigateByIOC:
    def test_cached_mode_returns_200(self, api_client, viewer_user, test_ioc_with_report, test_ioc):
        api_client.force_authenticate(user=viewer_user)
        url = f'/api/v1/investigation/ioc/{test_ioc.id}/'
        response = api_client.get(url)
        assert response.status_code == 200
        data = response.json()
        assert data['is_live'] is False
        assert 'risk_score' in data
        assert 'source_overlap_score' in data
        assert 'confidence_score' in data
        assert 'cache_age_seconds' in data
        assert 'last_correlation_timestamp' in data
        assert isinstance(data['evidence'], list)

    def test_live_mode_returns_200(self, api_client, viewer_user, test_ioc):
        api_client.force_authenticate(user=viewer_user)
        url = f'/api/v1/investigation/ioc/{test_ioc.id}/?live=true'
        response = api_client.get(url)
        assert response.status_code == 200
        data = response.json()
        assert data['is_live'] is True
        assert data['cache_age_seconds'] == 0
        assert 'risk_score' in data

    def test_cached_mode_hydrates_on_demand(self, api_client, viewer_user, test_ioc):
        """If no report exists, cached mode creates one on-demand."""
        assert not CorrelationReport.objects.filter(ioc=test_ioc).exists()
        api_client.force_authenticate(user=viewer_user)
        url = f'/api/v1/investigation/ioc/{test_ioc.id}/'
        response = api_client.get(url)
        assert response.status_code == 200
        assert CorrelationReport.objects.filter(ioc=test_ioc).exists()

    def test_nonexistent_ioc_returns_404(self, api_client, viewer_user):
        api_client.force_authenticate(user=viewer_user)
        url = '/api/v1/investigation/ioc/00000000-0000-0000-0000-000000000000/'
        response = api_client.get(url)
        assert response.status_code == 404

    def test_response_includes_sources(self, api_client, viewer_user, test_ioc_with_report, test_ioc):
        api_client.force_authenticate(user=viewer_user)
        url = f'/api/v1/investigation/ioc/{test_ioc.id}/'
        response = api_client.get(url)
        data = response.json()
        assert isinstance(data['sources'], list)
        assert len(data['sources']) >= 1
        assert data['sources'][0]['name'] == 'OTX'


@pytest.mark.django_db
class TestInvestigateByIP:
    def test_known_ip_returns_200(self, api_client, viewer_user, test_ioc):
        api_client.force_authenticate(user=viewer_user)
        response = api_client.get('/api/v1/investigation/ip/185.220.101.50/')
        assert response.status_code == 200
        data = response.json()
        assert data['ioc']['value'] == '185.220.101.50'

    def test_live_mode_via_ip(self, api_client, viewer_user, test_ioc):
        api_client.force_authenticate(user=viewer_user)
        response = api_client.get('/api/v1/investigation/ip/185.220.101.50/?live=true')
        assert response.status_code == 200
        assert response.json()['is_live'] is True

    def test_unknown_ip_returns_404(self, api_client, viewer_user):
        api_client.force_authenticate(user=viewer_user)
        response = api_client.get('/api/v1/investigation/ip/99.99.99.99/')
        assert response.status_code == 404


@pytest.mark.django_db
class TestInvestigateByDomain:
    def test_known_domain_returns_200(self, api_client, viewer_user, db):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.DOMAIN,
            value='malicious.example.com',
            severity='high',
            confidence=75
        )
        api_client.force_authenticate(user=viewer_user)
        response = api_client.get('/api/v1/investigation/domain/malicious.example.com/')
        assert response.status_code == 200
        assert response.json()['ioc']['value'] == 'malicious.example.com'

    def test_unknown_domain_returns_404(self, api_client, viewer_user):
        api_client.force_authenticate(user=viewer_user)
        response = api_client.get('/api/v1/investigation/domain/notexist.com/')
        assert response.status_code == 404


@pytest.mark.django_db
class TestInvestigateByHash:
    def test_known_md5_returns_200(self, api_client, viewer_user, db):
        ioc = IndicatorOfCompromise.objects.create(
            type=IndicatorType.MD5,
            value='d41d8cd98f00b204e9800998ecf8427e',
            severity='medium',
            confidence=60
        )
        api_client.force_authenticate(user=viewer_user)
        response = api_client.get(
            '/api/v1/investigation/hash/d41d8cd98f00b204e9800998ecf8427e/'
        )
        assert response.status_code == 200

    def test_unknown_hash_returns_404(self, api_client, viewer_user):
        api_client.force_authenticate(user=viewer_user)
        response = api_client.get('/api/v1/investigation/hash/aabbccdd/')
        assert response.status_code == 404
