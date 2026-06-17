import pytest
from rest_framework.test import APIClient
from apps.accounts.models import User
from apps.intelligence.models import ThreatActor, IndicatorOfCompromise, IndicatorType

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def viewer_user():
    user = User.objects.create_user(username='viewer', email='viewer@example.com', password='password123', role='viewer')
    return user

@pytest.mark.django_db
class TestIntelligenceAPI:
    def test_dashboard_analytics_unauthenticated(self, api_client):
        response = api_client.get('/api/v1/intel/analytics/summary/')
        assert response.status_code == 401

    def test_dashboard_analytics_authenticated(self, api_client, viewer_user):
        api_client.force_authenticate(user=viewer_user)
        
        # Setup data
        actor = ThreatActor.objects.create(name="Test Actor", threat_score=80)
        IndicatorOfCompromise.objects.create(
            type=IndicatorType.IPV4,
            value="127.0.0.1",
            severity="critical"
        )
        
        response = api_client.get('/api/v1/intel/analytics/summary/')
        assert response.status_code == 200
        
        data = response.json()
        assert data['iocs']['total'] == 1
        assert data['threat_actors']['total'] == 1
        assert data['threat_actors']['high_threat'] == 1

    def test_threat_actors_api(self, api_client, viewer_user):
        api_client.force_authenticate(user=viewer_user)
        ThreatActor.objects.create(name="Actor 1", threat_score=90)
        
        response = api_client.get('/api/v1/intel/actors/')
        assert response.status_code == 200
        data = response.json()
        assert len(data['results']) == 1
        assert data['results'][0]['name'] == 'Actor 1'
