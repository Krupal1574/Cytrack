"""
Tests: core app — health check endpoint
"""
import pytest
from rest_framework import status
from unittest.mock import patch


@pytest.mark.django_db
class TestHealthCheck:
    def test_health_check_returns_200(self, api_client):
        response = api_client.get('/health/')
        assert response.status_code == status.HTTP_200_OK

    def test_health_check_no_auth_required(self, api_client):
        """Health check must work without authentication for load balancers."""
        response = api_client.get('/health/')
        assert response.status_code != status.HTTP_401_UNAUTHORIZED

    def test_health_check_response_structure(self, api_client):
        response = api_client.get('/health/')
        data = response.json()
        assert 'status' in data
        assert 'checks' in data
        assert 'response_time_ms' in data
        assert 'database' in data['checks']

    def test_health_check_status_healthy(self, api_client):
        response = api_client.get('/health/')
        data = response.json()
        assert data['checks']['database']['status'] == 'ok'

    def test_ping_endpoint(self, api_client):
        response = api_client.get('/health/ping/')
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {'status': 'pong'}

    def test_health_check_db_failure(self, api_client):
        """Health check should return 503 when DB is unavailable."""
        with patch('django.db.connection.ensure_connection', side_effect=Exception('DB down')):
            response = api_client.get('/health/')
            assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            data = response.json()
            assert data['status'] == 'degraded'
