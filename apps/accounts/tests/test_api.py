"""
Tests: accounts app — API endpoints
"""
import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
class TestRegistrationAPI:
    def test_register_success(self, api_client):
        payload = {
            'email': 'newuser@cytrack.io',
            'username': 'newuser',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!',
        }
        response = api_client.post('/api/v1/auth/register/', payload)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert 'access' in data
        assert 'refresh' in data
        assert data['user']['email'] == 'newuser@cytrack.io'

    def test_register_password_mismatch(self, api_client):
        payload = {
            'email': 'newuser@cytrack.io',
            'username': 'newuser',
            'password': 'SecurePass123!',
            'password_confirm': 'DifferentPass456!',
        }
        response = api_client.post('/api/v1/auth/register/', payload)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_duplicate_email(self, api_client, viewer_user):
        payload = {
            'email': viewer_user.email,
            'username': 'anotheruser',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!',
        }
        response = api_client.post('/api/v1/auth/register/', payload)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_weak_password(self, api_client):
        payload = {
            'email': 'weak@cytrack.io',
            'username': 'weakuser',
            'password': '123',
            'password_confirm': '123',
        }
        response = api_client.post('/api/v1/auth/register/', payload)
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestLoginAPI:
    def test_login_success(self, api_client, viewer_user):
        payload = {'email': viewer_user.email, 'password': 'SecureTestPass123!'}
        response = api_client.post('/api/v1/auth/login/', payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'access' in data
        assert 'refresh' in data
        assert 'user' in data
        assert data['user']['role'] == 'VIEWER'

    def test_login_wrong_password(self, api_client, viewer_user):
        payload = {'email': viewer_user.email, 'password': 'WrongPassword!'}
        response = api_client.post('/api/v1/auth/login/', payload)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_nonexistent_user(self, api_client):
        payload = {'email': 'ghost@cytrack.io', 'password': 'pass'}
        response = api_client.post('/api/v1/auth/login/', payload)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestProfileAPI:
    def test_get_profile_authenticated(self, authenticated_client, viewer_user):
        response = authenticated_client.get('/api/v1/auth/me/')
        assert response.status_code == status.HTTP_200_OK
        assert response.json()['email'] == viewer_user.email

    def test_get_profile_unauthenticated(self, api_client):
        response = api_client.get('/api/v1/auth/me/')
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_profile(self, authenticated_client):
        response = authenticated_client.patch(
            '/api/v1/auth/profile/',
            {'first_name': 'Test', 'last_name': 'Analyst'},
        )
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestAPIKeyEndpoint:
    def test_regenerate_api_key(self, authenticated_client, viewer_user):
        old_key = str(viewer_user.api_key)
        response = authenticated_client.post('/api/v1/auth/api-key/regenerate/')
        assert response.status_code == status.HTTP_200_OK
        assert response.json()['api_key'] != old_key


@pytest.mark.django_db
class TestRBACPermissions:
    """Test that role-based access control is enforced."""

    def test_viewer_cannot_access_admin_org(self, authenticated_client):
        """Viewers should get 404 when they have no org."""
        response = authenticated_client.get('/api/v1/auth/organization/')
        assert response.status_code in (status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN)

    def test_admin_can_access_org(self, admin_client, admin_user, make_org):
        org = make_org()
        admin_user.organization = org
        admin_user.save()
        response = admin_client.get('/api/v1/auth/organization/')
        assert response.status_code == status.HTTP_200_OK
