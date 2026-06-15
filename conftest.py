"""
CyTrack Test Configuration — Shared Fixtures
=============================================
Provides reusable pytest fixtures for the entire test suite.
"""
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

User = get_user_model()


@pytest.fixture
def api_client():
    """Unauthenticated DRF API client."""
    return APIClient()


@pytest.fixture
def make_user(db):
    """Factory fixture for creating test users."""
    def _make_user(email='test@cytrack.io', role=None, **kwargs):
        from apps.accounts.models import User
        role = role or User.Role.VIEWER
        user = User.objects.create_user(
            email=email,
            username=email.split('@')[0],
            password='SecureTestPass123!',
            role=role,
            **kwargs,
        )
        return user
    return _make_user


@pytest.fixture
def viewer_user(make_user):
    """Viewer-role test user."""
    from apps.accounts.models import User
    return make_user(email='viewer@cytrack.io', role=User.Role.VIEWER)


@pytest.fixture
def analyst_user(make_user):
    """Analyst-role test user."""
    from apps.accounts.models import User
    return make_user(email='analyst@cytrack.io', role=User.Role.ANALYST)


@pytest.fixture
def admin_user(make_user):
    """Admin-role test user."""
    from apps.accounts.models import User
    return make_user(email='admin@cytrack.io', role=User.Role.ADMIN)


@pytest.fixture
def authenticated_client(api_client, viewer_user):
    """API client authenticated as a viewer user."""
    api_client.force_authenticate(user=viewer_user)
    return api_client


@pytest.fixture
def analyst_client(api_client, analyst_user):
    """API client authenticated as an analyst user."""
    api_client.force_authenticate(user=analyst_user)
    return api_client


@pytest.fixture
def admin_client(api_client, admin_user):
    """API client authenticated as an admin user."""
    api_client.force_authenticate(user=admin_user)
    return api_client


@pytest.fixture
def make_org(db):
    """Factory fixture for creating test organizations."""
    def _make_org(name='Test Org', plan='FREE'):
        from apps.accounts.models import Organization
        return Organization.objects.create(
            name=name,
            slug=name.lower().replace(' ', '-'),
            plan_tier=plan,
        )
    return _make_org
