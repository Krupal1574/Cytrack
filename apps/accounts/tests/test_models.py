"""
Tests: accounts app — models
"""
import pytest
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestOrganizationModel:
    def test_create_organization(self, make_org):
        org = make_org(name='ACME Security', plan='PRO')
        assert org.name == 'ACME Security'
        assert org.slug == 'acme-security'
        assert org.plan_tier == 'PRO'
        assert org.is_active is True
        assert str(org) == 'ACME Security (PRO)'

    def test_organization_member_count(self, make_org, make_user):
        org = make_org()
        make_user(email='a@test.io', organization=org)
        make_user(email='b@test.io', organization=org)
        assert org.members.count() == 2


@pytest.mark.django_db
class TestUserModel:
    def test_create_user_defaults(self, make_user):
        user = make_user()
        assert user.role == User.Role.VIEWER
        assert user.is_analyst is False
        assert user.is_admin is False
        assert user.api_key is not None
        assert user.api_key_active is True

    def test_analyst_role_permissions(self, make_user):
        user = make_user(role=User.Role.ANALYST)
        assert user.is_analyst is True
        assert user.is_admin is False

    def test_admin_role_permissions(self, make_user):
        user = make_user(role=User.Role.ADMIN)
        assert user.is_analyst is True
        assert user.is_admin is True

    def test_email_is_username_field(self):
        assert User.USERNAME_FIELD == 'email'

    def test_regenerate_api_key(self, make_user):
        user = make_user()
        original_key = user.api_key
        new_key = user.regenerate_api_key()
        user.refresh_from_db()
        assert user.api_key == new_key
        assert user.api_key != original_key

    def test_user_str(self, make_user):
        user = make_user(email='analyst@cytrack.io', role=User.Role.ANALYST)
        assert 'analyst@cytrack.io' in str(user)
        assert 'ANALYST' in str(user)

    def test_user_with_organization(self, make_user, make_org):
        org = make_org()
        user = make_user(organization=org)
        assert user.organization == org
        assert user in org.members.all()
