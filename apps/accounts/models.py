"""
CyTrack Accounts Models
========================
Custom user model with RBAC roles and multi-tenant organization support.
"""
import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _


class Organization(models.Model):
    """
    Represents a tenant organization in CyTrack.
    All data is scoped to an organization for multi-tenancy.
    """

    class PlanTier(models.TextChoices):
        FREE = 'FREE', _('Free')
        PRO = 'PRO', _('Professional')
        ENTERPRISE = 'ENTERPRISE', _('Enterprise')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200, unique=True)
    slug = models.SlugField(max_length=200, unique=True)
    plan_tier = models.CharField(
        max_length=20,
        choices=PlanTier.choices,
        default=PlanTier.FREE,
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'

    def __str__(self):
        return f'{self.name} ({self.plan_tier})'


class User(AbstractUser):
    """
    CyTrack custom user model extending Django's AbstractUser.
    Adds UUID primary key, organization scoping, and RBAC role.
    """

    class Role(models.TextChoices):
        SUPERADMIN = 'SUPERADMIN', _('Super Admin')  # CyTrack platform admin
        ADMIN = 'ADMIN', _('Admin')                  # Org admin
        ANALYST = 'ANALYST', _('Analyst')            # Read + write threat data
        VIEWER = 'VIEWER', _('Viewer')               # Read only

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='members',
    )
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.VIEWER,
    )

    # API key for programmatic access
    api_key = models.UUIDField(default=uuid.uuid4, unique=True, db_index=True)
    api_key_active = models.BooleanField(default=True)

    # Profile
    bio = models.TextField(blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    timezone = models.CharField(max_length=50, default='UTC')

    # Audit fields
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        ordering = ['email']
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['organization', 'role']),
            models.Index(fields=['api_key']),
        ]

    def __str__(self):
        return f'{self.email} [{self.role}]'

    @property
    def is_admin(self):
        return self.role in (self.Role.ADMIN, self.Role.SUPERADMIN)

    @property
    def is_analyst(self):
        return self.role in (self.Role.ANALYST, self.Role.ADMIN, self.Role.SUPERADMIN)

    def regenerate_api_key(self):
        """Generate a fresh API key for this user."""
        self.api_key = uuid.uuid4()
        self.save(update_fields=['api_key'])
        return self.api_key
