"""
CyTrack RBAC Permission Classes
================================
Custom DRF permissions based on the User.Role enum.
"""
from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsViewer(BasePermission):
    """Any authenticated user (Viewer, Analyst, Admin, SuperAdmin)."""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsAnalyst(BasePermission):
    """Analyst-level access: can create/update threat data."""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.is_analyst


class IsOrgAdmin(BasePermission):
    """Org admin: can manage organization members and settings."""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.is_admin


class IsOwnerOrAdmin(BasePermission):
    """Object-level: owner can access own data, admins can access all."""
    def has_object_permission(self, request, view, obj):
        if request.user.is_admin:
            return True
        # For objects with a 'user' attribute
        if hasattr(obj, 'user'):
            return obj.user == request.user
        # For the User object itself
        return obj == request.user


class ReadOnlyOrAnalyst(BasePermission):
    """Read access for all authenticated; write access for Analysts+."""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.method in SAFE_METHODS:
            return True
        return request.user.is_analyst


class APIKeyAuthentication(BasePermission):
    """
    Allow access via X-API-Key header in addition to JWT.
    Used for programmatic/SIEM integrations.
    """
    def has_permission(self, request, view):
        api_key = request.META.get('HTTP_X_API_KEY')
        if not api_key:
            # Fall through to JWT auth
            return request.user and request.user.is_authenticated

        from apps.accounts.models import User
        try:
            user = User.objects.get(api_key=api_key, api_key_active=True, is_active=True)
            request.user = user
            return True
        except User.DoesNotExist:
            return False
