"""
CyTrack Accounts Admin
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import User, Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'plan_tier', 'is_active', 'created_at']
    list_filter = ['plan_tier', 'is_active']
    search_fields = ['name', 'slug']
    prepopulated_fields = {'slug': ('name',)}
    readonly_fields = ['id', 'created_at', 'updated_at']


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = [
        'email', 'username', 'role', 'organization',
        'is_active', 'is_staff', 'created_at'
    ]
    list_filter = ['role', 'is_active', 'is_staff', 'organization']
    search_fields = ['email', 'username', 'first_name', 'last_name']
    ordering = ['email']
    readonly_fields = ['id', 'api_key', 'last_login', 'created_at', 'updated_at']

    fieldsets = (
        (None, {'fields': ('id', 'email', 'username', 'password')}),
        (_('Personal Info'), {'fields': ('first_name', 'last_name', 'bio', 'avatar', 'timezone')}),
        (_('Organization & Role'), {'fields': ('organization', 'role')}),
        (_('API Access'), {'fields': ('api_key', 'api_key_active')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important Dates'), {'fields': ('last_login', 'last_login_ip', 'created_at', 'updated_at')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'role', 'organization'),
        }),
    )
