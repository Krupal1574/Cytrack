"""
CyTrack Accounts Serializers
==============================
Serializers for user registration, login, profile management, and org data.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import Organization

User = get_user_model()


class OrganizationSerializer(serializers.ModelSerializer):
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ['id', 'name', 'slug', 'plan_tier', 'member_count', 'created_at']
        read_only_fields = ['id', 'created_at']

    def get_member_count(self, obj):
        return obj.members.filter(is_active=True).count()


class UserProfileSerializer(serializers.ModelSerializer):
    organization = OrganizationSerializer(read_only=True)
    role_display = serializers.CharField(source='get_role_display', read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'role', 'role_display', 'organization', 'bio', 'avatar',
            'timezone', 'api_key', 'api_key_active', 'last_login',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'email', 'role', 'api_key', 'last_login', 'created_at']


class RegisterSerializer(serializers.ModelSerializer):
    """User self-registration serializer."""
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
    )

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'password_confirm', 'first_name', 'last_name']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password': 'Passwords do not match.'})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
        )
        return user


class ChangePasswordSerializer(serializers.Serializer):
    """Authenticated password change."""
    old_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'},
    )

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Current password is incorrect.')
        return value


class CyTrackTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT serializer — adds user role and org to token claims.
    This embeds role info in the token so the frontend can gate UI without
    an extra API call on every page load.
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims
        token['email'] = user.email
        token['role'] = user.role
        token['org_id'] = str(user.organization.id) if user.organization else None
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        # Include profile data in login response
        data['user'] = UserProfileSerializer(self.user).data
        return data
