"""
CyTrack Accounts Views — Authentication + Profile Management
"""
import logging
from django.contrib.auth import get_user_model
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiExample

from .models import Organization
from .serializers import (
    RegisterSerializer,
    UserProfileSerializer,
    ChangePasswordSerializer,
    CyTrackTokenObtainPairSerializer,
    OrganizationSerializer,
)
from .permissions import IsOrgAdmin

logger = logging.getLogger(__name__)
User = get_user_model()


class LoginView(TokenObtainPairView):
    """
    Obtain JWT access + refresh tokens.
    Returns user profile alongside tokens for immediate use by the frontend.
    """
    serializer_class = CyTrackTokenObtainPairSerializer

    @extend_schema(tags=['auth'])
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            # Log successful login for audit trail
            logger.info('User login: %s from %s', request.data.get('email'), _get_client_ip(request))
        return response


class RegisterView(generics.CreateAPIView):
    """
    Register a new CyTrack account.
    New users default to VIEWER role and no organization.
    """
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    @extend_schema(tags=['auth'])
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Issue tokens immediately on registration
        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'Account created successfully.',
            'user': UserProfileSerializer(user).data,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }, status=status.HTTP_201_CREATED)


class LogoutView(APIView):
    """
    Logout by blacklisting the refresh token.
    The access token will expire naturally (short-lived).
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(tags=['auth'])
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            return Response({'message': 'Logged out successfully.'})
        except Exception:
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(generics.RetrieveUpdateAPIView):
    """Get and update the authenticated user's profile."""
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(tags=['auth'])
    def get_object(self):
        return self.request.user

    def get_serializer_class(self):
        return UserProfileSerializer


class ChangePasswordView(APIView):
    """Change password for the authenticated user."""
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(tags=['auth'])
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        logger.info('Password changed for user: %s', request.user.email)
        return Response({'message': 'Password changed successfully.'})


class RegenerateAPIKeyView(APIView):
    """Regenerate the user's API key for programmatic access."""
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(tags=['auth'])
    def post(self, request):
        new_key = request.user.regenerate_api_key()
        return Response({
            'message': 'API key regenerated.',
            'api_key': str(new_key),
        })


class OrganizationDetailView(generics.RetrieveUpdateAPIView):
    """View and update organization details (Admin only)."""
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    @extend_schema(tags=['auth'])
    def get_object(self):
        org = self.request.user.organization
        if not org:
            from rest_framework.exceptions import NotFound
            raise NotFound('You are not associated with an organization.')
        return org


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def me(request):
    """Quick endpoint to get current user data — used for session validation."""
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data)


def _get_client_ip(request):
    """Extract real client IP handling reverse proxy headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')
