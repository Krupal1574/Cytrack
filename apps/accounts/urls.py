"""CyTrack Accounts URL patterns."""
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from . import views

urlpatterns = [
    # Authentication
    path('login/', views.LoginView.as_view(), name='auth-login'),
    path('logout/', views.LogoutView.as_view(), name='auth-logout'),
    path('register/', views.RegisterView.as_view(), name='auth-register'),

    # JWT token management
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token-verify'),

    # Profile
    path('me/', views.me, name='auth-me'),
    path('profile/', views.ProfileView.as_view(), name='auth-profile'),
    path('change-password/', views.ChangePasswordView.as_view(), name='auth-change-password'),
    path('api-key/regenerate/', views.RegenerateAPIKeyView.as_view(), name='auth-regen-apikey'),

    # Organization
    path('organization/', views.OrganizationDetailView.as_view(), name='auth-org'),
]
