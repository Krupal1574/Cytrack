"""
CyTrack URL Configuration — Root Router
========================================
URL structure:
  /                     → Legacy dashboard (existing UI, maintained in Phase 1)
  /admin/               → Django Admin
  /api/v1/              → REST API (DRF)
  /api/schema/          → OpenAPI schema (JSON)
  /api/docs/            → Swagger UI
  /api/redoc/           → ReDoc UI
  /health/              → Health check endpoint
"""

from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)

urlpatterns = [
    # Django Admin
    path('admin/', admin.site.urls),

    # Legacy dashboard (Phase 1 — preserved as-is, UI rebuilt in Phase 4)
    path('', include('dashboard.urls')),

    # REST API v1
    path('api/v1/', include('apps.api_router')),

    # OpenAPI documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    # Health check (no auth required — used by Docker/load balancers)
    path('health/', include('apps.core.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)