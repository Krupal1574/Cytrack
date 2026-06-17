"""
CyTrack API Router — Central URL registry for all REST API endpoints.
All routes are prefixed with /api/v1/ from the root urls.py.
"""
from django.urls import path, include

urlpatterns = [
    # Authentication (JWT + registration)
    path('auth/', include('apps.accounts.urls')),

    # Intelligence data & Analytics (Phase 2 & 3)
    path('intel/', include('apps.intelligence.urls')),

    # Threat Correlation & Investigation (Phase 2B)
    path('investigation/', include('apps.investigation.urls')),

    # Stats (Phase 4 — stub in Phase 1)
    path('stats/', include('apps.core.urls_stats')),
]
