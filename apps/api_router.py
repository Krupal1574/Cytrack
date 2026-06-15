"""
CyTrack API Router — Central URL registry for all REST API endpoints.
All routes are prefixed with /api/v1/ from the root urls.py.
"""
from django.urls import path, include

urlpatterns = [
    # Authentication (JWT + registration)
    path('auth/', include('apps.accounts.urls')),

    # Intelligence data (Phase 2 — stubs in Phase 1)
    path('iocs/', include('apps.intelligence.urls_ioc')),
    path('pulses/', include('apps.intelligence.urls_pulse')),

    # Stats (Phase 4 — stub in Phase 1)
    path('stats/', include('apps.core.urls_stats')),
]
