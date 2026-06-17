from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    DashboardAnalyticsViewSet, ThreatActorViewSet, IOCViewSet,
    VulnerabilityViewSet, SourceViewSet, PublicDashboardStatsView
)

router = DefaultRouter()
router.register(r'analytics', DashboardAnalyticsViewSet, basename='analytics')
router.register(r'actors', ThreatActorViewSet, basename='threatactor')
router.register(r'iocs', IOCViewSet, basename='ioc')
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerability')
router.register(r'sources', SourceViewSet, basename='source')

urlpatterns = [
    # Public endpoint — aggregate stats only, no auth required
    path('analytics/public-stats/', PublicDashboardStatsView.as_view(), name='public-stats'),
    path('', include(router.urls)),
]
