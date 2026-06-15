"""Stats URL patterns for /api/v1/stats/."""
from django.urls import path
from .views import dashboard_stats

urlpatterns = [
    path('dashboard/', dashboard_stats, name='stats-dashboard'),
]
