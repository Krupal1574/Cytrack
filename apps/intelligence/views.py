from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from datetime import timedelta

from apps.accounts.permissions import IsViewer
from .models import IndicatorOfCompromise, ThreatActor, Vulnerability, ThreatPulse
from apps.ingestion.models import Source
from .serializers import IndicatorOfCompromiseSerializer, ThreatActorSerializer, VulnerabilitySerializer, SourceSerializer


class PublicDashboardStatsView(APIView):
    """
    Unauthenticated endpoint that serves all data needed by the public dashboard.

    Returns:
      - KPI counts (total_iocs, recent_iocs, high_threat_actors, kev_vulns)
      - Chart data for 6 Chart.js visualizations

    This endpoint is intentionally open — it returns only aggregate counts,
    never raw IOC values or sensitive indicators.
    """
    permission_classes = []  # Public — no auth required
    authentication_classes = []

    def get(self, request):
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)

        # ---- KPI Counts ----
        total_iocs = IndicatorOfCompromise.objects.count()
        recent_iocs = IndicatorOfCompromise.objects.filter(created_at__gte=thirty_days_ago).count()
        high_threat_actors = ThreatActor.objects.filter(threat_score__gte=75).count()
        kev_vulns = Vulnerability.objects.filter(is_kev=True).count()

        # ---- Chart 1: IOC Severity Distribution (Donut) ----
        severity_qs = (
            IndicatorOfCompromise.objects
            .values('severity')
            .annotate(count=Count('id'))
            .order_by('severity')
        )
        severity_chart = {
            'labels': [r['severity'].capitalize() for r in severity_qs],
            'data': [r['count'] for r in severity_qs],
        }

        # ---- Chart 2: IOC Daily Trend — last 30 days (Line) ----
        trend_qs = (
            IndicatorOfCompromise.objects
            .filter(created_at__gte=thirty_days_ago)
            .annotate(day=TruncDate('created_at'))
            .values('day')
            .annotate(count=Count('id'))
            .order_by('day')
        )
        trend_chart = {
            'labels': [str(r['day']) for r in trend_qs],
            'data': [r['count'] for r in trend_qs],
        }

        # ---- Chart 3: IOC Type Distribution (Bar) ----
        type_qs = (
            IndicatorOfCompromise.objects
            .values('type')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        type_chart = {
            'labels': [r['type'].upper() for r in type_qs],
            'data': [r['count'] for r in type_qs],
        }

        # ---- Chart 4: Source Coverage — IOCs per source (Horizontal Bar) ----
        source_qs = (
            Source.objects
            .annotate(ioc_count=Count('iocs', distinct=True))
            .values('name', 'ioc_count')
            .order_by('-ioc_count')
        )
        source_chart = {
            'labels': [r['name'] for r in source_qs],
            'data': [r['ioc_count'] for r in source_qs],
        }

        # ---- Chart 5: Top Threat Actors (Horizontal Bar) ----
        actor_qs = (
            ThreatActor.objects
            .order_by('-threat_score')
            .values('name', 'threat_score')[:10]
        )
        actor_chart = {
            'labels': [r['name'] for r in actor_qs],
            'data': [r['threat_score'] for r in actor_qs],
        }

        # ---- Chart 6: Risk Score Distribution from CorrelationReport (Histogram) ----
        risk_chart = {'labels': [], 'data': []}
        try:
            from apps.investigation.models import CorrelationReport
            buckets = [
                ('0–19', 0, 20), ('20–39', 20, 40), ('40–59', 40, 60),
                ('60–79', 60, 80), ('80–100', 80, 101),
            ]
            risk_chart = {
                'labels': [b[0] for b in buckets],
                'data': [
                    CorrelationReport.objects.filter(
                        risk_score__gte=b[1], risk_score__lt=b[2]
                    ).count()
                    for b in buckets
                ],
            }
        except Exception:
            pass  # CorrelationReport not populated yet

        return Response({
            'kpi': {
                'total_iocs': total_iocs,
                'recent_iocs': recent_iocs,
                'high_threat_actors': high_threat_actors,
                'kev_vulns': kev_vulns,
            },
            'charts': {
                'severity_distribution': severity_chart,
                'ioc_daily_trend': trend_chart,
                'ioc_type_distribution': type_chart,
                'source_coverage': source_chart,
                'top_threat_actors': actor_chart,
                'risk_distribution': risk_chart,
            },
        })


class DashboardAnalyticsViewSet(viewsets.ViewSet):
    """
    Read-only endpoint providing aggregated stats for the dashboard.
    """
    permission_classes = [permissions.IsAuthenticated, IsViewer]

    @action(detail=False, methods=['get'])
    def summary(self, request):
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)

        # Basic counts
        total_iocs = IndicatorOfCompromise.objects.count()
        recent_iocs = IndicatorOfCompromise.objects.filter(created_at__gte=thirty_days_ago).count()

        total_actors = ThreatActor.objects.count()
        high_threat_actors = ThreatActor.objects.filter(threat_score__gte=75).count()

        total_vulns = Vulnerability.objects.count()
        kev_vulns = Vulnerability.objects.filter(is_kev=True).count()

        # Distribution by severity
        severity_dist = list(IndicatorOfCompromise.objects.values('severity').annotate(count=Count('id')))

        # --- Phase 2B: Correlation Analytics ---

        # Top 5 Correlated IOCs (by risk_score from CorrelationReport)
        top_correlated_iocs = []
        try:
            from apps.investigation.models import CorrelationReport
            top_reports = (
                CorrelationReport.objects
                .select_related('ioc')
                .order_by('-risk_score')[:5]
            )
            top_correlated_iocs = [
                {
                    'ioc_id': str(r.ioc.id),
                    'value': r.ioc.value,
                    'type': r.ioc.type,
                    'severity': r.ioc.severity,
                    'risk_score': r.risk_score,
                    'source_count': r.source_count,
                }
                for r in top_reports
            ]
        except Exception:
            pass  # CorrelationReport table may not exist yet on first boot

        # Most Dangerous Actors (top 5 by threat_score)
        top_actors = list(
            ThreatActor.objects
            .order_by('-threat_score')
            .values('id', 'name', 'threat_score', 'country_of_origin')[:5]
        )

        # Active Exploited CVEs (KEV with due date in the future or no date)
        active_kev = list(
            Vulnerability.objects
            .filter(is_kev=True)
            .order_by('-cvss_score')
            .values('cve_id', 'cvss_score', 'kev_due_date', 'kev_action')[:10]
        )

        # Source Agreement Metrics
        iocs_with_multiple_sources = (
            IndicatorOfCompromise.objects
            .annotate(src_count=Count('source_nodes'))
            .filter(src_count__gte=2)
            .count()
        )
        iocs_with_single_source = (
            IndicatorOfCompromise.objects
            .annotate(src_count=Count('source_nodes'))
            .filter(src_count=1)
            .count()
        )

        return Response({
            'iocs': {
                'total': total_iocs,
                'recent_30d': recent_iocs,
                'severity_distribution': severity_dist
            },
            'threat_actors': {
                'total': total_actors,
                'high_threat': high_threat_actors
            },
            'vulnerabilities': {
                'total': total_vulns,
                'kev': kev_vulns
            },
            'correlation': {
                'top_correlated_iocs': top_correlated_iocs,
                'most_dangerous_actors': top_actors,
                'active_exploited_cves': active_kev,
                'source_agreement': {
                    'multi_source_iocs': iocs_with_multiple_sources,
                    'single_source_iocs': iocs_with_single_source,
                }
            }
        })

class ThreatActorViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows Threat Actors to be viewed.
    """
    queryset = ThreatActor.objects.all().order_by('-threat_score')
    serializer_class = ThreatActorSerializer
    permission_classes = [permissions.IsAuthenticated, IsViewer]

    @action(detail=False, methods=['get'])
    def top(self, request):
        """Get top 10 highest scored threat actors."""
        top_actors = self.queryset[:10]
        serializer = self.get_serializer(top_actors, many=True)
        return Response(serializer.data)

class IOCViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows IOCs to be viewed.
    """
    queryset = IndicatorOfCompromise.objects.all().order_by('-created_at')
    serializer_class = IndicatorOfCompromiseSerializer
    permission_classes = [permissions.IsAuthenticated, IsViewer]

class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows Vulnerabilities to be viewed.
    """
    queryset = Vulnerability.objects.all().order_by('-cvss_score', '-published_date')
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated, IsViewer]

class SourceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows Sources to be viewed.
    """
    queryset = Source.objects.all().order_by('name')
    serializer_class = SourceSerializer
    permission_classes = [permissions.IsAuthenticated, IsViewer]
