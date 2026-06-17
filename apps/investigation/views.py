"""
Investigation API Views.

Endpoints:
    GET /api/v1/investigation/ioc/<uuid>/        — cached CorrelationReport
    GET /api/v1/investigation/ioc/<uuid>/?live=true — live CorrelationService.compute()
    GET /api/v1/investigation/ip/<ip>/
    GET /api/v1/investigation/ip/<ip>/?live=true
    GET /api/v1/investigation/domain/<domain>/
    GET /api/v1/investigation/domain/<domain>/?live=true
    GET /api/v1/investigation/hash/<hash>/
    GET /api/v1/investigation/hash/<hash>/?live=true

Cache vs. Live
--------------
Default (no ?live): serves from CorrelationReport (O(1) DB read).
?live=true: calls CorrelationService.compute() in real time, then asynchronously
            updates the cache via a Celery task.
"""
import logging
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsViewer
from apps.intelligence.models import IndicatorOfCompromise, IndicatorType
from apps.investigation.models import CorrelationReport
from apps.investigation.services import CorrelationService
from apps.investigation.serializers import CorrelationReportSerializer, LiveCorrelationSerializer

logger = logging.getLogger(__name__)

HASH_TYPES = {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}
PERMISSION_CLASSES = [permissions.IsAuthenticated, IsViewer]


def _get_ioc_with_relations(queryset_filter: dict):
    """
    Fetch an IOC with all related objects prefetched, or return None.
    """
    return (
        IndicatorOfCompromise.objects
        .prefetch_related('source_nodes', 'threat_actors', 'vulnerabilities', 'pulses')
        .filter(**queryset_filter)
        .first()
    )


def _serve_investigation(ioc: IndicatorOfCompromise, live: bool) -> Response:
    """
    Core response builder.
    live=False → serve from CorrelationReport cache.
    live=True  → call CorrelationService.compute(), then trigger async cache update.
    """
    if live:
        data = CorrelationService.compute(ioc)
        # Inject the IOC object itself so the serializer can read it
        data['ioc'] = ioc
        serializer = LiveCorrelationSerializer(data)
        # Asynchronously update the cache so the next cached request is fresh
        try:
            from apps.investigation.tasks import rebuild_single_correlation
            rebuild_single_correlation.delay(str(ioc.id))
        except Exception as exc:
            logger.warning('[investigation] Could not schedule cache update: %s', exc)
        return Response(serializer.data)

    # Cached path
    try:
        report = CorrelationReport.objects.select_related('ioc').get(ioc=ioc)
    except CorrelationReport.DoesNotExist:
        # Report hasn't been computed yet — compute and persist on demand
        report = CorrelationService.build_report(ioc)

    serializer = CorrelationReportSerializer(report)
    return Response(serializer.data)


class InvestigateByIOCView(APIView):
    """
    GET /api/v1/investigation/ioc/<uuid>/
    GET /api/v1/investigation/ioc/<uuid>/?live=true
    """
    permission_classes = PERMISSION_CLASSES

    def get(self, request, ioc_id):
        ioc = _get_ioc_with_relations({'id': ioc_id})
        if ioc is None:
            return Response({'detail': 'IOC not found.'}, status=status.HTTP_404_NOT_FOUND)

        live = request.query_params.get('live', '').lower() == 'true'
        return _serve_investigation(ioc, live)


class InvestigateByIPView(APIView):
    """
    GET /api/v1/investigation/ip/<ip>/
    GET /api/v1/investigation/ip/<ip>/?live=true
    """
    permission_classes = PERMISSION_CLASSES

    def get(self, request, ip):
        ioc = _get_ioc_with_relations({
            'value': ip,
            'type__in': [IndicatorType.IPV4, IndicatorType.IPV6]
        })
        if ioc is None:
            return Response({'detail': f'No IOC found for IP: {ip}'}, status=status.HTTP_404_NOT_FOUND)

        live = request.query_params.get('live', '').lower() == 'true'
        return _serve_investigation(ioc, live)


class InvestigateByDomainView(APIView):
    """
    GET /api/v1/investigation/domain/<domain>/
    GET /api/v1/investigation/domain/<domain>/?live=true
    """
    permission_classes = PERMISSION_CLASSES

    def get(self, request, domain):
        ioc = _get_ioc_with_relations({'value': domain, 'type': IndicatorType.DOMAIN})
        if ioc is None:
            return Response({'detail': f'No IOC found for domain: {domain}'}, status=status.HTTP_404_NOT_FOUND)

        live = request.query_params.get('live', '').lower() == 'true'
        return _serve_investigation(ioc, live)


class InvestigateByHashView(APIView):
    """
    GET /api/v1/investigation/hash/<hash>/
    GET /api/v1/investigation/hash/<hash>/?live=true

    Searches MD5, SHA1, SHA256 by value.
    """
    permission_classes = PERMISSION_CLASSES

    def get(self, request, hash_value):
        ioc = _get_ioc_with_relations({
            'value': hash_value,
            'type__in': list(HASH_TYPES)
        })
        if ioc is None:
            return Response({'detail': f'No IOC found for hash: {hash_value}'}, status=status.HTTP_404_NOT_FOUND)

        live = request.query_params.get('live', '').lower() == 'true'
        return _serve_investigation(ioc, live)
