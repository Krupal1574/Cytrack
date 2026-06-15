"""
CyTrack Core Views — Health Check + System Status
"""
import time
import django
from django.conf import settings
from django.db import connection
from django.core.cache import cache
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Comprehensive health check endpoint.
    Used by Docker HEALTHCHECK, load balancers, and uptime monitors.

    Returns 200 if all systems are operational, 503 otherwise.
    """
    checks = {}
    overall_healthy = True
    start_time = time.time()

    # --- Database check ---
    try:
        connection.ensure_connection()
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        checks['database'] = {'status': 'ok', 'backend': settings.DATABASES['default']['ENGINE']}
    except Exception as e:
        checks['database'] = {'status': 'error', 'detail': str(e)}
        overall_healthy = False

    # --- Redis / Cache check ---
    try:
        cache.set('health_check', 'ok', timeout=10)
        result = cache.get('health_check')
        if result == 'ok':
            checks['cache'] = {'status': 'ok'}
        else:
            checks['cache'] = {'status': 'error', 'detail': 'Cache read/write mismatch'}
            overall_healthy = False
    except Exception as e:
        checks['cache'] = {'status': 'error', 'detail': str(e)}
        overall_healthy = False

    # --- Application info ---
    checks['app'] = {
        'status': 'ok',
        'version': '1.0.0',
        'django_version': django.get_version(),
        'debug': settings.DEBUG,
        'environment': getattr(settings, 'DJANGO_ENV', 'unknown'),
    }

    response_time_ms = round((time.time() - start_time) * 1000, 2)

    payload = {
        'status': 'healthy' if overall_healthy else 'degraded',
        'response_time_ms': response_time_ms,
        'checks': checks,
    }

    http_status = status.HTTP_200_OK if overall_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return Response(payload, status=http_status)


@api_view(['GET'])
@permission_classes([AllowAny])
def ping(request):
    """Minimal liveness probe — just confirms the process is alive."""
    return Response({'status': 'pong'})


@api_view(['GET'])
@permission_classes([AllowAny])
def dashboard_stats(request):
    """
    Placeholder stats endpoint for Phase 1.
    Returns hardcoded structure — populated from DB in Phase 4.
    """
    return Response({
        'total_iocs': 0,
        'total_pulses': 0,
        'total_cves': 0,
        'active_alerts': 0,
        'sources_active': 0,
        'last_ingestion': None,
        'message': 'Stats will be populated once ingestion is configured (Phase 2).',
    })
