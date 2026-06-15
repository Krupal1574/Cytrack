"""IOC API URLs — stub for Phase 1, populated in Phase 2."""
from django.urls import path
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def ioc_list(request):
    return Response({
        'count': 0,
        'results': [],
        'message': 'IOC database will be populated in Phase 2 (Threat Intelligence Ingestion).',
    })


urlpatterns = [
    path('', ioc_list, name='ioc-list'),
]
