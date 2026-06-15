"""
CyTrack ASGI Configuration
===========================
Supports both HTTP (Django) and WebSocket (Django Channels) connections.
"""
import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber.settings')

# Initialize Django ASGI application
django_asgi_app = get_asgi_application()

# Import WebSocket URL patterns after Django setup
from apps.alerts.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter({
    # HTTP → handled by standard Django
    'http': django_asgi_app,

    # WebSocket → handled by Django Channels
    'websocket': AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(websocket_urlpatterns)
        )
    ),
})
