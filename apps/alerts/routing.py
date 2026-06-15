"""WebSocket URL routing for CyTrack alerts."""
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/alerts/(?P<scope_id>[^/]+)/$', consumers.AlertConsumer.as_asgi()),
    # Shorthand for users without an org
    re_path(r'ws/alerts/$', consumers.AlertConsumer.as_asgi()),
]
