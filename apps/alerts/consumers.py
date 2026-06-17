"""
CyTrack WebSocket Consumer — Real-time Alert Delivery
=======================================================
Authenticated users connect to ws://cytrack/ws/alerts/<org_id>/
and receive real-time threat alert events pushed from Celery tasks.
"""
import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)


class AlertConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time alert delivery.

    Channel group naming: alerts_<org_id>
    Celery tasks send to this group when new alerts are generated.
    """

    async def connect(self):
        """Accept connection and join org-scoped channel group."""
        user = self.scope.get('user')

        # Reject unauthenticated connections
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return

        # Use org ID if user has one, otherwise use user ID (personal scope)
        org = getattr(user, 'organization', None)
        scope_id = str(org.id) if org else str(user.id)
        self.group_name = f'alerts_{scope_id}'

        # Join the channel group
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        # Join global alerts group
        await self.channel_layer.group_add('alerts_global', self.channel_name)
        await self.accept()

        logger.info('WebSocket connected: user=%s group=%s', user.email, self.group_name)

        # Send connection acknowledgement
        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'message': 'Connected to CyTrack real-time alert feed.',
            'group': self.group_name,
        }))

    async def disconnect(self, close_code):
        """Leave channel group on disconnect."""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
            await self.channel_layer.group_discard('alerts_global', self.channel_name)
            logger.info('WebSocket disconnected: group=%s code=%s', self.group_name, close_code)

    async def receive(self, text_data):
        """
        Handle messages from client.
        Currently only supports ping/pong for keepalive.
        """
        try:
            data = json.loads(text_data)
            if data.get('type') == 'ping':
                await self.send(text_data=json.dumps({'type': 'pong'}))
        except (json.JSONDecodeError, KeyError):
            pass

    # --- Event handlers (called by Celery via channel_layer.group_send) ---

    async def new_alert(self, event):
        """Broadcast new alert to all group members."""
        await self.send(text_data=json.dumps({
            'type': 'new_alert',
            'alert': event.get('alert', {}),
        }))

    async def new_ioc(self, event):
        """Broadcast new critical IOC detection."""
        await self.send(text_data=json.dumps({
            'type': 'new_ioc',
            'ioc': event.get('ioc', {}),
        }))

    async def ingestion_status(self, event):
        """Broadcast ingestion pipeline status updates."""
        await self.send(text_data=json.dumps({
            'type': 'ingestion_status',
            'source': event.get('source'),
            'status': event.get('status'),
            'count': event.get('count', 0),
        }))
