import logging
from typing import Any, Dict, List
import requests
from django.utils import timezone
from apps.intelligence.models import IndicatorOfCompromise, IndicatorType, ThreatActor, Vulnerability
from apps.ingestion.models import Source, SourceStatus
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

logger = logging.getLogger(__name__)

class BaseIngestionSource:
    """Abstract base class for all threat intelligence ingestion sources."""
    
    source_name = "Base"
    base_url = ""
    api_key = None
    
    class RateLimitExceeded(Exception):
        pass

    def __init__(self):
        self.session = requests.Session()
        self.db_source, _ = Source.objects.get_or_create(
            name=self.source_name,
            defaults={'is_active': True}
        )
        if self.api_key:
            self._setup_auth()

    def _setup_auth(self):
        """Override to configure authentication headers/params."""
        pass

    def fetch_data(self, **kwargs) -> Any:
        """Fetch data from the external source. Must be implemented by subclasses."""
        raise NotImplementedError

    def parse_data(self, data: Any) -> List[Dict]:
        """Parse raw data into a normalized format. Must be implemented by subclasses."""
        raise NotImplementedError

    def process_item(self, item: Dict):
        """
        Save normalized data into the database.
        Expected format of `item`:
        {
            'type': IndicatorType.*,
            'value': '...',
            'description': '...',
            'confidence': int,
            'severity': str
        }
        """
        ioc_type = item.get('type')
        value = item.get('value')
        
        if not ioc_type or not value:
            logger.warning(f"[{self.source_name}] Invalid item missing type or value: {item}")
            return
            
        try:
            # Upsert the IOC
            ioc, created = IndicatorOfCompromise.objects.get_or_create(
                type=ioc_type,
                value=value,
                defaults={
                    'description': item.get('description', ''),
                    'confidence': item.get('confidence', 50),
                    'severity': item.get('severity', 'low'),
                    'first_seen': timezone.now(),
                    'last_seen': timezone.now()
                }
            )
            
            # Ensure M2M link
            ioc.source_nodes.add(self.db_source)
            
            if not created:
                # Boost confidence if reported by multiple sources
                if ioc.confidence < item.get('confidence', 50):
                    ioc.confidence = item.get('confidence', 50)
                    
                ioc.last_seen = timezone.now()
                ioc.save()
                
            logger.debug(f"[{self.source_name}] Processed IOC {ioc_type}:{value} (Created: {created})")
            
            # Trigger WebSocket alert if severity is critical
            if ioc.severity == 'critical':
                channel_layer = get_channel_layer()
                if channel_layer:
                    async_to_sync(channel_layer.group_send)(
                        'alerts_global',
                        {
                            'type': 'new_ioc',
                            'ioc': {
                                'value': ioc.value,
                                'type': ioc.type,
                                'source': self.source_name,
                                'confidence': ioc.confidence
                            }
                        }
                    )
            
        except Exception as e:
            logger.error(f"[{self.source_name}] Error processing item {item}: {e}")

    def run(self):
        """Main execution flow: fetch, parse, and process."""
        if not self.db_source.is_active:
            logger.info(f"[{self.source_name}] Source is marked inactive. Skipping.")
            return

        logger.info(f"Starting ingestion from {self.source_name}")
        self.db_source.last_sync_status = SourceStatus.RUNNING
        self.db_source.save(update_fields=['last_sync_status'])
        
        try:
            raw_data = self.fetch_data()
            items = self.parse_data(raw_data)
            
            for item in items:
                self.process_item(item)
                
            self.db_source.last_sync_status = SourceStatus.SUCCESS
            self.db_source.last_sync_time = timezone.now()
            self.db_source.total_items_ingested += len(items)
            self.db_source.error_message = ""
            self.db_source.save()
            
            logger.info(f"Completed ingestion from {self.source_name}. Processed {len(items)} items.")
        except self.RateLimitExceeded as e:
            # Re-raise to let Celery handle the retry
            raise
        except Exception as e:
            self.db_source.last_sync_status = SourceStatus.FAILED
            self.db_source.error_message = str(e)
            self.db_source.save(update_fields=['last_sync_status', 'error_message'])
            logger.exception(f"Failed ingestion from {self.source_name}: {e}")
            raise
