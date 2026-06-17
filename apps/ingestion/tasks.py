from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from celery import shared_task
from .sources.otx import OTXIngestionSource
from .sources.abuseipdb import AbuseIPDBIngestionSource
from .sources.cisa import CISAKEVIngestionSource
from .sources.nvd import NVDIntegrationSource
from .sources.base import BaseIngestionSource
import logging

logger = logging.getLogger(__name__)

def _send_status(source: str, status: str):
    channel_layer = get_channel_layer()
    if channel_layer:
        async_to_sync(channel_layer.group_send)(
            'alerts_global',
            {
                'type': 'ingestion_status',
                'source': source,
                'status': status
            }
        )

@shared_task(queue='ingestion', bind=True, max_retries=3)
def ingest_otx_pulses(self):
    """Fetch and process OTX pulses."""
    _send_status('OTX', 'Started')
    try:
        source = OTXIngestionSource()
        source.run()
        _send_status('OTX', 'Completed')
    except BaseIngestionSource.RateLimitExceeded as exc:
        logger.warning(f"OTX Rate Limit: {exc}. Retrying in 300s.")
        self.retry(exc=exc, countdown=300)
    except Exception as exc:
        logger.error(f"Failed to ingest OTX pulses: {exc}")

@shared_task(queue='ingestion', bind=True, max_retries=3)
def ingest_abuseipdb_blacklist(self):
    """Fetch and process AbuseIPDB blacklist."""
    _send_status('AbuseIPDB', 'Started')
    try:
        source = AbuseIPDBIngestionSource()
        source.run()
        _send_status('AbuseIPDB', 'Completed')
    except BaseIngestionSource.RateLimitExceeded as exc:
        logger.warning(f"AbuseIPDB Rate Limit: {exc}. Retrying in 300s.")
        self.retry(exc=exc, countdown=300)
    except Exception as exc:
        logger.error(f"Failed to ingest AbuseIPDB blacklist: {exc}")

@shared_task(queue='ingestion', bind=True, max_retries=3)
def ingest_cisa_kev(self):
    """Fetch and process CISA KEV catalog."""
    _send_status('CISA KEV', 'Started')
    try:
        source = CISAKEVIngestionSource()
        source.run()
        _send_status('CISA KEV', 'Completed')
    except BaseIngestionSource.RateLimitExceeded as exc:
        logger.warning(f"CISA KEV Rate Limit: {exc}. Retrying in 300s.")
        self.retry(exc=exc, countdown=300)
    except Exception as exc:
        logger.error(f"Failed to ingest CISA KEV: {exc}")

@shared_task(queue='ingestion', bind=True, max_retries=5)
def ingest_nvd_cves(self):
    """Fetch and process NVD CVEs."""
    _send_status('NVD CVE', 'Started')
    try:
        source = NVDIntegrationSource()
        source.run()
        _send_status('NVD CVE', 'Completed')
    except BaseIngestionSource.RateLimitExceeded as exc:
        logger.warning(f"NVD Rate Limit: {exc}. Retrying in 300s.")
        self.retry(exc=exc, countdown=300)
    except Exception as exc:
        logger.error(f"Failed to ingest NVD data: {exc}")
