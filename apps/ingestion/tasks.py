"""
Ingestion Celery Tasks — Phase 1 Stubs
======================================
Task placeholders — full implementation in Phase 2.
These register with Celery Beat so the schedule is in place from Phase 1.
"""
import logging
from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(name='ingestion.ingest_otx_pulses', bind=True, max_retries=3)
def ingest_otx_pulses(self):
    """
    Ingest threat pulses from AlienVault OTX.
    Full implementation: Phase 2.
    """
    logger.info('[STUB] ingest_otx_pulses task triggered — Phase 2 implementation pending.')
    return {'status': 'stub', 'message': 'Phase 2 implementation pending'}


@shared_task(name='ingestion.ingest_abuseipdb', bind=True, max_retries=3)
def ingest_abuseipdb(self):
    """
    Ingest abusive IP data from AbuseIPDB.
    Full implementation: Phase 2.
    """
    logger.info('[STUB] ingest_abuseipdb task triggered — Phase 2 implementation pending.')
    return {'status': 'stub', 'message': 'Phase 2 implementation pending'}


@shared_task(name='ingestion.sync_cisa_kev', bind=True, max_retries=3)
def sync_cisa_kev(self):
    """
    Sync CISA Known Exploited Vulnerabilities feed.
    Full implementation: Phase 2.
    """
    logger.info('[STUB] sync_cisa_kev task triggered — Phase 2 implementation pending.')
    return {'status': 'stub', 'message': 'Phase 2 implementation pending'}


@shared_task(name='ingestion.sync_nvd_cves', bind=True, max_retries=3)
def sync_nvd_cves(self):
    """
    Sync CVEs from NIST NVD API.
    Full implementation: Phase 2.
    """
    logger.info('[STUB] sync_nvd_cves task triggered — Phase 2 implementation pending.')
    return {'status': 'stub', 'message': 'Phase 2 implementation pending'}
