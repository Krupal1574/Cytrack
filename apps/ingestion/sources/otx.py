import os
import requests
from typing import Any, Dict, List
from django.conf import settings
from apps.intelligence.models import IndicatorType
from .base import BaseIngestionSource

class OTXIngestionSource(BaseIngestionSource):
    """
    AlienVault OTX (Open Threat Exchange) Ingestion Source.
    Fetches subscribed pulses and extracts indicators.
    """
    source_name = "AlienVault OTX"
    base_url = "https://otx.alienvault.com/api/v1"
    
    def __init__(self):
        self.api_key = os.environ.get('OTX_API_KEY')
        super().__init__()

    def _setup_auth(self):
        self.session.headers.update({
            'X-OTX-API-KEY': self.api_key
        })

    def fetch_data(self) -> Any:
        if not self.api_key:
            raise ValueError("OTX_API_KEY is not set.")
            
        # Fetch pulses subscribed to by the user
        url = f"{self.base_url}/pulses/subscribed"
        response = self.session.get(url, params={'limit': 20})
        response.raise_for_status()
        return response.json().get('results', [])

    def parse_data(self, data: Any) -> List[Dict]:
        items = []
        
        # OTX type mapping to our IndicatorType
        otx_type_mapping = {
            'IPv4': IndicatorType.IPV4,
            'IPv6': IndicatorType.IPV6,
            'domain': IndicatorType.DOMAIN,
            'hostname': IndicatorType.DOMAIN,
            'URL': IndicatorType.URL,
            'FileHash-MD5': IndicatorType.MD5,
            'FileHash-SHA1': IndicatorType.SHA1,
            'FileHash-SHA256': IndicatorType.SHA256,
            'email': IndicatorType.EMAIL,
            'Mutex': IndicatorType.MUTEX
        }

        for pulse in data:
            pulse_name = pulse.get('name', 'Unknown Pulse')
            indicators = pulse.get('indicators', [])
            
            for ind in indicators:
                ind_type = ind.get('type')
                ind_value = ind.get('indicator')
                
                if ind_type in otx_type_mapping and ind_value:
                    items.append({
                        'type': otx_type_mapping[ind_type],
                        'value': ind_value,
                        'description': f"From OTX Pulse: {pulse_name}",
                        'confidence': 70,  # Default moderate-high for OTX pulses
                        'severity': 'high' # Assuming indicators in pulses are malicious
                    })
                    
        return items
