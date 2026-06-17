import os
import requests
from typing import Any, Dict, List
from apps.intelligence.models import IndicatorType
from .base import BaseIngestionSource

class AbuseIPDBIngestionSource(BaseIngestionSource):
    """
    AbuseIPDB Ingestion Source.
    Fetches blacklisted IPs.
    """
    source_name = "AbuseIPDB"
    base_url = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self):
        self.api_key = os.environ.get('ABUSEIPDB_API_KEY')
        super().__init__()

    def _setup_auth(self):
        self.session.headers.update({
            'Key': self.api_key,
            'Accept': 'application/json'
        })

    def fetch_data(self) -> Any:
        if not self.api_key:
            raise ValueError("ABUSEIPDB_API_KEY is not set.")
            
        # Fetch a list of the most reported IPs (blacklist)
        url = f"{self.base_url}/blacklist"
        response = self.session.get(url, params={'confidenceMinimum': 90, 'limit': 1000})
        
        if response.status_code == 429:
            raise self.RateLimitExceeded("AbuseIPDB Rate Limit Exceeded.")
            
        response.raise_for_status()
        return response.json().get('data', [])

    def parse_data(self, data: Any) -> List[Dict]:
        items = []
        
        for record in data:
            ip_address = record.get('ipAddress')
            abuse_score = record.get('abuseConfidenceScore', 0)
            
            if ip_address:
                # Basic distinction (AbuseIPDB usually returns IPv4 for blacklist unless specified)
                # We can assume IPV4 for simplicity unless a colon is found
                ind_type = IndicatorType.IPV6 if ':' in ip_address else IndicatorType.IPV4
                
                items.append({
                    'type': ind_type,
                    'value': ip_address,
                    'description': f"Blacklisted by AbuseIPDB with score {abuse_score}",
                    'confidence': abuse_score,
                    'severity': 'critical' if abuse_score > 90 else 'high'
                })
                    
        return items
