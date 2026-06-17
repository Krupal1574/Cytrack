import pytest
from unittest.mock import patch, MagicMock
from apps.intelligence.models import IndicatorOfCompromise, Vulnerability
from apps.ingestion.sources.otx import OTXIngestionSource
from apps.ingestion.sources.abuseipdb import AbuseIPDBIngestionSource
from apps.ingestion.sources.cisa import CISAKEVIngestionSource
from apps.ingestion.sources.virustotal import VirusTotalIngestionSource
from apps.ingestion.tasks import ingest_otx_pulses, ingest_abuseipdb_blacklist, ingest_cisa_kev

@pytest.fixture
def mock_requests_get():
    with patch('requests.Session.get') as mock_get:
        yield mock_get

@pytest.mark.django_db
class TestOTXIngestion:
    @patch.dict('os.environ', {'OTX_API_KEY': 'test_key'})
    def test_otx_ingestion(self, mock_requests_get):
        source = OTXIngestionSource()
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'results': [
                {
                    'name': 'Test Pulse',
                    'indicators': [
                        {'type': 'IPv4', 'indicator': '192.168.1.1'},
                        {'type': 'domain', 'indicator': 'evil.com'}
                    ]
                }
            ]
        }
        mock_requests_get.return_value = mock_response
        
        source.run()
        
        # Verify
        iocs = IndicatorOfCompromise.objects.all()
        assert iocs.count() == 2
        
        ip_ioc = IndicatorOfCompromise.objects.get(value='192.168.1.1')
        assert ip_ioc.type == 'ipv4'
        assert ip_ioc.source_nodes.filter(name='AlienVault OTX').exists()
        
        domain_ioc = IndicatorOfCompromise.objects.get(value='evil.com')
        assert domain_ioc.type == 'domain'

@pytest.mark.django_db
class TestAbuseIPDBIngestion:
    @patch.dict('os.environ', {'ABUSEIPDB_API_KEY': 'test_key'})
    def test_abuseipdb_ingestion(self, mock_requests_get):
        source = AbuseIPDBIngestionSource()
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'data': [
                {'ipAddress': '10.0.0.1', 'abuseConfidenceScore': 100},
            ]
        }
        mock_requests_get.return_value = mock_response
        
        source.run()
        
        # Verify
        iocs = IndicatorOfCompromise.objects.all()
        assert iocs.count() == 1
        
        ip_ioc = IndicatorOfCompromise.objects.get(value='10.0.0.1')
        assert ip_ioc.type == 'ipv4'
        assert ip_ioc.severity == 'critical'
        assert ip_ioc.source_nodes.filter(name='AbuseIPDB').exists()

@pytest.mark.django_db
class TestCISAKEVIngestion:
    def test_cisa_kev_ingestion(self, mock_requests_get):
        source = CISAKEVIngestionSource()
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'vulnerabilities': [
                {
                    'cveID': 'CVE-2021-44228',
                    'shortDescription': 'Log4Shell',
                    'dateAdded': '2021-12-10',
                    'dueDate': '2021-12-24',
                    'requiredAction': 'Apply updates'
                }
            ]
        }
        mock_requests_get.return_value = mock_response
        
        source.run()
        
        # Verify
        vulns = Vulnerability.objects.all()
        assert vulns.count() == 1
        
        vuln = Vulnerability.objects.get(cve_id='CVE-2021-44228')
        assert vuln.is_kev is True
        assert vuln.description == 'Log4Shell'

@pytest.mark.django_db
class TestTasks:
    @patch('apps.ingestion.sources.otx.OTXIngestionSource.run')
    def test_ingest_otx_task(self, mock_run):
        ingest_otx_pulses()
        mock_run.assert_called_once()
