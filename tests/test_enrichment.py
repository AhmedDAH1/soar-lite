import pytest
from app.services.enrichment_service import EnrichmentService


@pytest.mark.asyncio
async def test_enrich_ip():
    """Test IP enrichment (requires valid API keys)"""
    # Using Google DNS (should be harmless)
    enrichment = await EnrichmentService.enrich_ip("8.8.8.8")
    
    # Should have geolocation at minimum (no API key required)
    assert "geolocation" in enrichment
    assert enrichment["geolocation"]["country"] is not None


@pytest.mark.asyncio
async def test_enrich_hash_not_found():
    """Test hash enrichment with unknown hash"""
    # Random hash not in VirusTotal database
    fake_hash = "00000000000000000000000000000000"
    enrichment = await EnrichmentService.enrich_hash(fake_hash)
    
    # Should get response even if not found
    if enrichment.get("virustotal"):
        assert enrichment["virustotal"].get("status") == "not_found"


def test_determine_malicious_status_virustotal():
    """Test malicious determination based on VirusTotal data"""
    enrichment_data = {
        "virustotal": {
            "malicious": 5,
            "suspicious": 2
        }
    }
    
    is_malicious = EnrichmentService.determine_malicious_status(enrichment_data)
    assert is_malicious is True


def test_determine_malicious_status_abuseipdb():
    """Test malicious determination based on AbuseIPDB data"""
    enrichment_data = {
        "abuseipdb": {
            "abuse_confidence_score": 90
        }
    }
    
    is_malicious = EnrichmentService.determine_malicious_status(enrichment_data)
    assert is_malicious is True


def test_determine_malicious_status_harmless():
    """Test harmless IOC determination"""
    enrichment_data = {
        "virustotal": {
            "malicious": 0,
            "harmless": 50
        },
        "abuseipdb": {
            "abuse_confidence_score": 0
        }
    }
    
    is_malicious = EnrichmentService.determine_malicious_status(enrichment_data)
    assert is_malicious is False