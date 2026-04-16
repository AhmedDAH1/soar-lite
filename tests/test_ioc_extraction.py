from app.services.ioc_extractor import IOCExtractor
from app.models.ioc import IOCType


def test_extract_ipv4():
    """Test IPv4 extraction"""
    text = "Attacker IP is 185.220.101.50 and 8.8.8.8"
    iocs = IOCExtractor.extract_from_text(text)
    
    ip_iocs = [ioc for ioc in iocs if ioc["type"] == IOCType.IP]
    assert len(ip_iocs) == 2
    assert "185.220.101.50" in [ioc["value"] for ioc in ip_iocs]


def test_private_ip_filtered():
    """Test that private IPs are excluded"""
    text = "Internal host 192.168.1.100 and 10.0.0.1 detected"
    iocs = IOCExtractor.extract_from_text(text)
    
    ip_iocs = [ioc for ioc in iocs if ioc["type"] == IOCType.IP]
    assert len(ip_iocs) == 0  # Both are private


def test_extract_domain():
    """Test domain extraction"""
    text = "Downloaded from evil-server.com and malware.ru"
    iocs = IOCExtractor.extract_from_text(text)
    
    domain_iocs = [ioc for ioc in iocs if ioc["type"] == IOCType.DOMAIN]
    assert len(domain_iocs) == 2
    assert "evil-server.com" in [ioc["value"] for ioc in domain_iocs]


def test_extract_email():
    """Test email extraction"""
    text = "Phishing from attacker@evil.com"
    iocs = IOCExtractor.extract_from_text(text)
    
    email_iocs = [ioc for ioc in iocs if ioc["type"] == IOCType.EMAIL]
    assert len(email_iocs) == 1
    assert email_iocs[0]["value"] == "attacker@evil.com"


def test_extract_md5_hash():
    """Test MD5 hash extraction"""
    text = "Malware hash: 44d88612fea8a8f36de82e1278abb02f"
    iocs = IOCExtractor.extract_from_text(text)
    
    hash_iocs = [ioc for ioc in iocs if ioc["type"] == IOCType.MD5]
    assert len(hash_iocs) == 1
    assert hash_iocs[0]["value"] == "44d88612fea8a8f36de82e1278abb02f"


def test_extract_sha256_hash():
    """Test SHA256 hash extraction"""
    text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = IOCExtractor.extract_from_text(text)
    
    hash_iocs = [ioc for ioc in iocs if ioc["type"] == IOCType.SHA256]
    assert len(hash_iocs) == 1


def test_no_duplicate_extraction():
    """Test that duplicate IOCs are not extracted twice"""
    text = "IP 8.8.8.8 and 8.8.8.8 again"
    iocs = IOCExtractor.extract_from_text(text)
    
    ip_iocs = [ioc for ioc in iocs if ioc["type"] == IOCType.IP]
    assert len(ip_iocs) == 1  # Only extracted once