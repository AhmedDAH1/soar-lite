from app.models.ioc import IOCType
from app.services.ioc_extractor import IOCExtractor


def test_extract_ipv4():
    """Test IPv4 extraction"""
    text = "Attacker IP is 185.220.101.50 and 8.8.8.8"
    iocs = IOCExtractor.extract_from_text(text)

    ip_iocs = [ioc for ioc in iocs if ioc["type"] == IOCType.IP]
    assert len(ip_iocs) == 2
    assert "185.220.101.50" in [ioc["value"] for ioc in ip_iocs]


def test_private_ips_are_extracted_but_marked_internal():
    """An internal host scanning the network is what the analyst needs to see,
    so internal addresses are IOCs too; they are just never enriched."""
    text = "Internal host 192.168.1.100 and 10.0.0.1 detected"
    iocs = IOCExtractor.extract_from_text(text)

    ip_values = {ioc["value"] for ioc in iocs if ioc["type"] == IOCType.IP}
    assert ip_values == {"192.168.1.100", "10.0.0.1"}
    assert all(IOCExtractor.is_private_ip(ip) for ip in ip_values)
    assert not IOCExtractor.is_private_ip("8.8.8.8")


def test_private_ips_are_never_sent_to_enrichment_services(monkeypatch):
    import asyncio
    from types import SimpleNamespace

    from app.services.enrichment_service import EnrichmentService

    async def must_not_be_called(ip):
        raise AssertionError(f"{ip} was sent to an external service")

    monkeypatch.setattr(EnrichmentService, "enrich_ip", must_not_be_called)
    ioc = SimpleNamespace(type=IOCType.IP, value="10.0.0.5", enrichment_data=None)
    asyncio.run(EnrichmentService.enrich_ioc(db=None, ioc=ioc))
    assert ioc.enrichment_data is None


def test_same_indicator_in_several_fields_is_one_ioc():
    alert = {"title": "Scan from 45.33.32.156", "description": "Source 45.33.32.156",
             "raw_data": {"src_ip": "45.33.32.156"}}
    iocs = IOCExtractor.extract_from_alert_data(alert)
    assert [(i["value"], i["extracted_from"]) for i in iocs] == [("45.33.32.156", "alert_title")]


def test_attachment_names_are_not_domains():
    iocs = IOCExtractor.extract_from_text("Attachment invoice.pdf.exe from evil-domain.ru")
    domains = {i["value"] for i in iocs if i["type"] == IOCType.DOMAIN}
    assert domains == {"evil-domain.ru"}

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
