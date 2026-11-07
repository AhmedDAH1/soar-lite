import ipaddress
import re

from app.models.ioc import IOCType

# File extensions that aren't top-level domains: "invoice.pdf.exe" in an alert
# is an attachment name, not a domain to look up.
FILE_EXTENSIONS = {
    "exe", "dll", "scr", "bat", "cmd", "vbs", "js", "jar", "hta", "lnk", "iso",
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf",
    "txt", "csv", "htm", "html",
}


class IOCExtractor:
    """
    Extracts Indicators of Compromise (IOCs) from text using regex patterns.

    Supports extraction of:
    - IPv4 addresses
    - Domain names
    - Email addresses
    - MD5 hashes
    - SHA256 hashes
    """

    # Regex patterns for different IOC types
    PATTERNS = {
        IOCType.IP: r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        IOCType.DOMAIN: r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
        IOCType.EMAIL: r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        IOCType.MD5: r'\b[a-fA-F0-9]{32}\b',
        IOCType.SHA256: r'\b[a-fA-F0-9]{64}\b',
    }

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Internal addresses (RFC 1918, loopback, link-local, ...).

        They are still extracted as IOCs, since an internal host scanning the
        network is exactly what an analyst needs to see, but they are never
        sent to external enrichment services.
        """
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not address.is_global

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IPv4 address (all octets 0-255)"""
        octets = ip.split('.')
        if len(octets) != 4:
            return False

        try:
            return all(0 <= int(octet) <= 255 for octet in octets)
        except ValueError:
            return False

    @staticmethod
    def extract_from_text(text: str, source: str = "unknown") -> list[dict]:
        """
        Extract all IOCs from text.

        Args:
            text: Text to extract IOCs from (alert title, description, etc.)
            source: Where the text came from (e.g., "alert_title")

        Returns:
            List of dicts with keys: type, value, extracted_from
        """
        if not text:
            return []

        iocs = []
        seen = set()  # Prevent duplicates

        # Extract each IOC type
        for ioc_type, pattern in IOCExtractor.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)

            for match in matches:
                value = match.lower().strip()

                # Type-specific validation
                if ioc_type == IOCType.IP and not IOCExtractor.is_valid_ip(value):
                    continue
                if ioc_type == IOCType.DOMAIN and value.rsplit(".", 1)[-1] in FILE_EXTENSIONS:
                    continue

                # Avoid duplicates
                ioc_key = f"{ioc_type.value}:{value}"
                if ioc_key in seen:
                    continue

                seen.add(ioc_key)
                iocs.append({
                    "type": ioc_type,
                    "value": value,
                    "extracted_from": source
                })

        return iocs

    @staticmethod
    def extract_from_alert_data(alert_data: dict) -> list[dict]:
        """
        Extract IOCs from all text fields in alert data.

        Args:
            alert_data: Dict with 'title', 'description', 'raw_data' fields

        Returns:
            List of extracted IOCs with source tracking
        """
        all_iocs = []

        # Extract from title
        if alert_data.get('title'):
            all_iocs.extend(
                IOCExtractor.extract_from_text(alert_data['title'], "alert_title")
            )

        # Extract from description
        if alert_data.get('description'):
            all_iocs.extend(
                IOCExtractor.extract_from_text(alert_data['description'], "alert_description")
            )

        # Extract from raw_data (convert dict to string)
        if alert_data.get('raw_data'):
            raw_text = str(alert_data['raw_data'])
            all_iocs.extend(
                IOCExtractor.extract_from_text(raw_text, "alert_raw_data")
            )

        # The same indicator often appears in the title, the description and
        # the raw data: keep one, from the first place it was found.
        unique, seen = [], set()
        for ioc in all_iocs:
            key = (ioc["type"], ioc["value"])
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        return unique
