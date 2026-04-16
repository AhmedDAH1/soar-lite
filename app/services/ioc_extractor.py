import re
from typing import List, Dict, Tuple
from app.models.ioc import IOCType


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
    
    # Private IP ranges (RFC 1918) - exclude these from extraction
    PRIVATE_IP_PATTERNS = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^169\.254\.',
    ]
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is in private range (RFC 1918)"""
        for pattern in IOCExtractor.PRIVATE_IP_PATTERNS:
            if re.match(pattern, ip):
                return True
        return False
    
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
    def extract_from_text(text: str, source: str = "unknown") -> List[Dict]:
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
                if ioc_type == IOCType.IP:
                    if not IOCExtractor.is_valid_ip(value):
                        continue
                    if IOCExtractor.is_private_ip(value):
                        continue  # Skip private IPs (not threat intel worthy)
                
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
    def extract_from_alert_data(alert_data: Dict) -> List[Dict]:
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
        
        return all_iocs