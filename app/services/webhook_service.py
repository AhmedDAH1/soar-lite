import hashlib
import hmac
from typing import Optional, Dict, Any
from app.config import get_settings

settings = get_settings()


class WebhookService:
    """
    Webhook validation and processing service.
    """
    
    @staticmethod
    def validate_signature(payload: str, signature: str, secret: str) -> bool:
        """
        Validate webhook signature using HMAC-SHA256.
        
        This prevents attackers from sending fake alerts to your SOAR platform.
        
        Args:
            payload: Raw request body (string)
            signature: Signature from X-Webhook-Signature header
            secret: Shared secret key
            
        Returns:
            True if signature is valid
            
        Example:
            # Sending system computes:
            signature = HMAC-SHA256(payload, secret_key)
            
            # We verify:
            expected = HMAC-SHA256(payload, secret_key)
            return signature == expected
        """
        if not secret:
            # If no secret configured, skip validation (dev mode)
            return True
        
        # Compute expected signature
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Constant-time comparison (prevents timing attacks)
        return hmac.compare_digest(signature, expected_signature)
    
    @staticmethod
    def parse_siem_alert(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Splunk-style SIEM alert format.
        
        Example Splunk webhook:
        {
          "search_name": "Failed SSH Logins",
          "result": {
            "src_ip": "1.2.3.4",
            "count": 5
          },
          "severity": "high"
        }
        """
        return {
            'source': 'siem',
            'title': data.get('search_name', 'SIEM Alert'),
            'description': f"Correlation rule triggered: {data.get('search_name', 'Unknown')}",
            'severity': data.get('severity', 'medium'),
            'raw_data': data.get('result', {})
        }
    
    @staticmethod
    def parse_edr_alert(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CrowdStrike/EDR-style alert format.
        
        Example EDR webhook:
        {
          "alert_type": "malware_detected",
          "hostname": "DESKTOP-123",
          "file_hash": "abc123...",
          "severity": "critical"
        }
        """
        return {
            'source': 'edr',
            'title': f"{data.get('alert_type', 'EDR Alert')} on {data.get('hostname', 'unknown host')}",
            'description': f"Endpoint detection: {data.get('alert_type')}",
            'severity': data.get('severity', 'high'),
            'raw_data': data
        }
    
    @staticmethod
    def parse_email_alert(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse email phishing report format.
        
        Example email gateway webhook:
        {
          "from": "attacker@evil.com",
          "subject": "Urgent: Reset your password",
          "recipient": "victim@company.com",
          "verdict": "phishing"
        }
        """
        return {
            'source': 'email_gateway',
            'title': f"Phishing email: {data.get('subject', 'No subject')[:50]}",
            'description': f"From: {data.get('from')} | To: {data.get('recipient')} | Verdict: {data.get('verdict')}",
            'severity': 'medium',
            'raw_data': data
        }
    
    @staticmethod
    def parse_generic_alert(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse generic webhook format (fallback).
        
        Handles any JSON with common fields like:
        - title/summary/name
        - description/message/details
        - severity/priority
        """
        # Try to find a title
        title = (
            data.get('title') or 
            data.get('summary') or 
            data.get('name') or 
            data.get('alert_name') or
            'Generic Webhook Alert'
        )
        
        # Try to find description
        description = (
            data.get('description') or
            data.get('message') or
            data.get('details') or
            str(data)[:200]
        )
        
        # Try to find severity
        severity = (
            data.get('severity') or
            data.get('priority') or
            data.get('risk_level') or
            'medium'
        )
        
        return {
            'source': data.get('source', 'webhook'),
            'title': title,
            'description': description,
            'severity': severity,
            'raw_data': data
        }