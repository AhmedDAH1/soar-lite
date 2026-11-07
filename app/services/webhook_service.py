import hashlib
import hmac
from typing import Any

SIGNATURE_HEADER = "X-Webhook-Signature"
TIMESTAMP_HEADER = "X-Webhook-Timestamp"


class WebhookService:
    """
    Webhook signing and payload parsing.

    Every webhook request must be signed by the sender with the shared
    WEBHOOK_SECRET, so nobody else can create incidents:

        X-Webhook-Timestamp: <unix time in seconds>
        X-Webhook-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>." + raw body>

    The timestamp is part of what is signed, and requests older than
    WEBHOOK_MAX_AGE seconds are refused, so a captured request can't be
    replayed later. This is the scheme Stripe and Slack use.
    """

    @staticmethod
    def sign(body: bytes, secret: str, timestamp: int) -> str:
        """The X-Webhook-Signature value for a request body sent at `timestamp`."""
        message = f"{timestamp}.".encode() + body
        return "sha256=" + hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

    @staticmethod
    def check_signature(
        body: bytes, secret: str, timestamp: str | None, signature: str | None,
        now: float, max_age: int,
    ) -> str | None:
        """None if the request is authentic, otherwise the reason it isn't."""
        if not timestamp or not signature:
            return f"Missing {TIMESTAMP_HEADER} or {SIGNATURE_HEADER} header"
        try:
            sent_at = int(timestamp)
        except ValueError:
            return f"Invalid {TIMESTAMP_HEADER}"
        if abs(now - sent_at) > max_age:
            return "Request expired: timestamp too old or too far in the future"
        expected = WebhookService.sign(body, secret, sent_at)
        # Constant-time comparison, so the signature can't be guessed byte by byte
        if not hmac.compare_digest(signature.encode(), expected.encode()):
            return "Invalid signature"
        return None

    @staticmethod
    def parse_siem_alert(data: dict[str, Any]) -> dict[str, Any]:
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
            'description': data.get('description')
            or f"Correlation rule triggered: {data.get('search_name', 'Unknown')}",
            'severity': data.get('severity', 'medium'),
            'raw_data': data.get('result', {})
        }

    @staticmethod
    def parse_edr_alert(data: dict[str, Any]) -> dict[str, Any]:
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
    def parse_email_alert(data: dict[str, Any]) -> dict[str, Any]:
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
            'description': data.get('description')
            or f"From: {data.get('from')} | To: {data.get('recipient')} | Verdict: {data.get('verdict')}",
            'severity': data.get('severity', 'medium'),
            'raw_data': data
        }

    @staticmethod
    def parse_generic_alert(data: dict[str, Any]) -> dict[str, Any]:
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
