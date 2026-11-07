#!/usr/bin/env python3
"""
Webhook testing tool - simulates external systems sending alerts.

Usage (with the server running and the same secret set):
    WEBHOOK_SECRET=... python tests/webhook_tester.py
"""

import json
import os
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.services.webhook_service import (  # noqa: E402
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookService,
)

API_BASE = "http://127.0.0.1:8000"
SECRET = os.environ.get("WEBHOOK_SECRET", "")


def post_signed(path, payload):
    """Send a webhook signed the way SOAR-Lite requires (README, "Sending alerts")."""
    body = json.dumps(payload).encode()
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        TIMESTAMP_HEADER: str(timestamp),
        SIGNATURE_HEADER: WebhookService.sign(body, SECRET, timestamp),
    }
    return requests.post(f"{API_BASE}{path}", data=body, headers=headers, timeout=10)

def test_siem_webhook():
    """Simulate Splunk SIEM sending brute force alert"""
    payload = {
        "search_name": "SSH Brute Force Detected",
        "result": {
            "src_ip": "89.248.165.41",
            "dest_ip": "10.0.5.100",
            "failed_attempts": 127,
            "username": "root",
            "protocol": "ssh"
        },
        "severity": "high"
    }

    response = post_signed("/api/webhooks/siem", payload)
    print(f"SIEM Webhook: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    return response.json()


def test_edr_webhook():
    """Simulate CrowdStrike EDR sending malware alert"""
    payload = {
        "alert_type": "malware_execution",
        "hostname": "LAPTOP-SALES-05",
        "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        "file_path": "C:\\Users\\jane\\Downloads\\invoice.exe",
        "severity": "critical",
        "user": "jane.smith",
        "process_id": 4521
    }

    response = post_signed("/api/webhooks/edr", payload)
    print(f"\nEDR Webhook: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    return response.json()


def test_email_webhook():
    """Simulate email gateway sending phishing report"""
    payload = {
        "from": "ceo@evil-lookalike.com",
        "subject": "RE: Urgent Wire Transfer Needed",
        "recipient": "finance@company.com",
        "verdict": "phishing",
        "urls": ["http://fake-company-portal.ru/login"],
        "attachments": ["payment_details.pdf.exe"],
        "timestamp": "2026-04-17T14:30:00Z"
    }

    response = post_signed("/api/webhooks/email", payload)
    print(f"\nEmail Webhook: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    return response.json()


def test_generic_webhook():
    """Simulate custom tool sending generic alert"""
    payload = {
        "source": "firewall",
        "alert_name": "Port Scan Detected",
        "message": "Nmap scan detected from 45.33.32.156 targeting 10.0.0.0/24",
        "priority": "medium",
        "raw_data": {
            "scanner_ip": "45.33.32.156",
            "target_network": "10.0.0.0/24",
            "ports_scanned": [22, 80, 443, 3389, 8080]
        }
    }

    response = post_signed("/api/webhooks/generic", payload)
    print(f"\nGeneric Webhook: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    return response.json()


if __name__ == "__main__":
    if not SECRET:
        sys.exit("Set WEBHOOK_SECRET to the server's secret first.")
    print("🚀 Testing Webhook Endpoints\n")
    print("=" * 50)

    try:
        test_siem_webhook()
        test_edr_webhook()
        test_email_webhook()
        test_generic_webhook()

        print("\n" + "=" * 50)
        print("✅ All webhooks sent successfully!")
        print("\nCheck dashboard at http://127.0.0.1:8000")

    except requests.exceptions.ConnectionError:
        print("❌ Error: Cannot connect to API")
        print("Make sure server is running: uvicorn app.main:app --reload")
    except Exception as e:
        print(f"❌ Error: {e}")
