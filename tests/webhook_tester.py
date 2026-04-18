#!/usr/bin/env python3
"""
Webhook testing tool - simulates external systems sending alerts.

Usage:
    python tests/webhook_tester.py
"""

import requests
import json

API_BASE = "http://127.0.0.1:8000"

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
    
    response = requests.post(f"{API_BASE}/api/webhooks/siem", json=payload)
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
    
    response = requests.post(f"{API_BASE}/api/webhooks/edr", json=payload)
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
    
    response = requests.post(f"{API_BASE}/api/webhooks/email", json=payload)
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
    
    response = requests.post(f"{API_BASE}/api/webhooks/generic", json=payload)
    print(f"\nGeneric Webhook: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    return response.json()


if __name__ == "__main__":
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