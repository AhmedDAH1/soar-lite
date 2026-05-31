"""
Demo data seeding.

On startup, if the database has no incidents yet, inserts a handful of
realistic security alerts through the normal ingestion path
(create_alert_with_incident) so the dashboard shows meaningful content.

Because the alerts carry real indicators (IPs, file hashes, domains) in
their text, the IOC extractor picks them up automatically — the seeded
data demonstrates the full ingestion → incident → IOC-extraction pipeline,
not just static rows.

Safe by design: only seeds when the incidents table is empty, so it never
duplicates data or overwrites a populated database.
"""

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Incident
from app.schemas.alert import AlertCreate
from app.services.alert_service import create_alert_with_incident

DEMO_ALERTS = [
    AlertCreate(
        source="siem",
        title="Multiple failed SSH login attempts",
        description=(
            "15 failed SSH login attempts detected from 185.220.101.47 "
            "targeting host 10.0.0.5 within 60 seconds. Possible brute-force attack."
        ),
        severity="high",
        raw_data={
            "src_ip": "185.220.101.47",
            "dest_ip": "10.0.0.5",
            "attempts": 15,
            "protocol": "ssh",
            "rule": "Multiple Failed Logins",
        },
    ),
    AlertCreate(
        source="edr",
        title="Malware detected on endpoint LAPTOP-FIN-07",
        description=(
            "EDR flagged a malicious executable on LAPTOP-FIN-07 (user: j.martin). "
            "File hash 44d88612fea8a8f36de82e1278abb02f matched a known trojan signature. "
            "Outbound connection attempt to malware-c2.example-bad.com observed."
        ),
        severity="critical",
        raw_data={
            "hostname": "LAPTOP-FIN-07",
            "user": "j.martin",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f",
            "c2_domain": "malware-c2.example-bad.com",
            "action": "quarantined",
        },
    ),
    AlertCreate(
        source="email",
        title="Phishing email reported by user",
        description=(
            "User victim@company.com reported a phishing email from "
            "billing@paypa1-secure.com with subject 'URGENT: Verify your account'. "
            "Message contained a credential-harvesting link: http://198.51.100.23/login/verify."
        ),
        severity="medium",
        raw_data={
            "from": "billing@paypa1-secure.com",
            "recipient": "victim@company.com",
            "subject": "URGENT: Verify your account",
            "url": "http://198.51.100.23/login/verify",
            "verdict": "phishing",
        },
    ),
    AlertCreate(
        source="siem",
        title="Internal host port scan detected",
        description=(
            "Host 10.0.0.88 scanned 1,024 ports across the 10.0.0.0/24 subnet in under "
            "two minutes. Behaviour consistent with internal reconnaissance."
        ),
        severity="medium",
        raw_data={
            "src_ip": "10.0.0.88",
            "ports_scanned": 1024,
            "subnet": "10.0.0.0/24",
            "rule": "Horizontal Port Scan",
        },
    ),
]


def seed_demo_data() -> None:
    """Insert demo alerts if the database is empty. Idempotent."""
    db: Session = SessionLocal()
    try:
        if db.query(Incident).first() is not None:
            return  # Already has data — never duplicate or overwrite.

        for alert in DEMO_ALERTS:
            create_alert_with_incident(db, alert)
        db.commit()
        print(f"🌱 Seeded {len(DEMO_ALERTS)} demo alerts for the dashboard")
    except Exception as e:
        db.rollback()
        print(f"⚠️  Demo seed skipped due to error: {e}")
    finally:
        db.close()
