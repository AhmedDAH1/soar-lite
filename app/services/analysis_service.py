"""
Analyse uploaded logs and emails ("Analyze logs" on the dashboard).

SOAR-Lite doesn't parse logs itself. It hands them to the detection tools
that do, over their HTTP APIs, and turns what they find into incidents
exactly as if the tools had sent them by webhook:

- logs (SSH auth, web server access, firewall syslog) → Log Threat Detector
- emails (.eml) → Email Threat Analyzer

Each detection becomes an incident with its IOCs extracted, and, when a
model is configured, goes to AI triage.
"""

import re

import requests
from sqlalchemy.orm import Session

from app.config import get_settings
from app.schemas.alert import WebhookAlert
from app.services.alert_service import create_alert_with_incident
from app.services.webhook_service import WebhookService

TIMEOUT_SECONDS = 60
MAX_FILES = 20
MAX_TOTAL_BYTES = 5 * 1024 * 1024
EMAIL_HEADER = re.compile(r"^(from|to|subject|received|return-path|message-id|mime-version):", re.IGNORECASE | re.MULTILINE)


class AnalyzerUnavailableError(Exception):
    pass


def is_email(name: str, content: str) -> bool:
    """An .eml file, or text that starts with email headers."""
    if name.lower().endswith((".eml", ".msg")):
        return True
    head = content[:4000]
    return len(EMAIL_HEADER.findall(head)) >= 3 and "\n\n" in content


def _post(url: str, payload: dict, tool: str) -> dict:
    try:
        response = requests.post(url, json=payload, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as e:
        raise AnalyzerUnavailableError(f"{tool} isn't reachable at {url.rsplit('/api', 1)[0]} ({e.__class__.__name__}).") from None
    if response.status_code != 200:
        try:
            detail = response.json().get("error", response.text[:200])
        except ValueError:
            detail = response.text[:200]
        raise AnalyzerUnavailableError(f"{tool} refused the file: {detail}")
    return response.json()


def _health(base_url: str) -> bool:
    try:
        return requests.get(base_url.rstrip("/") + "/health", timeout=3).status_code == 200
    except requests.RequestException:
        return False


def analyzers_status() -> dict:
    s = get_settings()
    return {
        "logs": {"name": "Log Threat Detector", "url": s.LOG_ANALYZER_URL, "up": _health(s.LOG_ANALYZER_URL)},
        "email": {"name": "Email Threat Analyzer", "url": s.EMAIL_ANALYZER_URL, "up": _health(s.EMAIL_ANALYZER_URL)},
    }


def _open_incident(db: Session, parsed: dict) -> int:
    alert = create_alert_with_incident(db, WebhookAlert(**parsed).to_alert_create())
    return alert.incident_id


def analyze_files(db: Session, files: list[dict]) -> dict:
    """Send each file to the right tool and open an incident for every detection."""
    s = get_settings()
    logs = [f for f in files if not is_email(f["name"], f["content"])]
    emails = [f for f in files if is_email(f["name"], f["content"])]
    summary, incidents = [], []

    if logs:
        data = _post(s.LOG_ANALYZER_URL.rstrip("/") + "/api/analyze",
                     {"logs": [{"name": f["name"], "content": f["content"]} for f in logs]}, "Log Threat Detector")
        opened = [_open_incident(db, WebhookService.parse_siem_alert(a)) for a in data.get("alerts", [])]
        incidents += opened
        for entry in data.get("logs", []):
            summary.append({"name": entry.get("name"), "kind": "log", "type": entry.get("type_name"),
                            "entries": entry.get("entries", 0), "detections": entry.get("alerts", 0)})
        if data.get("correlated"):
            summary.append({"name": "Correlation across these logs", "kind": "correlation", "type": "Log Threat Detector",
                            "entries": None, "detections": data["correlated"]})

    for f in emails:
        data = _post(s.EMAIL_ANALYZER_URL.rstrip("/") + "/api/analyze", {"raw": f["content"]}, "Email Threat Analyzer")
        level = data.get("threat_level", "CLEAN")
        row = {"name": f["name"], "kind": "email", "type": "email", "entries": None,
               "detections": 0 if level == "CLEAN" else 1,
               "verdict": f"{level.title()} ({data.get('threat_score', 0)}/100)"}
        if level != "CLEAN" and data.get("soar"):
            incidents.append(_open_incident(db, WebhookService.parse_email_alert(data["soar"])))
        summary.append(row)

    return {"files": summary, "incident_ids": incidents}


def validate(files) -> str | None:
    if not isinstance(files, list) or not files:
        return "Choose at least one file."
    if len(files) > MAX_FILES:
        return f"At most {MAX_FILES} files at a time."
    total = 0
    for f in files:
        if not isinstance(f, dict) or not isinstance(f.get("content"), str) or not isinstance(f.get("name"), str):
            return "Each file needs a name and text content."
        total += len(f["content"].encode("utf-8"))
    if total > MAX_TOTAL_BYTES:
        return "Files too large: 5 MB at a time."
    return None
