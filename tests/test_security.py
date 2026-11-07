"""
Security controls added in 2.0.0. Each test fails if the control is removed.

Alerts are written by whoever sends them, often an attacker (a phishing
subject, a scanner's User-Agent), so the platform must check who sent an
alert and must never let alert text run as code in the analyst's browser.
"""

import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.services.webhook_service import SIGNATURE_HEADER, TIMESTAMP_HEADER
from tests.helpers import post_webhook, signed_headers

client = TestClient(app)
STATIC = Path(__file__).resolve().parent.parent / "static"
ALERT = {"search_name": "Port scan", "description": "Scan from 10.0.0.5", "severity": "high"}
WEBHOOKS = ["/api/webhooks/siem", "/api/webhooks/edr", "/api/webhooks/email", "/api/webhooks/generic"]


# ── Signed webhooks ───────────────────────────────────────────────

@pytest.mark.parametrize("path", WEBHOOKS)
def test_unsigned_webhooks_are_refused(path):
    # Before 2.0.0 these created an incident for anyone who asked.
    response = client.post(path, json=ALERT)
    assert response.status_code == 401


@pytest.mark.parametrize("path", WEBHOOKS)
def test_signed_webhooks_are_accepted(path):
    assert post_webhook(client, path, ALERT).status_code == 201


def test_signature_with_the_wrong_secret_is_refused():
    response = post_webhook(client, "/api/webhooks/siem", ALERT, secret="your_webhook_secret")
    assert response.status_code == 401


def test_body_changed_after_signing_is_refused():
    body = json.dumps(ALERT).encode()
    headers = signed_headers(body)
    tampered = json.dumps(dict(ALERT, severity="low")).encode()
    assert client.post("/api/webhooks/siem", content=tampered, headers=headers).status_code == 401


def test_replayed_old_request_is_refused():
    old = int(time.time()) - get_settings().WEBHOOK_MAX_AGE - 60
    response = post_webhook(client, "/api/webhooks/siem", ALERT, timestamp=old)
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


def test_changing_the_timestamp_breaks_the_signature():
    body = json.dumps(ALERT).encode()
    headers = signed_headers(body, timestamp=int(time.time()) - 1000)
    headers[TIMESTAMP_HEADER] = str(int(time.time()))  # make an old request look fresh
    assert client.post("/api/webhooks/siem", content=body, headers=headers).status_code == 401


def test_garbage_headers_are_refused():
    headers = {TIMESTAMP_HEADER: "yesterday", SIGNATURE_HEADER: "sha256=00"}
    assert client.post("/api/webhooks/siem", json=ALERT, headers=headers).status_code == 401


def test_webhooks_are_disabled_without_a_secret(monkeypatch):
    monkeypatch.setattr(get_settings(), "WEBHOOK_SECRET", "")
    response = post_webhook(client, "/api/webhooks/siem", ALERT)
    assert response.status_code == 503


def test_no_secret_is_hard_coded():
    source = Path("app/routers/webhooks.py").read_text() + Path("app/services/webhook_service.py").read_text()
    assert "your_webhook_secret" not in source


# ── Read-only demo ────────────────────────────────────────────────

@pytest.fixture
def demo_mode(monkeypatch):
    monkeypatch.setattr(get_settings(), "DEMO_MODE", True)


def test_demo_refuses_every_change(demo_mode):
    assert client.post("/api/alerts/", json={"source": "x", "title": "x"}).status_code == 403
    assert post_webhook(client, "/api/webhooks/siem", ALERT).status_code == 403
    assert client.patch("/api/incidents/1", json={"status": "resolved"}).status_code == 403
    assert client.post("/api/enrichment/incident/1").status_code == 403  # would spend API quota
    assert client.post("/api/playbooks/execute/1").status_code == 403


def test_demo_can_still_be_viewed(demo_mode):
    assert client.get("/api/incidents/").status_code == 200
    assert client.get("/health").json()["demo_mode"] is True


def test_old_seed_demo_setting_also_makes_the_demo_read_only(monkeypatch):
    # The live demo was deployed with SEED_DEMO=1.
    monkeypatch.setattr(get_settings(), "SEED_DEMO", True)
    assert client.post("/api/alerts/", json={"source": "x", "title": "x"}).status_code == 403


# ── Browser protections ───────────────────────────────────────────

def test_pages_send_a_strict_content_security_policy():
    csp = client.get("/").headers["Content-Security-Policy"].split("; ")
    assert "script-src 'self'" in csp       # no inline scripts, no third-party scripts
    assert "style-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


@pytest.mark.parametrize("page", ["index.html", "incident.html"])
def test_pages_load_no_third_party_code(page):
    # Chart.js and Tailwind are bundled in static/vendor/; CDNs can be
    # compromised, and are blocked in some regions.
    html = (STATIC / page).read_text()
    assert not re.search(r"""(src|href)=["']https?://""", html)


def test_other_websites_cannot_read_the_api():
    # The wildcard CORS policy let any website read every incident.
    response = client.get("/api/incidents/", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in response.headers


def test_api_docs_are_off_by_default():
    assert get_settings().DEBUG is False


@pytest.mark.parametrize("page", ["index.html", "incident.html"])
def test_pages_have_no_inline_scripts_or_handlers(page):
    # The CSP blocks these, so any left behind would be broken buttons.
    html = (STATIC / page).read_text()
    assert not re.search(r"\son[a-z]+\s*=", html)
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)


@pytest.mark.parametrize("script", ["app.js", "incident-detail.js"])
def test_alert_data_is_escaped_before_it_becomes_html(script):
    source = (STATIC / script).read_text()
    for field in ["incident.title", "alert.title", "alert.description", "ioc.value", "action.description"]:
        if field in source:
            # every interpolation of the field goes through esc(...)
            assert not re.search(r"\$\{" + re.escape(field) + r"\}", source), field


# ── Reports ───────────────────────────────────────────────────────

def _incident_titled(title):
    return client.post("/api/alerts/", json={"source": "siem", "title": title, "description": title}).json()["incident_id"]


def test_markup_in_an_alert_does_not_break_the_pdf_report():
    # ReportLab parses <tags> in Paragraph text; an unknown tag made report generation fail.
    incident = _incident_titled("Scan <img src=x onerror=alert(1)>")
    assert client.get(f"/api/reports/incident/{incident}/pdf").status_code == 200


def test_an_alert_cannot_plant_a_link_in_the_pdf_report():
    incident = _incident_titled('Report <a href="https://evil.example/login">open evidence</a>')
    pdf = client.get(f"/api/reports/incident/{incident}/pdf").content
    assert b"/URI" not in pdf  # no clickable link annotation
