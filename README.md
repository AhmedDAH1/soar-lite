# SOAR-Lite

> **🚀 [Live Demo →](https://soar-lite.onrender.com)** &nbsp;·&nbsp; A populated SOC dashboard with sample incidents you can explore.
> *Hosted on Render free tier — first load may take ~30 seconds while the container wakes.*

[![Live Demo](https://img.shields.io/badge/Live_Demo-Online-success?style=flat-square)](https://soar-lite.onrender.com)
![CI](https://github.com/AhmedDAH1/soar-lite/actions/workflows/ci.yml/badge.svg)
[![Release](https://img.shields.io/github/v/release/AhmedDAH1/soar-lite?style=flat-square)](https://github.com/AhmedDAH1/soar-lite/releases/latest)
[![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-blue?style=flat-square&logo=docker)](Dockerfile)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

A lightweight Security Orchestration, Automation & Response platform that demonstrates the full SOC workflow: alert ingestion, IOC extraction, threat-intelligence enrichment, automated playbook execution, case management, and incident reporting.

---

## Why I Built This

SOC analysts spend hours on repetitive triage — checking whether an IP is malicious, escalating incidents by hand, copy-pasting indicators into reports. I wanted to understand how SOAR platforms automate that loop end-to-end, so I built one. SOAR-Lite takes an alert from ingestion all the way to a finished report, applying the same orchestration pattern (ingest → extract → enrich → decide → act → document) that commercial platforms like Splunk SOAR and Cortex XSOAR use.

---

## Demo

**🚀 [Live dashboard →](https://soar-lite.onrender.com)** — explore sample incidents (brute-force SSH, malware detection, phishing, port scan) with their extracted IOCs, seeded through the real ingestion pipeline.

**🎬 [6-minute walkthrough video →](https://youtu.be/Wade9SSN-Ts)** — the full incident-response workflow from a live webhook alert through enrichment, automated playbook escalation, and PDF report generation, including VirusTotal detecting real malware (67/69 engines).

---

## Quick Start

### Option 1 — Docker with PostgreSQL (full stack)

```bash
git clone https://github.com/AhmedDAH1/soar-lite.git
cd soar-lite
docker-compose up -d        # starts the app + a PostgreSQL container
open http://localhost:8000
```

### Option 2 — Local development (SQLite)

```bash
git clone https://github.com/AhmedDAH1/soar-lite.git
cd soar-lite
python3 -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt

alembic upgrade head         # create the schema
uvicorn app.main:app --reload
open http://127.0.0.1:8000
```

The app is database-agnostic via SQLAlchemy — it uses SQLite by default and PostgreSQL when `DATABASE_URL` points at a Postgres instance. The [live demo](https://soar-lite.onrender.com) runs on SQLite with `DEMO_MODE=true`, which seeds sample incidents on startup and makes the instance read-only.

To receive alerts by webhook, set a shared secret first (webhooks are refused without one):

```bash
export WEBHOOK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

---

## Features

**Alert Ingestion & Processing**
- REST API for alert creation, plus signed webhook endpoints for SIEM, EDR, and email-gateway formats
- Flexible JSON parsing that maps multiple vendor naming conventions to one internal schema
- Automatic incident creation and linking

**IOC Extraction & Enrichment**
- Regex-based extraction of IPs, domains, file hashes, and emails from alert text
- VirusTotal (malware/domain reputation), AbuseIPDB (IP abuse scoring), and IP geolocation
- Internal (RFC 1918) addresses are kept as IOCs but never sent to external APIs

**Automated Playbook System**
- YAML-defined playbooks with conditional logic (e.g. *if malicious → escalate*)
- Actions update severity, add tags, and write timeline entries
- Three sample playbooks included

**Case Management**
- Full CRUD on incidents with a validated status workflow (NEW → INVESTIGATING → CONTAINED → RESOLVED)
- Search and filtering by severity, status, IOC value, and date range
- Timeline/audit trail for every action

**Incident Reporting**
- One-click PDF and DOCX reports with executive summaries and technical detail

**Web Dashboard**
- Real-time metrics, severity/status distribution charts (Chart.js), incident list and detail views, dark SOC theme

---

## Architecture

SOAR-Lite follows a layered pipeline: **Ingestion → Processing → Storage → Analysis → Response.**

```
1. EDR sends webhook: "Malware detected: hash abc123 on LAPTOP-05"
   ↓
2. Alert created → Incident auto-created (status: NEW)
   ↓
3. IOC Extractor finds the file hash
   ↓
4. Enrichment: VirusTotal reports 67/69 engines detect malware
   ↓
5. Playbook evaluates: IF malicious_count >= 2 THEN escalate to CRITICAL
   ↓
6. Automated actions: severity updated, tag added, timeline entry written
   ↓
7. Analyst works the incident: NEW → INVESTIGATING → CONTAINED → RESOLVED
   ↓
8. PDF report generated with the full timeline
```

| Layer | Technology | Purpose |
|-------|-----------|---------|
| API | FastAPI | Async REST framework |
| Database | PostgreSQL / SQLite | Relational storage (via SQLAlchemy) |
| Migrations | Alembic | Schema version control |
| Enrichment | aiohttp | Async HTTP client for external APIs |
| Playbooks | PyYAML | YAML rule parsing |
| Reports | ReportLab, python-docx | PDF/DOCX generation |
| Frontend | Vanilla JS, Tailwind (prebuilt), Chart.js (bundled) | Dashboard UI |
| Testing | pytest | 88 tests, including security tests |
| CI/CD | GitHub Actions | Automated test pipeline |
| Containers | Docker, Docker Compose | Deployment |

**Design principles:** modular components (IOC extraction, enrichment, playbooks are independent), async-first enrichment for concurrent API calls, database-agnostic via SQLAlchemy, stateless API endpoints, and event-driven incident creation from webhooks.

---

## Sending alerts

Alerts arrive on four webhook endpoints: `/api/webhooks/siem`, `/edr`,
`/email` and `/generic`. Every request must be signed with the shared
`WEBHOOK_SECRET`, so nobody else can create incidents:

```
X-Webhook-Timestamp: <unix time in seconds>
X-Webhook-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>." followed by the raw body>
```

The timestamp is part of what's signed, and requests more than five minutes
old are refused, so a captured request can't be replayed. Unsigned or
tampered requests get `401`. In Python:

```python
import hashlib, hmac, json, time, requests

body = json.dumps({"search_name": "Port scan", "severity": "high",
                   "description": "Scan from 203.0.113.7"}).encode()
ts = int(time.time())
sig = hmac.new(SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
requests.post("http://localhost:8000/api/webhooks/siem", data=body, headers={
    "Content-Type": "application/json",
    "X-Webhook-Timestamp": str(ts),
    "X-Webhook-Signature": f"sha256={sig}",
})
```

`python tests/webhook_tester.py` sends one signed example to each endpoint.

---

## Testing

```bash
pytest -v                              # run all tests
pytest --cov=app --cov-report=html     # with coverage
ruff check app/ tests/                 # lint
```

88 tests, including integration tests covering the full ingestion-to-report
workflow and [security tests](tests/test_security.py) that fail if any of the
controls below is removed. Lint and tests run in CI on every push.

---

## Security

Everything SOAR-Lite displays (alert titles, descriptions, IOCs) is written by
whoever sent the alert, and for a security tool that is often the attacker: a
phishing email's subject line or a scanner's User-Agent ends up in an
incident. So alert data is treated as hostile.

| Threat | Defence |
|---|---|
| **Forged alerts.** Anyone who can reach the server creates incidents, or floods the queue to hide a real one | Every webhook must carry an HMAC-SHA256 signature over a timestamp and the body. Wrong secret, edited body or a request older than five minutes: `401`. No secret configured: webhooks are off. |
| **Script in alert text** (stored XSS). An alert titled `<img src=x onerror=...>` runs in the analyst's browser | Every value is HTML-escaped before it's displayed. A strict Content-Security-Policy (`script-src 'self'`, no inline scripts or handlers) blocks injected code even if escaping were missed. |
| **Markup in PDF reports.** ReportLab interprets tags in text, so alert text could break report generation or plant a clickable link | Alert text is escaped before it goes into the PDF. |
| **Third-party code.** A compromised CDN serves script to every analyst | Chart.js and the Tailwind stylesheet are bundled in `static/vendor/`; the dashboard loads nothing from other sites. |
| **Other websites reading incidents** | No CORS headers, so browsers keep other sites from reading the API. |
| **Visitors changing the public demo** | `DEMO_MODE` refuses every `POST`, `PATCH`, `PUT` and `DELETE`, which also protects the enrichment API quotas. |

Also: SQL queries go through the SQLAlchemy ORM (parameterised), input is
validated with Pydantic, secrets come from environment variables, incident
status changes follow an enforced state machine, internal (RFC 1918) addresses
are never sent to enrichment APIs, and the API docs are off unless
`DEBUG=true`.

The [2.0.0 changelog](CHANGELOG.md) lists the vulnerabilities that were
found and fixed.

### Limitations

SOAR-Lite has **no login**. Anyone who can reach it can read and change every
incident, so run it on your own machine or a private network (Docker Compose
publishes it on `127.0.0.1` only), or publicly only with `DEMO_MODE=true`.

---

## API Documentation

When running with `DEBUG=true`, interactive docs are available at `/docs` (Swagger) and `/redoc`.

Key endpoint groups: `/api/alerts`, `/api/incidents` (list, detail, update, `/statistics`), `/api/iocs`, `/api/enrichment`, `/api/playbooks` (list, execute, timeline), `/api/reports` (PDF/DOCX), and `/api/webhooks` (siem, edr, email, generic).

---

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full guide (Docker, Render, database migration, security hardening). The live demo runs on Render's free tier using a Docker deploy with SQLite and `DEMO_MODE=true`.

### Rebuilding the stylesheet

The dashboard uses a prebuilt Tailwind stylesheet (`static/vendor/tailwind.css`)
instead of Tailwind's CDN script. After adding Tailwind classes to the HTML or
JavaScript, rebuild it:

```bash
npx tailwindcss@3.4.17 -c tailwind.config.js -i static/tailwind.input.css -o static/vendor/tailwind.css --minify
```

---

## Skills Demonstrated

| Skill | Where in this project |
|---|---|
| Async REST API design | FastAPI app with async enrichment |
| SOC workflow orchestration | Ingest → extract → enrich → playbook → report pipeline |
| External API integration | VirusTotal, AbuseIPDB, geolocation (with graceful degradation) |
| IOC extraction | Regex parsing of IPs, domains, hashes, emails |
| Rule-based automation | YAML playbook engine with conditional escalation |
| Relational data modeling | Incidents → Alerts → IOCs → Actions, with Alembic migrations |
| State-machine validation | Enforced incident status transitions |
| Secure webhook design | HMAC-signed requests with replay protection |
| Handling hostile data | Escaping, Content-Security-Policy, safe PDF generation |
| Document generation | PDF/DOCX reports |
| Testing & CI/CD | 88 tests, lint and tests in GitHub Actions, pre-commit hooks |
| Containerization & deployment | Docker, Docker Compose, live on Render |

---

## Future Enhancements

Slack/Teams analyst notifications · login and role-based access · rate-limiting middleware · MITRE ATT&CK technique mapping · ticketing-system integration (Jira, ServiceNow).

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**Ahmed Dahdouh** — Software Engineering Student · Cybersecurity Enthusiast

[![GitHub](https://img.shields.io/badge/GitHub-AhmedDAH1-black?style=flat-square&logo=github)](https://github.com/AhmedDAH1)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ahmed_Dahdouh-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/ahmed-dahdouh)

---

## Related Projects

- [email-threat-analyzer](https://github.com/AhmedDAH1/email-threat-analyzer) — phishing detection engine with a live web demo, validated on the Nazario corpus
- [log_threat_detector](https://github.com/AhmedDAH1/log_threat_detector) — SIEM-style log analysis with correlation and AbuseIPDB enrichment
- [network-scanner](https://github.com/AhmedDAH1/network-scanner) — Scapy-based network reconnaissance with CVE lookup
- [attack-surface-mapper](https://github.com/AhmedDAH1/attack-surface-mapper) — attack-surface discovery with MITRE ATT&CK mapping and compliance checks
