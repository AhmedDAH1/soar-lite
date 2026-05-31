# SOAR-Lite

> **🚀 [Live Demo →](https://soar-lite.onrender.com)** &nbsp;·&nbsp; A populated SOC dashboard with sample incidents you can explore.
> *Hosted on Render free tier — first load may take ~30 seconds while the container wakes.*

[![Live Demo](https://img.shields.io/badge/Live_Demo-Online-success?style=flat-square)](https://soar-lite.onrender.com)
![CI](https://github.com/AhmedDAH1/soar-lite/actions/workflows/ci.yml/badge.svg)
[![Tests](https://img.shields.io/badge/tests-53%20passing-brightgreen?style=flat-square)](https://github.com/AhmedDAH1/soar-lite/actions)
[![Coverage](https://img.shields.io/badge/coverage-84%25-brightgreen?style=flat-square)](https://github.com/AhmedDAH1/soar-lite)
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

The app is database-agnostic via SQLAlchemy — it uses SQLite by default and PostgreSQL when `DATABASE_URL` points at a Postgres instance. The [live demo](https://soar-lite.onrender.com) runs on SQLite with `SEED_DEMO=1` to populate sample incidents on startup.

---

## Features

**Alert Ingestion & Processing**
- REST API for alert creation, plus webhook endpoints for SIEM, EDR, and email-gateway formats
- Flexible JSON parsing that maps multiple vendor naming conventions to one internal schema
- Automatic incident creation and linking

**IOC Extraction & Enrichment**
- Regex-based extraction of IPs, domains, file hashes, and emails from alert text
- VirusTotal (malware/domain reputation), AbuseIPDB (IP abuse scoring), and IP geolocation
- RFC 1918 private-IP filtering so internal addresses aren't sent to external APIs

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
| Frontend | Vanilla JS, Tailwind, Chart.js | Dashboard UI |
| Testing | pytest | 53 tests, 84% coverage |
| CI/CD | GitHub Actions | Automated test pipeline |
| Containers | Docker, Docker Compose | Deployment |

**Design principles:** modular components (IOC extraction, enrichment, playbooks are independent), async-first enrichment for concurrent API calls, database-agnostic via SQLAlchemy, stateless API endpoints, and event-driven incident creation from webhooks.

---

## Testing

```bash
pytest -v                              # run all tests
pytest --cov=app --cov-report=html     # with coverage
ruff check app/ tests/                 # lint
```

53 tests passing · 84% coverage · integration tests covering the full ingestion-to-report workflow · enforced in CI on every push.

---

## Security Features

- HMAC-SHA256 webhook signature validation
- SQL-injection prevention via ORM parameterization
- XSS-protection and other security response headers
- Pydantic input validation
- Secrets via environment variables (never hardcoded)
- State-machine enforcement on incident status transitions
- RFC 1918 private-IP filtering before external enrichment

---

## API Documentation

When running with `DEBUG=true`, interactive docs are available at `/docs` (Swagger) and `/redoc`.

Key endpoint groups: `/api/alerts`, `/api/incidents` (list, detail, update, `/statistics`), `/api/iocs`, `/api/enrichment`, `/api/playbooks` (list, execute, timeline), `/api/reports` (PDF/DOCX), and `/api/webhooks` (siem, edr, email, generic).

---

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full guide (Docker, Render, database migration, security hardening). The live demo runs on Render's free tier using a Docker deploy with SQLite.

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
| Document generation | PDF/DOCX reports |
| Testing & CI/CD | 53 tests, 84% coverage, GitHub Actions, pre-commit hooks |
| Containerization & deployment | Docker, Docker Compose, live on Render |

---

## Future Enhancements

Slack/Teams analyst notifications · JWT auth and role-based access · rate-limiting middleware · MITRE ATT&CK technique mapping · ticketing-system integration (Jira, ServiceNow).

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
