# SOAR-Lite

![CI](https://github.com/AhmedDAH1/soar-lite/actions/workflows/ci.yml/badge.svg)
[![Tests](https://img.shields.io/badge/tests-53%20passing-brightgreen)](https://github.com/AhmedDAH1/soar-lite/actions)
[![Coverage](https://img.shields.io/badge/coverage-84%25-brightgreen)](https://github.com/AhmedDAH1/soar-lite)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> Lightweight Security Orchestration, Automation & Response platform demonstrating SOC workflow orchestration, threat intelligence enrichment, and automated playbook execution.

## 🎯 Project Overview

SOAR-Lite is a portfolio cybersecurity project demonstrating:
- **Alert Ingestion** from multiple sources (webhooks, email, SIEM)
- **IOC Extraction** using regex (IPs, domains, hashes, emails)
- **Threat Intelligence Enrichment** (VirusTotal, AbuseIPDB, geolocation)
- **Automated Playbooks** (YAML-based response automation)
- **Case Management** with workflow validation
- **Incident Reporting** (PDF/DOCX generation)
- **Web Dashboard** with real-time metrics

Built to showcase skills needed for **SOC Analyst** and **Security Engineer** positions.

---
## 🎬 Live Demo Video

[![SOAR-Lite Demo](https://img.shields.io/badge/▶️_Watch_Demo-YouTube-red?style=for-the-badge)](https://youtu.be/Wade9SSN-Ts)

**6-minute complete walkthrough** showing the full incident response workflow from alert ingestion to final report.

**What you'll see:**
- Real-time webhook alert from simulated EDR
- Automatic IOC extraction and enrichment
- VirusTotal integration detecting actual malware (67/69 engines)
- Automated playbook escalating severity
- Professional PDF report generation

[**→ Watch the Demo**](https://youtu.be/Wade9SSN-Ts)

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/AhmedDAH1/soar-lite.git
cd soar-lite

# Start application (includes PostgreSQL)
docker-compose up -d

# Access dashboard
open http://localhost:8000
```

### Option 2: Local Development

```bash
# Clone and setup
git clone https://github.com/AhmedDAH1/soar-lite.git
cd soar-lite
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start server
uvicorn app.main:app --reload

# Access dashboard
open http://127.0.0.1:8000
```

---

## 📋 Features

### ✅ Alert Ingestion & Processing
- REST API for alert creation
- Webhook endpoints (SIEM, EDR, email gateway)
- Flexible JSON parsing for multiple vendor formats
- Automatic incident creation and linking

### ✅ IOC Extraction & Enrichment
- Regex-based extraction (IPs, domains, hashes, emails)
- VirusTotal API integration (malware/domain reputation)
- AbuseIPDB integration (IP abuse scoring)
- IP geolocation (country, city, ISP)
- Private IP filtering (RFC 1918 compliance)

### ✅ Automated Playbook System
- YAML-based playbook definitions
- Condition evaluation (if malicious → escalate)
- Actions: update severity, add tags, create timeline entries
- 3 sample playbooks included

### ✅ Case Management
- Full CRUD operations on incidents
- Status workflow validation (NEW → INVESTIGATING → CONTAINED → RESOLVED)
- Search and filtering (severity, status, IOC value, date range)
- Timeline/audit trail for all actions

### ✅ Incident Reporting
- PDF report generation (professional formatting)
- DOCX report generation (editable documents)
- Executive summaries and technical details
- One-click download from dashboard

### ✅ Web Dashboard
- Real-time metrics (total incidents, unresolved, critical)
- Severity and status distribution charts (Chart.js)
- Incident list with filtering
- Incident detail view with full context
- Dark theme SOC aesthetic

---

## 🛠️ Technology Stack

**Backend:**
- FastAPI (async Python web framework)
- SQLAlchemy (ORM)
- PostgreSQL (production) / SQLite (development)
- Alembic (database migrations)

**Threat Intelligence:**
- VirusTotal API
- AbuseIPDB API
- ipapi.co (geolocation)

**Frontend:**
- Vanilla JavaScript (no framework dependencies)
- Tailwind CSS (utility-first styling)
- Chart.js (data visualization)

**Testing & CI/CD:**
- pytest (53 tests, 84% coverage)
- GitHub Actions (automated testing)
- Ruff (Python linting)
- pre-commit hooks

**Deployment:**
- Docker & Docker Compose
- Production-ready configuration
- See [DEPLOYMENT.md](DEPLOYMENT.md) for full guide

---

## 📊 Architecture

### System Overview

SOAR-Lite follows a layered architecture with clear separation of concerns:

**Alert Ingestion → Processing → Storage → Analysis → Response**

### Component Breakdown

**1. Alert Ingestion Layer**
- **Webhooks**: Accept alerts from SIEM (Splunk), EDR (CrowdStrike), Firewalls
- **Email Gateway**: Process phishing reports and malicious attachments
- **Manual API**: REST endpoints for custom alert creation

**2. Processing Pipeline**
- **IOC Extraction**: Regex-based parsing extracts IPs, domains, file hashes, emails, URLs
- **Enrichment Engine**: Async calls to VirusTotal, AbuseIPDB, IP geolocation APIs
- **Playbook Execution**: YAML-based automated response workflows

**3. Data Layer**
- **Database**: PostgreSQL (production) or SQLite (development)
- **Models**: Incidents, Alerts, IOCs, Actions (timeline/audit trail)
- **Relationships**: One-to-many hierarchy (Incident → Alerts → IOCs)

**4. Business Logic**
- **Case Management**: Full CRUD operations with state machine validation
- **Playbook Engine**: Conditional logic evaluation + automated actions
- **Report Generator**: PDF/DOCX creation with executive summaries

**5. Presentation Layer**
- **Web Dashboard**: Real-time metrics, charts, incident management interface
- **API Documentation**: Auto-generated Swagger/ReDoc (FastAPI)
- **Reports**: One-click PDF/DOCX incident reports

### Data Flow Example

```
1. EDR sends webhook: "Malware detected: hash abc123 on LAPTOP-05"
   ↓
2. Alert created → Incident auto-created (status: NEW)
   ↓
3. IOC Extractor finds hash "abc123"
   ↓
4. Enrichment: VirusTotal reports 67/69 engines detect malware
   ↓
5. Playbook evaluates: "IF malicious_count >= 2 THEN escalate to CRITICAL"
   ↓
6. Automated actions: Severity updated, tag added, timeline entry created
   ↓
7. Dashboard: Analyst sees critical incident and investigates
   ↓
8. Analyst workflow: NEW → INVESTIGATING → CONTAINED → RESOLVED
   ↓
9. Report generated: PDF with full timeline sent to management
```

### Technology Stack by Layer

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **API** | FastAPI | Async REST API framework |
| **Database** | PostgreSQL / SQLite | Relational data storage |
| **ORM** | SQLAlchemy | Database abstraction layer |
| **Migrations** | Alembic | Schema version control |
| **Enrichment** | aiohttp | Async HTTP client for external APIs |
| **Playbooks** | PyYAML | YAML configuration parsing |
| **Reports** | ReportLab, python-docx | PDF/DOCX document generation |
| **Frontend** | Vanilla JavaScript | Lightweight UI (no framework) |
| **Styling** | Tailwind CSS | Utility-first CSS framework |
| **Charts** | Chart.js | Data visualization |
| **Testing** | pytest | Unit and integration tests |
| **CI/CD** | GitHub Actions | Automated testing pipeline |
| **Containers** | Docker, Docker Compose | Application deployment |
| **Web Server** | Nginx (optional) | Production reverse proxy |

### Architecture Principles

**Modularity**: Each component (IOC extraction, enrichment, playbooks) is independent and can be modified without affecting others.

**Async-First**: Uses Python's async/await for concurrent API calls, improving enrichment performance by 3x.

**Database-Agnostic**: Works with SQLite (dev) and PostgreSQL (prod) via SQLAlchemy abstraction.

**Stateless API**: FastAPI endpoints are stateless, enabling horizontal scaling.

**Event-Driven**: Webhooks trigger automatic incident creation and playbook execution.

**Extensible**: Easy to add new IOC types, enrichment sources, or playbook actions.

---

## 🧪 Testing

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=app --cov-report=html

# Run linting
ruff check app/ tests/

# View coverage report
open htmlcov/index.html
```

**Test Coverage:**
- 53 tests passing
- 84.85% code coverage
- Integration tests for full workflow
- Edge case testing
- CI/CD automated testing

---

## 📦 Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for full deployment guide including:
- Docker deployment
- Render.com (free tier)
- Heroku
- AWS EC2
- Database migration
- Security hardening

**Quick deploy to Render:**
1. Fork this repository
2. Create account on Render.com
3. Create PostgreSQL database
4. Create Web Service from GitHub
5. Set environment variables
6. Deploy!

---

## 🔐 Security Features

- HMAC-SHA256 webhook signature validation
- SQL injection prevention (ORM parameterization)
- XSS protection headers
- CORS configuration
- Input validation (Pydantic)
- Secret management (environment variables)
- State machine workflow enforcement
- Private IP filtering

---

## 📚 Learning Outcomes

This project demonstrates:
- ✅ RESTful API design (FastAPI)
- ✅ Async programming (aiohttp, asyncio)
- ✅ Database design (relational modeling, migrations)
- ✅ External API integration (VirusTotal, AbuseIPDB)
- ✅ Regex pattern matching (IOC extraction)
- ✅ YAML configuration (playbooks)
- ✅ Frontend development (vanilla JS, Tailwind)
- ✅ Testing (pytest, 84% coverage)
- ✅ CI/CD (GitHub Actions)
- ✅ Docker containerization
- ✅ Production deployment

---

## 📖 API Documentation

When running in development mode (`DEBUG=true`):
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

**Alerts:**
- `POST /api/alerts/` - Create alert
- `GET /api/alerts/{id}` - Get alert details

**Incidents:**
- `GET /api/incidents/` - List incidents (with filtering)
- `GET /api/incidents/{id}` - Get incident details
- `PATCH /api/incidents/{id}` - Update incident
- `GET /api/incidents/statistics` - Get dashboard metrics

**IOCs:**
- `GET /api/iocs/incident/{id}` - Get IOCs for incident

**Enrichment:**
- `POST /api/enrichment/incident/{id}` - Enrich IOCs

**Playbooks:**
- `GET /api/playbooks/` - List playbooks
- `POST /api/playbooks/execute/{id}` - Execute playbooks
- `GET /api/playbooks/timeline/{id}` - Get timeline

**Reports:**
- `GET /api/reports/incident/{id}/pdf` - Generate PDF
- `GET /api/reports/incident/{id}/docx` - Generate DOCX

**Webhooks:**
- `POST /api/webhooks/siem` - SIEM webhook
- `POST /api/webhooks/edr` - EDR webhook
- `POST /api/webhooks/email` - Email webhook
- `POST /api/webhooks/generic` - Generic webhook

---

## 🤝 Contributing

This is a portfolio project, but feedback is welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Run tests (`pytest -v`)
5. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
6. Push to the branch (`git push origin feature/AmazingFeature`)
7. Open a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

---

## 👤 Author

**Ahmed Dahdouh**
- GitHub: [@AhmedDAH1](https://github.com/AhmedDAH1)
- LinkedIn: [Ahmed Dahdouh](https://www.linkedin.com/in/ahmed-dahdouh)

---

## 🙏 Acknowledgments

- Inspired by enterprise SOAR platforms (Splunk SOAR, Palo Alto Cortex XSOAR)
- Built as a demonstration project for SOC analyst and security engineer positions
- Uses real threat intelligence APIs (VirusTotal, AbuseIPDB)
- Special thanks to the open-source community for FastAPI, SQLAlchemy, and pytest

---

## 📈 Project Stats

- **Lines of Code**: ~5,000+
- **Files**: 50+
- **Commits**: 100+
- **Tests**: 53 passing
- **Coverage**: 84.85%
- **API Endpoints**: 20+
- **Database Tables**: 4
- **Milestones Completed**: 10/10

---

## 🔮 Future Enhancements

Potential features for future development:
- Email notifications (SMTP integration)
- Slack/Teams webhooks for analyst alerts
- Rate limiting middleware
- JWT authentication
- Role-based access control (admin vs analyst)
- Metrics dashboard (Prometheus + Grafana)
- Machine learning anomaly detection
- Threat hunting queries
- MITRE ATT&CK framework mapping
- Integration with ticketing systems (Jira, ServiceNow)

---

## 📞 Support

For issues or questions:
- **GitHub Issues**: [Create an issue](https://github.com/AhmedDAH1/soar-lite/issues)
- **Documentation**: This README and [DEPLOYMENT.md](DEPLOYMENT.md)
- **Email**: pach.trojan@gmail.com

---

**⭐ If this project helped you learn or you found it useful, please star it!**

---

## 📸 Screenshots

*Coming soon: Dashboard, incident detail view, reports*

---

## 🎓 Educational Use

This project is ideal for:
- Cybersecurity students learning SOC operations
- Developers learning async Python and FastAPI
- Security engineers building portfolio projects
- Anyone interested in security automation

Feel free to use this as a learning resource or starting point for your own SOAR platform!

---

**Built with ❤️ by Ahmed Dahdouh | April 2026**
