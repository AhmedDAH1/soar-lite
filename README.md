# SOAR-Lite

> Lightweight Security Orchestration, Automation & Response platform demonstrating SOC workflow orchestration, threat intelligence enrichment, and automated playbook execution.

## 🎯 Project Status

**Current Milestone:** 0 - Foundation ✅  
**Next Up:** Alert Ingestion API

## 🏗️ Architecture

- **Backend:** FastAPI (Python 3.10+)
- **Database:** SQLite (→ PostgreSQL for production)
- **Task Processing:** asyncio
- **Testing:** pytest

## 🚀 Quick Start

```bash
# Clone and setup
git clone <your-repo>
cd soar-lite
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start server
uvicorn app.main:app --reload
```

Visit http://127.0.0.1:8000/docs for API documentation.

## 🧪 Testing

```bash
pytest -v
```

## 📋 Roadmap

- [x] M0: Foundation & project setup
- [ ] M1: Alert ingestion API
- [ ] M2: IOC extraction
- [ ] M3: Threat intelligence enrichment
- [ ] M4: Playbook system
- [ ] M5: Case management CRUD
- [ ] M6: Web dashboard
- [ ] M7: Report generation
- [ ] M8: Webhook ingestion
- [ ] M9: Testing & CI/CD
- [ ] M10: Production deployment

## 📚 Learning Goals

This project demonstrates:
- RESTful API design with FastAPI
- Async programming for external API integration
- Database modeling and migrations
- Automated incident response workflows
- SOC operational concepts

---

**Built as a portfolio project for SOC analyst positions.**