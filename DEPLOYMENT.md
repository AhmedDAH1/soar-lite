# SOAR-Lite Deployment Guide

## Quick Start with Docker

### Prerequisites
- Docker and Docker Compose installed
- API keys (VirusTotal, AbuseIPDB) - optional but recommended

### 1. Clone Repository
```bash
git clone https://github.com/AhmedDAH1/soar-lite.git
cd soar-lite
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env and add your API keys
```

### 3. Start Application
```bash
docker-compose up -d
```

### 4. Access Dashboard
Open http://localhost:8000

### 5. Check Logs
```bash
docker-compose logs -f web
```

### 6. Stop Application
```bash
docker-compose down
```

---

## Production Deployment

### Render.com (Recommended - Free Tier Available)

1. **Create PostgreSQL Database**
   - Go to Render Dashboard → New → PostgreSQL
   - Choose free tier
   - Copy connection string

2. **Create Web Service**
   - Go to Render Dashboard → New → Web Service
   - Connect GitHub repository
   - Configure:
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Add environment variables:
     - `DATABASE_URL`: (paste PostgreSQL connection string)
     - `VIRUSTOTAL_API_KEY`: (your key)
     - `ABUSEIPDB_API_KEY`: (your key)
     - `DEBUG`: `false`

3. **Deploy**
   - Click "Create Web Service"
   - Wait 3-5 minutes for deployment
   - Access at: `https://your-app-name.onrender.com`

---

### Heroku

1. **Install Heroku CLI**
```bash
brew install heroku/brew/heroku  # macOS
```

2. **Login and Create App**
```bash
heroku login
heroku create soar-lite-prod
```

3. **Add PostgreSQL**
```bash
heroku addons:create heroku-postgresql:mini
```

4. **Set Environment Variables**
```bash
heroku config:set VIRUSTOTAL_API_KEY=your_key
heroku config:set ABUSEIPDB_API_KEY=your_key
heroku config:set DEBUG=false
```

5. **Create Procfile**
Create `Procfile` in project root:
```bash
echo "web: alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port \$PORT" > Procfile
```
6. **Deploy**
```bash
git push heroku main
```

7. **Access**
```bash
heroku open
```

---

### AWS EC2 (Advanced)

1. **Launch EC2 Instance**
   - Ubuntu 22.04 LTS
   - t2.micro (free tier)
   - Security group: Allow ports 22, 80, 443, 8000

2. **SSH into Instance**
```bash
ssh -i your-key.pem ubuntu@your-ec2-ip
```

3. **Install Docker**
```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo usermod -aG docker ubuntu
```

4. **Clone and Deploy**
```bash
git clone https://github.com/AhmedDAH1/soar-lite.git
cd soar-lite
cp .env.example .env
# Edit .env with your keys
docker-compose up -d
```

5. **Configure Nginx (Optional)**
```bash
sudo apt install nginx
# Configure reverse proxy from port 80 to 8000
```

---

## Database Migration (SQLite → PostgreSQL)

If you have existing data in SQLite:

```bash
# Export SQLite data
sqlite3 soar_lite.db .dump > backup.sql

# Start PostgreSQL container
docker-compose up -d db

# Import to PostgreSQL (requires conversion - use pgloader)
pgloader soar_lite.db postgresql://soar_user:password@localhost/soar_lite
```

---

## Monitoring

### Health Check Endpoint
```bash
curl http://localhost:8000/health
```

### View Logs
```bash
# Docker
docker-compose logs -f web

# Heroku
heroku logs --tail

# Render
View in dashboard
```

### Database Access
```bash
# Docker
docker exec -it soar-lite-db psql -U soar_user -d soar_lite

# Heroku
heroku pg:psql
```

---

## Backup and Restore

### Backup PostgreSQL
```bash
docker exec soar-lite-db pg_dump -U soar_user soar_lite > backup_$(date +%Y%m%d).sql
```

### Restore PostgreSQL
```bash
docker exec -i soar-lite-db psql -U soar_user soar_lite < backup_20260418.sql
```

---

## Troubleshooting

### Application won't start
```bash
# Check logs
docker-compose logs web

# Common issues:
# - Database not ready: Wait 30s and retry
# - Port conflict: Change port in docker-compose.yml
# - Migration error: Run `docker-compose exec web alembic upgrade head`
```

### Database connection errors
```bash
# Verify database is running
docker-compose ps

# Test connection
docker exec soar-lite-db pg_isready -U soar_user
```

### API keys not working
```bash
# Verify environment variables
docker-compose exec web env | grep API_KEY
```

---

## Security Checklist

- [ ] Change default PostgreSQL password
- [ ] Set DEBUG=false in production
- [ ] Configure CORS for your domain only
- [ ] Use HTTPS (Let's Encrypt + Nginx/Caddy)
- [ ] Rotate API keys regularly
- [ ] Enable firewall (UFW/Security Groups)
- [ ] Set up automated backups
- [ ] Monitor logs for suspicious activity
- [ ] Keep dependencies updated (`pip list --outdated`)

---

## Performance Optimization

### Enable PostgreSQL Connection Pooling
Edit `app/database.py`:
```python
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True
)
```

### Add Redis for Caching (Optional)
```yaml
# docker-compose.yml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
```

### Scale Horizontally
```bash
docker-compose up -d --scale web=3
```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/AhmedDAH1/soar-lite/issues
- Documentation: README.md
