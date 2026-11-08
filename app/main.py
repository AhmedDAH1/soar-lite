from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import Base, engine
from app.routers import (
    alerts,
    analyze,
    enrichment,
    incidents,
    iocs,
    playbooks,
    reports,
    triage,
    webhooks,
)

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Lightweight Security Orchestration, Automation & Response platform",
    docs_url="/docs" if settings.DEBUG else None,  # Disable docs in production
    redoc_url="/redoc" if settings.DEBUG else None
)

# No CORS middleware: the dashboard is served from the same origin as the API,
# so other websites have no reason to read it.

# Alert titles, descriptions and IOCs are written by whoever sends the alert,
# so the dashboard treats them as hostile. The page escapes them; this policy
# is the second layer, refusing inline scripts and event handlers even if
# escaping were missed somewhere.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",  # Chart.js and the stylesheet are bundled: no third-party code
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")  # Swagger UI needs inline scripts
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def read_only_demo(request: Request, call_next):
    """In the public demo, visitors can look at everything but change nothing."""
    if get_settings().demo_mode and request.method in WRITE_METHODS:
        return JSONResponse(
            status_code=403,
            content={"detail": "This is a read-only demo. Run SOAR-Lite locally to try changes."},
        )
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    if not request.url.path.startswith(DOCS_PATHS):
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers
app.include_router(alerts.router)
app.include_router(iocs.router)
app.include_router(enrichment.router)
app.include_router(playbooks.router)
app.include_router(incidents.router)
app.include_router(reports.router)
app.include_router(webhooks.router)
app.include_router(analyze.router)
app.include_router(triage.router)


@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    Base.metadata.create_all(bind=engine)
    print(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} started")
    print(f"📊 Database: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else 'SQLite'}")

    # Seed demo data on the hosted demo (ephemeral DB starts empty each cold start).
    if settings.demo_mode:
        from app.seed import seed_demo_data
        seed_demo_data()


@app.get("/")
async def root():
    """Serve the dashboard homepage"""
    return FileResponse('static/index.html')


@app.get("/analyze")
async def analyze_page():
    """The Analyze logs page"""
    return FileResponse('static/analyze.html')


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "database": "connected",
        "demo_mode": get_settings().demo_mode,
    }
