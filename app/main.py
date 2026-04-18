from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.config import get_settings
from app.database import engine, Base
from app.routers import alerts, iocs, enrichment, playbooks, incidents, reports  # Add reports

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Lightweight Security Orchestration, Automation & Response platform"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers
app.include_router(alerts.router)
app.include_router(iocs.router)
app.include_router(enrichment.router)
app.include_router(playbooks.router)
app.include_router(incidents.router)
app.include_router(reports.router)  # Add this line


@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    Base.metadata.create_all(bind=engine)
    print(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} started")


@app.get("/")
async def root():
    """Serve the dashboard homepage"""
    return FileResponse('static/index.html')


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {"status": "healthy"}