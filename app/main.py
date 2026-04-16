from fastapi import FastAPI
from app.config import get_settings
from app.database import engine, Base
from app.routers import alerts 

settings = get_settings()

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Lightweight Security Orchestration, Automation & Response platform"
)

# Include routers
app.include_router(alerts.router) 

@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    # Create tables if they don't exist (migrations should handle this)
    Base.metadata.create_all(bind=engine)
    print(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} started")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {"status": "healthy"}