from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.
    For local development, create a .env file in the project root.
    """
    
    # Application
    APP_NAME: str = "SOAR-Lite"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = "sqlite:///./soar_lite.db"
    
    # API Keys (we'll add these in Milestone 3)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Cached settings instance.
    Using lru_cache ensures we only read .env once.
    """
    return Settings()