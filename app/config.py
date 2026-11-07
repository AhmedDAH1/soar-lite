from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.
    For local development, create a .env file in the project root.
    """

    # Application
    APP_NAME: str = "SOAR-Lite"
    APP_VERSION: str = "2.0.0"
    # Enables /docs and /redoc. Off unless set, so a deployment never exposes them by accident.
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./soar_lite.db"

    # API keys for IOC enrichment (optional; enrichment skips a service without one)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # Webhooks: senders sign each request with this shared secret (see the
    # README, "Sending alerts"). Webhooks are refused until it is set.
    WEBHOOK_SECRET: str = ""
    # How old (in seconds) a signed request may be, to stop replayed requests.
    WEBHOOK_MAX_AGE: int = 300

    # Public demo: seed sample incidents on startup and refuse every change,
    # so visitors can look but not write. SEED_DEMO=1 is the older name.
    DEMO_MODE: bool = False
    SEED_DEMO: bool = False

    @property
    def demo_mode(self) -> bool:
        return self.DEMO_MODE or self.SEED_DEMO

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings instance.
    Using lru_cache ensures we only read .env once.
    """
    return Settings()
