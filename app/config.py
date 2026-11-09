from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.
    For local development, create a .env file in the project root.
    """

    # Application
    APP_NAME: str = "SOAR-Lite"
    APP_VERSION: str = "3.1.0"
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

    # Log and email analysis ("Analyze logs" page): the HTTP APIs of
    # Log Threat Detector (analysis_api.py) and Email Threat Analyzer (web_app.py).
    LOG_ANALYZER_URL: str = "http://localhost:5001"
    EMAIL_ANALYZER_URL: str = "http://localhost:5002"

    # AI triage (https://github.com/AhmedDAH1/ai-alert-triage). Off until a model
    # is set: TRIAGE_PROVIDER picks a preset (deepseek, kimi, ollama), or set
    # TRIAGE_BASE_URL and TRIAGE_MODEL for any OpenAI-compatible API.
    TRIAGE_PROVIDER: str = ""
    TRIAGE_BASE_URL: str = ""
    TRIAGE_MODEL: str = ""
    TRIAGE_API_KEY: str = ""
    TRIAGE_TIMEOUT: int = 0            # seconds; 0 = 60 for cloud APIs, 600 for a local model
    TRIAGE_MODE: str = "strict"        # naive | hardened | guarded | strict
    AUTO_TRIAGE: bool = True           # triage every new incident as it arrives
    # The SOC's own records (asset inventory, change tickets, known senders)
    # that the AI may cite to dismiss an alert. Attackers can't write to it.
    SOC_CONTEXT_FILE: str = "soc_context.yml"

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
