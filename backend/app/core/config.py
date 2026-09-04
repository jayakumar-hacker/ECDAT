"""
ECDAT configuration.

All values can be overridden with environment variables (see .env.example).
Nothing here requires paid/external services - the app is offline-first.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "ECDAT - Enterprise Cryptographic Discovery & Analysis Tool"
    APP_VERSION: str = "0.1.0-mvp"
    ENV: str = "development"

    # Database - SQLite by default, zero configuration.
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/ecdat.db"

    # Auth
    SECRET_KEY: str = "ecdat-dev-secret-change-in-production-8f2a9c1e"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    ALGORITHM: str = "HS256"

    # Scanning limits (defensive / performance)
    MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB per file
    MAX_FILES_PER_SCAN: int = 20000
    SCAN_EXCLUDED_DIRS: tuple = (
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", ".mypy_cache", ".pytest_cache", "target",
    )
    SCAN_EXCLUDED_FILES: tuple = (
        "ecdat-policy.yaml", "ecdat-policy.yml", ".ecdat-policy.yaml", ".ecdat-policy.yml",
    )

    # Risk scoring thresholds (documented as ECDAT model, not an official standard)
    RISK_LOW_MAX: int = 24
    RISK_MEDIUM_MAX: int = 49
    RISK_HIGH_MAX: int = 74
    # 75-100 = CRITICAL

    # Mosca default threat horizon (years) - configurable per assessment, this is only the default
    DEFAULT_THREAT_HORIZON_YEARS: int = 10

    # Tier 2 - Harvest-now-decrypt-later (HNDL) lens. An asset is flagged as
    # HNDL-exposed when its data has a shelf-life (data_retention_years) at or
    # above this threshold. Configurable, not a prediction.
    HNDL_SHELF_LIFE_THRESHOLD_YEARS: int = 10

    # AI Assistant - optional, offline by default
    AI_ENABLED: bool = False
    AI_PROVIDER: str = "none"  # "none" | "ollama" | "openai_compatible"
    AI_API_BASE: str = ""
    AI_API_KEY: str = ""
    AI_MODEL: str = ""
    # Never send scanned source code externally unless explicitly true
    AI_ALLOW_EXTERNAL_CONTEXT: bool = False

    # CORS
    FRONTEND_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # Reports output directory
    REPORTS_DIR: str = os.path.join(BASE_DIR, "reports_output")


settings = Settings()
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
