"""
Aegis-Gate configuration.
All secrets are read from environment variables or a local .env file.
Run:  copy .env.example .env  then fill in values before starting.
"""

import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (same folder as this file)
load_dotenv(Path(__file__).resolve().parent / ".env")

BASE_DIR = Path(__file__).resolve().parent


def _require_env(name: str, default: str = None) -> str:
    """Return env var value; fall back to default or raise."""
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(
            f"Required environment variable '{name}' is not set. "
            f"Copy .env.example to .env and configure it."
        )
    return value


def _get_secret_key() -> str:
    """
    Enforce SECRET_KEY via environment variable.
    """
    return _require_env("SECRET_KEY")


class Config:
    # ── Core secrets ─────────────────────────────────────────────
    SECRET_KEY: str = _get_secret_key()

    # Admin password must be provided via environment variable for security.
    ADMIN_PASSWORD: str = _require_env("ADMIN_PASSWORD")

    # ── Email settings ───────────────────────────────────────────
    EMAIL_HOST: str = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
    EMAIL_PORT: int = int(os.environ.get("EMAIL_PORT", 587))
    EMAIL_USERNAME: str = os.environ.get("EMAIL_USERNAME", "")
    EMAIL_PASSWORD: str = os.environ.get("EMAIL_PASSWORD", "")
    EMAIL_FROM: str = os.environ.get("EMAIL_FROM", EMAIL_USERNAME)

    # ── Paths ────────────────────────────────────────────────────
    DATABASE_PATH = BASE_DIR / "db" / "aegis.db"
    KEYS_DIR      = BASE_DIR / "keys"
    LOGS_DIR      = BASE_DIR / "logs"

    # ── Session settings ─────────────────────────────────────────
    SESSION_COOKIE_HTTPONLY     = True
    SESSION_COOKIE_SAMESITE     = "Lax"
    PERMANENT_SESSION_LIFETIME  = 3600   # seconds (1 hour for non-trusted sessions)

    # ── Device limits ─────────────────────────────────────────────
    MAX_DEVICES_PER_USER = 2
    MAX_ADMIN_DEVICES = 10

    # ── Auth settings ─────────────────────────────────────────────
    MAX_FAILED_ATTEMPTS         = 5
    LOCKOUT_DURATION_MINUTES    = 15
    NONCE_EXPIRY_SECONDS        = 300
    OTP_VALIDITY_SECONDS        = 300

    # ── Trusted session renewal ───────────────────────────────────
    TRUSTED_SESSION_DAYS = 7

    # ── AI risk thresholds ────────────────────────────────────────
    RISK_THRESHOLD_BLOCK      = 0.75
    RISK_THRESHOLD_CHALLENGE  = 0.45

    # ── RSA key size ─────────────────────────────────────────────
    RSA_KEY_SIZE = 2048

    # ── Runtime flags ─────────────────────────────────────────────
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
