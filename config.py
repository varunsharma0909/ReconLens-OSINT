"""
config.py - Central configuration.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
    ALLOW_LIVE_MODE = _bool("ALLOW_LIVE_MODE", True)

    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    ABUSE_CH_AUTH_KEY = os.getenv("ABUSE_CH_AUTH_KEY", "").strip()
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    AUTHORIZED_EMAIL_DOMAINS = _list("AUTHORIZED_EMAIL_DOMAINS")
    USER_AGENT = os.getenv("OSINT_USER_AGENT", "OSINT-Footprint-Dashboard/1.0 (academic project)")
    HTTP_TIMEOUT = _int("HTTP_TIMEOUT", 10)
    CRTSH_TIMEOUT = _int("CRTSH_TIMEOUT", 25)
    DNS_TIMEOUT = _int("DNS_TIMEOUT", 5)
    SCAN_RATE_LIMIT = os.getenv("SCAN_RATE_LIMIT", "10 per minute")
    DEFAULT_RATE_LIMIT = os.getenv("DEFAULT_RATE_LIMIT", "1000 per hour")
    RETENTION_DAYS = _int("RETENTION_DAYS", 30)
    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "database" / "osint.db"))
    LOG_DIR = BASE_DIR / "logs"
    MAX_CONTENT_LENGTH = 16 * 1024
    JSON_SORT_KEYS = False


def get_config() -> dict:
    return {k: getattr(Config, k) for k in dir(Config) if k.isupper()}
