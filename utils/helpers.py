"""
Shared utility helpers for Aegis-Gate.
"""

import hashlib
import secrets
from datetime import datetime
from flask import request


def get_client_ip() -> str:
    """Extract real IP, respecting proxy headers."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def get_user_agent() -> str:
    return request.headers.get("User-Agent", "unknown")


def hash_string(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def utcnow_iso() -> str:
    return datetime.utcnow().isoformat()


def sanitize_input(value: str, max_len: int = 255) -> str:
    if not value:
        return ""
    return str(value).strip()[:max_len]
