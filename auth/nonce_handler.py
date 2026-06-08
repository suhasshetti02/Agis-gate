"""
Nonce/challenge-response management for Aegis-Gate.
"""

import secrets
from datetime import datetime, timedelta
from db.database import get_db
from config import Config


def generate_nonce(user_id: int = None, device_fingerprint: str = None, purpose: str = "auth") -> str:
    """Create a nonce, store it, and return its value."""
    nonce = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(seconds=Config.NONCE_EXPIRY_SECONDS)

    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO nonces (nonce, user_id, device_fingerprint, purpose, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (nonce, user_id, device_fingerprint, purpose, expires_at.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    return nonce


def validate_nonce(nonce: str, purpose: str = "auth") -> bool:
    """
    Validate a nonce:
    - Must exist, match purpose, not be expired, and not already used.
    - Marks it used on success.
    """
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, expires_at, used FROM nonces WHERE nonce = ? AND purpose = ?",
            (nonce, purpose),
        ).fetchone()

        if not row:
            return False

        if row["used"]:
            return False

        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.utcnow() > expires_at:
            return False

        # Mark used
        conn.execute("UPDATE nonces SET used=1 WHERE id=?", (row["id"],))
        conn.commit()
    finally:
        conn.close()

    return True


def build_challenge(nonce: str, device_fingerprint: str, timestamp: str) -> str:
    """Build the challenge string that the client must sign."""
    return f"{nonce}|{device_fingerprint}|{timestamp}"


def cleanup_expired_nonces():
    """Remove expired nonces from the database."""
    conn = get_db()
    try:
        conn.execute("DELETE FROM nonces WHERE expires_at < datetime('now')")
        conn.commit()
    finally:
        conn.close()
