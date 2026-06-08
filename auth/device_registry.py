"""
Device registry for Aegis-Gate.
Handles device registration, fingerprinting, trust scores, and limits.
"""

import hashlib
from db.database import get_db
from config import Config


def compute_device_fingerprint(user_agent: str, platform: str, extra: str = "") -> str:
    """Compute a SHA-256 fingerprint from device metadata."""
    raw = f"{user_agent}|{platform}|{extra}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get_user_device_count(user_id: int) -> int:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM devices WHERE user_id=? AND is_blocked=0",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()
    return row["cnt"] if row else 0


def get_user_device_limit(user_id: int) -> int:
    conn = get_db()
    try:
        user = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
    finally:
        conn.close()
    if user and user["is_admin"]:
        return getattr(Config, 'MAX_ADMIN_DEVICES', 10)
    return Config.MAX_DEVICES_PER_USER


def can_register_device(user_id: int) -> bool:
    return get_user_device_count(user_id) < get_user_device_limit(user_id)


def register_device(user_id: int, device_name: str, device_fingerprint: str, public_key: str) -> dict:
    """
    Register a new device for a user.
    Returns the device record or raises ValueError if limits/duplicates exist.
    """
    limit = get_user_device_limit(user_id)
    if get_user_device_count(user_id) >= limit:
        raise ValueError(f"Device limit reached ({limit} devices per user).")

    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id, is_blocked FROM devices WHERE device_fingerprint=?",
            (device_fingerprint,),
        ).fetchone()

        if existing:
            raise ValueError("Device already registered.")

        conn.execute(
            """
            INSERT INTO devices (user_id, device_name, device_fingerprint, public_key, is_trusted)
            VALUES (?, ?, ?, ?, 0)
            """,
            (user_id, device_name, device_fingerprint, public_key),
        )
        conn.commit()

        device = conn.execute(
            "SELECT * FROM devices WHERE device_fingerprint=?", (device_fingerprint,)
        ).fetchone()
    finally:
        conn.close()

    return dict(device)


def get_device_by_fingerprint(fingerprint: str):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_fingerprint=?", (fingerprint,)
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_devices_for_user(user_id: int):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM devices WHERE user_id=? ORDER BY registered_at DESC", (user_id,)
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def update_device_last_seen(device_id: int):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE devices SET last_seen=datetime('now'), login_count=login_count+1 WHERE id=?",
            (device_id,),
        )
        conn.commit()
    finally:
        conn.close()


def set_device_trusted(device_id: int, trusted: bool):
    conn = get_db()
    try:
        conn.execute("UPDATE devices SET is_trusted=? WHERE id=?", (1 if trusted else 0, device_id))
        conn.commit()
    finally:
        conn.close()


def update_device_trust_score(device_id: int, score: float):
    score = max(0.0, min(1.0, score))
    conn = get_db()
    try:
        conn.execute("UPDATE devices SET trust_score=? WHERE id=?", (score, device_id))
        conn.commit()
    finally:
        conn.close()


def block_device(device_id: int, block: bool = True):
    conn = get_db()
    try:
        if block:
            conn.execute("UPDATE devices SET is_blocked=1, is_trusted=0 WHERE id=?", (device_id,))
        else:
            conn.execute("UPDATE devices SET is_blocked=0 WHERE id=?", (device_id,))
        conn.commit()
    finally:
        conn.close()


def remove_device(device_id: int, user_id: int):
    conn = get_db()
    try:
        conn.execute("DELETE FROM devices WHERE id=? AND user_id=?", (device_id, user_id))
        conn.commit()
    finally:
        conn.close()
