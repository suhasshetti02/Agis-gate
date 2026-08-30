"""
Session management for Aegis-Gate.
Handles session creation, validation, and trusted-device renewal.
"""

import secrets
from datetime import datetime, timedelta
from db.database import get_db
from config import Config
from network.network_controller import SimulatedNetworkController, NetworkAllocationError
import logging

logger = logging.getLogger(__name__)


def create_session(user_id: int, device_id: int, ip_address: str, user_agent: str,
                   trusted: bool = False) -> str:
    """Create a new DB session and return the session token."""
    token = secrets.token_urlsafe(48)
    if trusted:
        expires_at = datetime.utcnow() + timedelta(days=Config.TRUSTED_SESSION_DAYS)
    else:
        expires_at = datetime.utcnow() + timedelta(seconds=Config.PERMANENT_SESSION_LIFETIME)

    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO sessions (user_id, device_id, session_token, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, device_id, token, expires_at.isoformat(), ip_address, user_agent),
        )
        session_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
        
        # Phase 5: Network Access Control
        # Determine if user is admin for VLAN
        user = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
        is_admin = bool(user["is_admin"]) if user else False
        
        try:
            SimulatedNetworkController.allocate_network(session_id, user_id, device_id, is_admin)
        except NetworkAllocationError as e:
            logger.error(f"Failed to provision network: {e}")
            # If network provisioning fails, we should arguably fail the session, 
            # but for simulated purposes we'll log it. An explicit failure state
            # would be better if we wanted to enforce strict NAC.
            pass
            
    finally:
        conn.close()
    return token


def validate_session(token: str) -> dict | None:
    """Validate session token; return session dict or None if invalid/expired."""
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT s.*, u.username, u.is_admin, u.is_blocked as user_blocked,
                   d.device_fingerprint, d.is_trusted, d.is_blocked as device_blocked
            FROM sessions s
            JOIN users   u ON s.user_id   = u.id
            JOIN devices d ON s.device_id = d.id
            WHERE s.session_token=? AND s.is_active=1
            """,
            (token,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return None

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.utcnow() > expires_at:
        invalidate_session(token)
        return None

    if row["user_blocked"] or row["device_blocked"]:
        return None

    return dict(row)


def renew_trusted_session(token: str) -> str | None:
    """
    Renew a trusted session when it is within 24 hours of expiry.
    Returns the new token, 'block', 'challenge', or the original token.
    """
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_token=? AND is_active=1", (token,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return None

    expires_at = datetime.fromisoformat(row["expires_at"])
    time_left  = expires_at - datetime.utcnow()

    if time_left > timedelta(hours=24):
        return token  # Still valid, no renewal needed

    conn2 = get_db()
    try:
        device = conn2.execute(
            "SELECT is_trusted, device_fingerprint FROM devices WHERE id=?", (row["device_id"],)
        ).fetchone()
        if not device or not device["is_trusted"]:
            return token  # Do not renew untrusted devices automatically
        device_fingerprint = device["device_fingerprint"]
    finally:
        conn2.close()

    from flask import request
    from ai.risk_engine import compute_risk_score
    from utils.logger import log_audit

    ip = request.remote_addr
    ua = request.user_agent.string if request.user_agent else ""

    risk = compute_risk_score(row["user_id"], device_fingerprint, ip, ua)
    score = risk["score"]

    if score >= Config.RISK_THRESHOLD_BLOCK:
        invalidate_session(token)
        log_audit(row["user_id"], "session_renewal_blocked", f"risk={score}", ip)
        return "block"
    elif score >= Config.RISK_THRESHOLD_CHALLENGE:
        invalidate_session(token)
        log_audit(row["user_id"], "session_renewal_challenge", f"risk={score}", ip)
        return "challenge"

    new_token = create_session(
        user_id=row["user_id"],
        device_id=row["device_id"],
        ip_address=ip,
        user_agent=ua,
        trusted=True,
    )
    invalidate_session(token)
    log_audit(row["user_id"], "session_renewed", f"risk={score}", ip)
    return new_token


def invalidate_session(token: str):
    conn = get_db()
    try:
        session = conn.execute("SELECT id FROM sessions WHERE session_token=?", (token,)).fetchone()
        if session:
            SimulatedNetworkController.release_network(session["id"])
            
        conn.execute("UPDATE sessions SET is_active=0 WHERE session_token=?", (token,))
        conn.commit()
    finally:
        conn.close()


def invalidate_all_user_sessions(user_id: int):
    conn = get_db()
    try:
        sessions = conn.execute("SELECT id FROM sessions WHERE user_id=? AND is_active=1", (user_id,)).fetchall()
        for s in sessions:
            SimulatedNetworkController.release_network(s["id"])
            
        conn.execute("UPDATE sessions SET is_active=0 WHERE user_id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def get_active_sessions_for_user(user_id: int):
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT s.*, d.device_name FROM sessions s
            JOIN devices d ON s.device_id = d.id
            WHERE s.user_id=? AND s.is_active=1
            ORDER BY s.created_at DESC
            """,
            (user_id,),
        ).fetchall()
        
        results = []
        for r in rows:
            rd = dict(r)
            try:
                created = datetime.fromisoformat(rd["created_at"])
                expires = datetime.fromisoformat(rd["expires_at"])
                rd["is_trusted_session"] = (expires - created).total_seconds() > 86400  # More than 1 day
            except Exception:
                rd["is_trusted_session"] = False
            results.append(rd)
        return results
    finally:
        conn.close()
