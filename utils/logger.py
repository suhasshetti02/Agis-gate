"""
Logging utilities for Aegis-Gate.
Logs auth events and audit actions to both the SQLite database and rotating file logs.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from db.database import get_db
from config import Config


def _get_file_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"aegis.{name}")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        # Ensure log directory exists at call time (not module import time)
        os.makedirs(Config.LOGS_DIR, exist_ok=True)
        handler = RotatingFileHandler(
            str(Config.LOGS_DIR / f"{name}.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)
    return logger


def log_attempt(user_id, username_tried: str, device_fingerprint: str,
                ip_address: str, user_agent: str, status: str,
                risk_score: float = 0.0, block_reason: str = None):
    """Log a login attempt to the DB and the auth log file."""
    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO login_attempts
                (user_id, username_tried, device_fingerprint, ip_address,
                 user_agent, status, risk_score, block_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username_tried, device_fingerprint, ip_address,
             user_agent, status, risk_score, block_reason),
        )
        conn.commit()
    finally:
        conn.close()

    _get_file_logger("auth").info(
        f"USER={username_tried} | DEVICE={device_fingerprint} | IP={ip_address} "
        f"| STATUS={status} | RISK={risk_score:.4f} | REASON={block_reason}"
    )


def log_audit(user_id, action: str, details: str = None, ip_address: str = None):
    """Log an admin or system audit event to the DB and the audit log file."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
            (user_id, action, details, ip_address),
        )
        conn.commit()
    finally:
        conn.close()

    _get_file_logger("audit").info(
        f"USER_ID={user_id} | ACTION={action} | DETAILS={details} | IP={ip_address}"
    )


def get_recent_attempts(limit: int = 100):
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT la.*, u.username
            FROM login_attempts la
            LEFT JOIN users u ON la.user_id = u.id
            ORDER BY la.attempted_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def get_audit_log(limit: int = 100):
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT al.*, u.username
            FROM audit_log al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]
