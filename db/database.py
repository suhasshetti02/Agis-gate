"""
Aegis-Gate database initialisation and connection helper.
Uses SQLite with WAL mode and foreign key enforcement.
All Path objects are converted to str for cross-platform sqlite3 compatibility.
"""

import sqlite3
import os
from pathlib import Path
from config import Config


def get_db() -> sqlite3.Connection:
    """Return a new database connection with Row factory enabled."""
    # str() ensures Windows UNC/long paths work with sqlite3
    conn = sqlite3.connect(str(Config.DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize all tables and seed the admin user."""
    os.makedirs(Config.DATABASE_PATH.parent, exist_ok=True)
    conn = get_db()
    c = conn.cursor()

    # ── Users ─────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    UNIQUE NOT NULL,
            email           TEXT    UNIQUE NOT NULL,
            password_hash   TEXT    NOT NULL,
            is_admin        INTEGER DEFAULT 0,
            is_blocked      INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until   TEXT    DEFAULT NULL,
            created_at      TEXT    DEFAULT (datetime('now')),
            last_login      TEXT    DEFAULT NULL,
            behavioral_profile TEXT DEFAULT NULL
        )
    """)
    try:
        c.execute("ALTER TABLE users ADD COLUMN behavioral_profile TEXT DEFAULT NULL")
    except Exception:
        pass

    # ── Devices ───────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id             INTEGER NOT NULL,
            device_name         TEXT    NOT NULL,
            device_fingerprint  TEXT    UNIQUE NOT NULL,
            public_key          TEXT    NOT NULL,
            trust_score         REAL    DEFAULT 1.0,
            is_trusted          INTEGER DEFAULT 0,
            is_blocked          INTEGER DEFAULT 0,
            registered_at       TEXT    DEFAULT (datetime('now')),
            last_seen           TEXT    DEFAULT NULL,
            login_count         INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ── Sessions ──────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            device_id       INTEGER NOT NULL,
            session_token   TEXT    UNIQUE NOT NULL,
            created_at      TEXT    DEFAULT (datetime('now')),
            expires_at      TEXT    NOT NULL,
            is_active       INTEGER DEFAULT 1,
            ip_address      TEXT,
            user_agent      TEXT,
            FOREIGN KEY (user_id)   REFERENCES users(id),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    # ── Login attempts ────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id             INTEGER,
            username_tried      TEXT,
            device_fingerprint  TEXT,
            ip_address          TEXT NOT NULL,
            user_agent          TEXT,
            status              TEXT NOT NULL,
            risk_score          REAL DEFAULT 0.0,
            block_reason        TEXT DEFAULT NULL,
            attempted_at        TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ── Risk scores ───────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS risk_scores (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            device_id    INTEGER,
            score        REAL    NOT NULL,
            category     TEXT    DEFAULT 'Low Risk',
            reasons      TEXT,
            factors      TEXT,
            action_taken TEXT,
            evaluated_at TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id)   REFERENCES users(id),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    # ── Nonces ────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            nonce               TEXT UNIQUE NOT NULL,
            user_id             INTEGER,
            device_fingerprint  TEXT,
            purpose             TEXT DEFAULT 'auth',
            created_at          TEXT DEFAULT (datetime('now')),
            expires_at          TEXT NOT NULL,
            used                INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ── OTPs ──────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            otp_code        TEXT    NOT NULL,
            purpose         TEXT    DEFAULT 'device_registration',
            created_at      TEXT    DEFAULT (datetime('now')),
            expires_at      TEXT    NOT NULL,
            used            INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ── Audit log ─────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            action     TEXT NOT NULL,
            details    TEXT,
            ip_address TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ── Network Allocations ───────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_allocations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      INTEGER NOT NULL UNIQUE,
            user_id         INTEGER NOT NULL,
            device_id       INTEGER NOT NULL,
            vlan_id         INTEGER NOT NULL,
            ip_address      TEXT    UNIQUE NOT NULL,
            status          TEXT    DEFAULT 'allocated',
            allocated_at    TEXT    DEFAULT (datetime('now')),
            released_at     TEXT    DEFAULT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id),
            FOREIGN KEY (user_id)    REFERENCES users(id),
            FOREIGN KEY (device_id)  REFERENCES devices(id)
        )
    """)

    conn.commit()
    _seed_admin(conn)
    conn.close()


def _seed_admin(conn: sqlite3.Connection):
    """Insert the admin account on first run using the configured password."""
    from werkzeug.security import generate_password_hash
    from config import Config  # local import avoids circular import at module load

    existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        conn.execute(
            """
            INSERT INTO users (username, email, password_hash, is_admin)
            VALUES (?, ?, ?, 1)
            """,
            (
                "admin",
                "admin@aegis.local",
                generate_password_hash(Config.ADMIN_PASSWORD, method="pbkdf2:sha256"),
            ),
        )
        conn.commit()
