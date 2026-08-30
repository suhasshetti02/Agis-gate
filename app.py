"""
Aegis-Gate: AI-Enhanced Cryptographic Network Access Control System
────────────────────────────────────────────────────────────────────
Entry point. Run with:  python app.py
"""

import os
import sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import Flask, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect
from config import Config, BASE_DIR
from db.database import init_db
from auth.rsa_handler import save_server_keys
from routes import auth_bp, dashboard_bp, admin_bp, api_bp


def create_app() -> Flask:
    app = Flask(__name__)
    csrf = CSRFProtect(app)

    # ── Config ──────────────────────────────────────────────
    app.secret_key = Config.SECRET_KEY
    app.config["SESSION_COOKIE_HTTPONLY"]    = Config.SESSION_COOKIE_HTTPONLY
    app.config["SESSION_COOKIE_SAMESITE"]    = Config.SESSION_COOKIE_SAMESITE
    app.config["PERMANENT_SESSION_LIFETIME"] = Config.PERMANENT_SESSION_LIFETIME

    # Expose only safe config variables to Jinja templates
    app.jinja_env.globals["config"] = {
        "MAX_DEVICES_PER_USER": Config.MAX_DEVICES_PER_USER
    }

    # ── Initialisation ───────────────────────────────────────
    init_db()
    save_server_keys()
    _ensure_dirs()

    # ── Blueprints ───────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    # ── Root redirect ────────────────────────────────────────
    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard.index"))
        return redirect(url_for("auth.login"))

    # ── Error handlers ───────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        from flask import render_template
        return render_template("error.html", code=500, message="Internal server error."), 500

    return app


def _ensure_dirs():
    """Create runtime directories if they don't exist."""
    os.makedirs(Config.LOGS_DIR, exist_ok=True)
    os.makedirs(Config.KEYS_DIR, exist_ok=True)
    os.makedirs(BASE_DIR / "models", exist_ok=True)


if __name__ == "__main__":
    app = create_app()
    print("\n" + "=" * 55)
    print("  AEGIS-GATE  -  Cryptographic Access Control System")
    print("=" * 55)
    print("  URL  : http://0.0.0.0:8888")
    print("  DB   :", Config.DATABASE_PATH)
    print("  DEBUG:", Config.DEBUG)
    print("=" * 55 + "\n")
    app.run(debug=Config.DEBUG, host="0.0.0.0", port=8888)
