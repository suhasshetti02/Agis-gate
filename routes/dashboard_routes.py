"""
User dashboard routes for Aegis-Gate.
"""

from flask import Blueprint, render_template, redirect, url_for, session, flash, request
from db.database import get_db
from auth.device_registry import get_devices_for_user, remove_device, set_device_trusted
from auth.session_manager import (
    get_active_sessions_for_user,
    invalidate_session,
    renew_trusted_session,
    validate_session,
    invalidate_all_user_sessions,
)
from ai.risk_engine import get_risk_history
from utils.helpers import get_client_ip
from utils.logger import log_audit

dashboard_bp = Blueprint("dashboard", __name__)


def _require_login():
    """Return the current user dict, or None if not authenticated."""
    token = session.get("session_token")
    session_data = validate_session(token) if token else None
    if not session_data:
        session.clear()
        return None
    user_id = session_data["user_id"]
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    finally:
        conn.close()
    return dict(user) if user else None


@dashboard_bp.route("/dashboard")
def index():
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))

    # Attempt trusted session renewal
    token = session.get("session_token")
    if token:
        new_token = renew_trusted_session(token)
        if new_token == "block":
            session.clear()
            flash("Session blocked due to high security risk.", "danger")
            return redirect(url_for("auth.login"))
        elif new_token == "challenge":
            session.clear()
            flash("Security check required. Please login again to verify.", "warning")
            return redirect(url_for("auth.login"))
        elif new_token and new_token != token:
            session["session_token"] = new_token
            flash("Trusted session securely renewed.", "info")

    devices      = get_devices_for_user(user["id"])
    sessions     = get_active_sessions_for_user(user["id"])
    risk_history = get_risk_history(user["id"], limit=5)

    import json
    behavioral_profile = {}
    if user.get("behavioral_profile"):
        try:
            behavioral_profile = json.loads(user["behavioral_profile"])
        except Exception:
            pass

    return render_template(
        "dashboard.html",
        user=user,
        devices=devices,
        sessions=sessions,
        risk_history=risk_history,
        behavioral_profile=behavioral_profile,
        risk_score=session.get("risk_score", 0.0),
    )


@dashboard_bp.route("/devices")
def devices():
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))

    device_list = get_devices_for_user(user["id"])
    return render_template("devices.html", user=user, devices=device_list)


@dashboard_bp.route("/devices/remove/<int:device_id>", methods=["POST"])
def remove_dev(device_id):
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))

    remove_device(device_id, user["id"])
    log_audit(user["id"], "device_removed", f"device_id={device_id}", get_client_ip())
    flash("Device removed.", "success")
    return redirect(url_for("dashboard.devices"))


@dashboard_bp.route("/devices/trust/<int:device_id>", methods=["POST"])
def trust_dev(device_id):
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))

    conn = get_db()
    try:
        device = conn.execute(
            "SELECT id FROM devices WHERE id=? AND user_id=?", (device_id, user["id"])
        ).fetchone()
    finally:
        conn.close()

    if not device:
        flash("Device not found.", "danger")
        return redirect(url_for("dashboard.devices"))

    action  = request.form.get("action", "trust")
    trusted = action == "trust"
    set_device_trusted(device_id, trusted)
    log_audit(
        user["id"],
        f"device_{'trusted' if trusted else 'untrusted'}",
        f"device_id={device_id}",
        get_client_ip(),
    )
    flash(f"Device {'trusted' if trusted else 'untrusted'}.", "success")
    return redirect(url_for("dashboard.devices"))


@dashboard_bp.route("/sessions/revoke/<int:session_id>", methods=["POST"])
def revoke_session(session_id):
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))

    conn = get_db()
    try:
        sess = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    finally:
        conn.close()

    if sess and sess["user_id"] == user["id"]:
        invalidate_session(sess["session_token"])
        log_audit(user["id"], "session_revoked", f"session_id={session_id}", get_client_ip())
        flash("Session revoked.", "success")

    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/profile", methods=["GET", "POST"])
def profile():
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        from werkzeug.security import check_password_hash, generate_password_hash
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()

        if not check_password_hash(user["password_hash"], current_password):
            flash("Incorrect current password.", "danger")
            return redirect(url_for("dashboard.profile"))
            
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "warning")
            return redirect(url_for("dashboard.profile"))

        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (generate_password_hash(new_password, method="pbkdf2:sha256"), user["id"])
            )
            conn.commit()
            invalidate_all_user_sessions(user["id"])
            session.clear()
            log_audit(user["id"], "password_changed", None, get_client_ip())
            flash("Password updated successfully. Please log in again.", "success")
        finally:
            conn.close()
            
        return redirect(url_for("auth.login"))

    return render_template("profile.html", user=user)
