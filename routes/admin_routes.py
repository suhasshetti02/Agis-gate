"""
Admin dashboard routes for Aegis-Gate.
"""

from flask import Blueprint, render_template, redirect, url_for, session, flash, request, jsonify
from werkzeug.security import check_password_hash
from db.database import get_db
from auth.device_registry import block_device, set_device_trusted
from auth.session_manager import invalidate_all_user_sessions, validate_session
from utils.logger import get_recent_attempts, get_audit_log, log_audit
from utils.helpers import get_client_ip
from ai.risk_engine import get_risk_history

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get("session_token")
        session_data = validate_session(token) if token else None
        if not session_data:
            session.clear()
            return redirect(url_for("auth.login"))
        user_id = session_data["user_id"]
            
        conn = get_db()
        try:
            user = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
        finally:
            conn.close()
            
        if not user or not user["is_admin"]:
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard.index"))
            
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route("/")
@admin_required
def index():
    conn = get_db()
    try:
        stats = {
            "total_users": conn.execute(
                "SELECT COUNT(*) as c FROM users WHERE is_admin=0"
            ).fetchone()["c"],
            "total_devices": conn.execute(
                "SELECT COUNT(*) as c FROM devices"
            ).fetchone()["c"],
            "active_sessions": conn.execute(
                "SELECT COUNT(*) as c FROM sessions WHERE is_active=1"
            ).fetchone()["c"],
            "blocked_users": conn.execute(
                "SELECT COUNT(*) as c FROM users WHERE is_blocked=1"
            ).fetchone()["c"],
            "blocked_devices": conn.execute(
                "SELECT COUNT(*) as c FROM devices WHERE is_blocked=1"
            ).fetchone()["c"],
            "attempts_today": conn.execute(
                "SELECT COUNT(*) as c FROM login_attempts WHERE attempted_at > date('now')"
            ).fetchone()["c"],
            "failed_today": conn.execute(
                "SELECT COUNT(*) as c FROM login_attempts "
                "WHERE status LIKE 'fail%' AND attempted_at > date('now')"
            ).fetchone()["c"],
        }
        recent_attempts = get_recent_attempts(10)
    finally:
        conn.close()

    return render_template("admin/dashboard.html", stats=stats, recent_attempts=recent_attempts)


@admin_bp.route("/users")
@admin_required
def users():
    conn = get_db()
    try:
        user_list = conn.execute("""
            SELECT u.*, COUNT(d.id) as device_count
            FROM users u
            LEFT JOIN devices d ON u.id = d.user_id
            WHERE u.is_admin=0
            GROUP BY u.id
            ORDER BY u.created_at DESC
        """).fetchall()
    finally:
        conn.close()

    return render_template("admin/users.html", users=[dict(u) for u in user_list])


@admin_bp.route("/users/action/<int:user_id>", methods=["POST"])
@admin_required
def user_action(user_id):
    action = request.form.get("action", "block")
    
    conn = get_db()
    try:
        if action == "block":
            conn.execute("UPDATE users SET is_blocked=1 WHERE id=?", (user_id,))
            invalidate_all_user_sessions(user_id)
            flash("User blocked.", "success")
        elif action == "unblock":
            conn.execute("UPDATE users SET is_blocked=0, lockout_until=NULL WHERE id=?", (user_id,))
            flash("User unblocked.", "success")
        elif action == "reset_failed":
            conn.execute("UPDATE users SET failed_attempts=0, lockout_until=NULL WHERE id=?", (user_id,))
            flash("Failed attempts reset.", "success")
        elif action == "delete":
            # Safety check - don't delete other admins or self if possible
            user = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
            if user and not user["is_admin"]:
                conn.execute("DELETE FROM login_attempts WHERE user_id=?", (user_id,))
                conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
                conn.execute("DELETE FROM devices WHERE user_id=?", (user_id,))
                conn.execute("DELETE FROM otps WHERE user_id=?", (user_id,))
                conn.execute("DELETE FROM nonces WHERE user_id=?", (user_id,))
                conn.execute("DELETE FROM risk_scores WHERE user_id=?", (user_id,))
                conn.execute("DELETE FROM audit_log WHERE user_id=?", (user_id,))
                conn.execute("DELETE FROM users WHERE id=?", (user_id,))
                flash("User deleted.", "success")
            else:
                flash("Cannot delete admin users.", "danger")
        conn.commit()
    finally:
        conn.close()

    log_audit(
        session.get("user_id"),
        f"admin_user_action_{action}",
        f"target_user={user_id}",
        get_client_ip(),
    )
    return redirect(url_for("admin.users"))

@admin_bp.route("/devices")
@admin_required
def devices():
    conn = get_db()
    try:
        device_list = conn.execute("""
            SELECT d.*, u.username FROM devices d
            JOIN users u ON d.user_id = u.id
            ORDER BY d.registered_at DESC
        """).fetchall()
    finally:
        conn.close()

    return render_template("admin/devices.html", devices=[dict(d) for d in device_list])


@admin_bp.route("/devices/action/<int:device_id>", methods=["POST"])
@admin_required
def device_action(device_id):
    action = request.form.get("action", "block")
    
    if action == "block":
        block_device(device_id, True)
        flash("Device blocked.", "success")
    elif action == "unblock":
        block_device(device_id, False)
        flash("Device unblocked.", "success")
    elif action == "revoke":
        set_device_trusted(device_id, False)
        flash("Device trust revoked.", "success")

    log_audit(
        session.get("user_id"),
        f"admin_device_action_{action}",
        f"device_id={device_id}",
        get_client_ip(),
    )
    return redirect(url_for("admin.devices"))


@admin_bp.route("/logs")
@admin_required
def logs():
    attempts = get_recent_attempts(200)
    return render_template("admin/logs.html", attempts=attempts)


@admin_bp.route("/audit")
@admin_required
def audit():
    audit_entries = get_audit_log(200)
    return render_template("admin/audit.html", entries=audit_entries)


@admin_bp.route("/risk")
@admin_required
def risk_overview():
    conn = get_db()
    try:
        scores = conn.execute("""
            SELECT r.*, u.username, d.device_name
            FROM risk_scores r
            JOIN users u ON r.user_id = u.id
            LEFT JOIN devices d ON r.device_id = d.id
            ORDER BY r.evaluated_at DESC LIMIT 200
        """).fetchall()
        
        results = []
        import json
        for s in scores:
            sd = dict(s)
            try:
                sd["factors"] = json.loads(sd["factors"]) if sd["factors"] else {}
            except Exception:
                sd["factors"] = {}
            try:
                sd["reasons"] = json.loads(sd["reasons"]) if sd.get("reasons") else []
            except Exception:
                sd["reasons"] = []
            results.append(sd)
    finally:
        conn.close()

    return render_template("admin/risk.html", scores=results)


@admin_bp.route("/api/stats")
@admin_required
def api_stats():
    """JSON endpoint for admin dashboard charts."""
    conn = get_db()
    try:
        # Attempts by status — last 7 days
        daily = conn.execute("""
            SELECT date(attempted_at) as day, status, COUNT(*) as cnt
            FROM login_attempts
            WHERE attempted_at > date('now', '-7 days')
            GROUP BY day, status
            ORDER BY day
        """).fetchall()

        # Risk score distribution
        risk_dist = conn.execute("""
            SELECT
                CASE
                    WHEN score < 0.3 THEN 'Low'
                    WHEN score < 0.6 THEN 'Medium'
                    ELSE 'High'
                END as category,
                COUNT(*) as cnt
            FROM risk_scores
            GROUP BY category
        """).fetchall()
    finally:
        conn.close()

    return jsonify({
        "daily":     [dict(r) for r in daily],
        "risk_dist": [dict(r) for r in risk_dist],
    })
