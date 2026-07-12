"""
Authentication routes for Aegis-Gate.
"""

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta, timezone

from db.database import get_db
from auth.rsa_handler import verify_signature
from auth.nonce_handler import generate_nonce, validate_nonce, build_challenge
from auth.otp_handler import generate_otp, verify_otp, deliver_otp
from auth.device_registry import (
    get_device_by_fingerprint, register_device, can_register_device,
    update_device_last_seen, set_device_trusted
)
from auth.session_manager import create_session, validate_session, invalidate_session
from ai.risk_engine import compute_risk_score, decay_trust_score, boost_trust_score
from ai.anomaly_detector import get_ml_risk_adjustment
from utils.logger import log_attempt, log_audit
from utils.helpers import get_client_ip, get_user_agent
from config import Config

auth_bp = Blueprint("auth", __name__)


def _get_user_by_username(username: str):
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    finally:
        conn.close()
    return dict(user) if user else None


def _increment_failed(user_id: int):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET failed_attempts=failed_attempts+1 WHERE id=?", (user_id,))
        user = conn.execute("SELECT failed_attempts FROM users WHERE id=?", (user_id,)).fetchone()
        if user and user["failed_attempts"] >= Config.MAX_FAILED_ATTEMPTS:
            lockout_until = (
                datetime.utcnow() + timedelta(minutes=Config.LOCKOUT_DURATION_MINUTES)
            ).isoformat()
            conn.execute(
                "UPDATE users SET lockout_until=?, is_blocked=1 WHERE id=?",
                (lockout_until, user_id),
            )
        conn.commit()
    finally:
        conn.close()


def _reset_failed(user_id: int):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET failed_attempts=0, lockout_until=NULL, is_blocked=0, "
            "last_login=datetime('now') WHERE id=?",
            (user_id,),
        )
        conn.commit()
    finally:
        conn.close()


def _is_locked_out(user: dict) -> bool:
    if not user.get("lockout_until"):
        return False
    lockout_until = datetime.fromisoformat(user["lockout_until"])
    if datetime.utcnow() < lockout_until:
        return True
    # Lockout expired — unblock
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET is_blocked=0, lockout_until=NULL, failed_attempts=0 WHERE id=?",
            (user["id"],),
        )
        conn.commit()
    finally:
        conn.close()
    return False


# ─── Login Page ────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "").strip()
        device_fp = request.form.get("device_fingerprint", "").strip()
        device_name = request.form.get("device_name", "Unknown Device").strip()

        ip = get_client_ip()
        ua = get_user_agent()

        user = _get_user_by_username(username)
        if not user:
            log_attempt(None, username, device_fp, ip, ua, "fail_no_user")
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        if _is_locked_out(user):
            log_attempt(user["id"], username, device_fp, ip, ua, "blocked_lockout")
            flash("Account temporarily locked. Try again later.", "warning")
            return render_template("login.html")

        if not check_password_hash(user["password_hash"], password):
            _increment_failed(user["id"])
            log_attempt(user["id"], username, device_fp, ip, ua, "fail_bad_password")
            if device_fp:
                device = get_device_by_fingerprint(device_fp)
                if device:
                    decay_trust_score(device["id"], 0.1)
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        # Password OK – compute risk
        behavioral_data = request.form.get("behavioral_data")
        risk = compute_risk_score(user["id"], device_fp, ip, ua, behavioral_data)
        hour = datetime.utcnow().hour

        # ML anomaly adjustment
        device     = get_device_by_fingerprint(device_fp) if device_fp else None
        device_age = 0.0
        login_count = 0
        if device:
            reg_date    = datetime.fromisoformat(device["registered_at"])
            device_age  = (datetime.utcnow() - reg_date).days
            login_count = device["login_count"]

        ml_adj      = get_ml_risk_adjustment(user["id"], hour, 0, risk["score"], device_age, login_count)
        final_score = min(1.0, risk["score"] + ml_adj)

        log_attempt(
            user["id"], username, device_fp, ip, ua,
            "blocked" if final_score >= Config.RISK_THRESHOLD_BLOCK else "allow",
            final_score,
        )

        if final_score >= Config.RISK_THRESHOLD_BLOCK:
            flash("Access denied due to high-risk activity.", "danger")
            return render_template("login.html")

        # Require device fingerprint
        if not device_fp:
            flash("Device fingerprint missing.", "warning")
            return render_template("login.html")

        device = get_device_by_fingerprint(device_fp)

        if not device:
            # Unknown device – trigger OTP registration flow
            session["pending_user_id"]    = user["id"]
            session["pending_device_fp"]  = device_fp
            session["pending_device_name"] = device_name
            otp = generate_otp(user["id"], "device_registration")
            success = deliver_otp(user["id"], user["username"], user["email"], otp)
            if success:
                flash("We have sent a verification code to your registered college email.", "info")
            else:
                flash("Unable to send verification email. Please try again later.", "danger")
            return redirect(url_for("auth.register_device_otp"))

        if device["is_blocked"]:
            flash("This device has been blocked.", "danger")
            return render_template("login.html")

        if device["user_id"] != user["id"]:
            flash("Device does not belong to this account.", "danger")
            return render_template("login.html")

        # Risk requires cryptographic challenge
        if final_score >= Config.RISK_THRESHOLD_CHALLENGE:
            session["challenge_user_id"]  = user["id"]
            session["challenge_device_fp"] = device_fp
            nonce = generate_nonce(user["id"], device_fp, "auth")
            return redirect(url_for("auth.challenge", nonce=nonce))

        # All OK – create session
        _complete_login(user, device, ip, ua, final_score)
        return redirect(url_for("dashboard.index"))

    return render_template("login.html")


def _complete_login(user: dict, device: dict, ip: str, ua: str, risk_score: float):
    is_trusted = bool(device.get("is_trusted"))
    token = create_session(user["id"], device["id"], ip, ua, trusted=is_trusted)
    update_device_last_seen(device["id"])
    boost_trust_score(device["id"], 0.02)
    _reset_failed(user["id"])
    session.clear()
    session["session_token"] = token
    session["user_id"]       = user["id"]
    session["username"]      = user["username"]
    session["is_admin"]      = bool(user["is_admin"])
    session["risk_score"]    = risk_score
    log_audit(user["id"], "login_success", f"device={device['device_fingerprint']}", ip)

    # Automatically retrain the ML model when enough new data is available
    conn = get_db()
    try:
        row = conn.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE user_id=?", (user["id"],)).fetchone()
        if row and row["cnt"] > 0 and row["cnt"] % 10 == 0:
            from ai.anomaly_detector import train_anomaly_model
            import threading
            threading.Thread(target=train_anomaly_model, args=(user["id"],)).start()
    except Exception:
        pass
    finally:
        conn.close()


# ─── Nonce Challenge ────────────────────────────────────────────────────────────

@auth_bp.route("/challenge")
def challenge():
    nonce = request.args.get("nonce", "")
    return render_template("challenge.html", nonce=nonce)


@auth_bp.route("/verify-challenge", methods=["POST"])
def verify_challenge():
    data      = request.get_json()
    nonce     = data.get("nonce", "")
    signature = data.get("signature", "")
    timestamp = data.get("timestamp", "")
    device_fp = session.get("challenge_device_fp", "")
    user_id   = session.get("challenge_user_id")

    if not user_id:
        return jsonify({"success": False, "message": "Session expired."}), 400

    if not validate_nonce(nonce, "auth"):
        return jsonify({"success": False, "message": "Invalid or expired nonce."}), 400

    try:
        client_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if client_time.tzinfo is None:
            client_time = client_time.replace(tzinfo=timezone.utc)
        drift = abs((datetime.now(timezone.utc) - client_time.astimezone(timezone.utc)).total_seconds())
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid challenge timestamp."}), 400

    if drift > Config.NONCE_EXPIRY_SECONDS:
        return jsonify({"success": False, "message": "Challenge timestamp expired."}), 400

    device = get_device_by_fingerprint(device_fp)
    if not device:
        return jsonify({"success": False, "message": "Device not found."}), 400

    challenge_str = build_challenge(nonce, device_fp, timestamp)
    if not verify_signature(device["public_key"], challenge_str, signature):
        decay_trust_score(device["id"], 0.2)
        return jsonify({"success": False, "message": "Signature verification failed."}), 401

    set_device_trusted(device["id"], True)
    device["is_trusted"] = 1

    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    finally:
        conn.close()

    ip = get_client_ip()
    ua = get_user_agent()
    _complete_login(dict(user), device, ip, ua, 0.0)
    return jsonify({"success": True, "redirect": url_for("dashboard.index")})


# ─── Device OTP Registration ────────────────────────────────────────────────────

@auth_bp.route("/register-device", methods=["GET", "POST"])
def register_device_otp():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        otp_entered = request.form.get("otp", "").strip()
        public_key  = request.form.get("public_key", "").strip()
        device_fp   = session.get("pending_device_fp", "")
        device_name = session.get("pending_device_name", "New Device")

        success, message = verify_otp(user_id, otp_entered, "device_registration")
        if not success:
            flash(message, "danger")
            return render_template("otp.html")

        if not can_register_device(user_id):
            flash(f"Device limit reached ({Config.MAX_DEVICES_PER_USER} devices).", "warning")
            return redirect(url_for("auth.login"))

        try:
            device = register_device(user_id, device_name, device_fp, public_key)
        except ValueError as e:
            flash(str(e), "warning")
            return render_template("otp.html")

        conn = get_db()
        try:
            user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        finally:
            conn.close()

        ip = get_client_ip()
        ua = get_user_agent()
        _complete_login(dict(user), device, ip, ua, 0.2)
        log_audit(user_id, "device_registered", f"fp={device_fp}", ip)
        flash("Device registered and logged in!", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("otp.html")


@auth_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    user_id = session.get("pending_user_id")
    if not user_id:
        return jsonify({"success": False, "message": "Session expired."}), 400

    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    finally:
        conn.close()

    if not user:
        return jsonify({"success": False, "message": "User not found."}), 400

    otp = generate_otp(user_id, "device_registration")
    success = deliver_otp(user_id, user["username"], user["email"], otp)
    
    if success:
        return jsonify({"success": True, "message": "OTP resent to your college email."})
    else:
        return jsonify({"success": False, "message": "Unable to send verification email. Please try again later."}), 500


# ─── Register User ──────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "warning")
            return render_template("register.html")

        conn = get_db()
        try:
            existing = conn.execute(
                "SELECT id FROM users WHERE username=? OR email=?", (username, email)
            ).fetchone()
            if existing:
                flash("Username or email already taken.", "warning")
                return render_template("register.html")

            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, generate_password_hash(password, method="pbkdf2:sha256")),
            )
            conn.commit()
        finally:
            conn.close()

        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


# ─── Logout ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    token = session.get("session_token")
    if token:
        invalidate_session(token)
    log_audit(session.get("user_id"), "logout", ip_address=get_client_ip())
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
