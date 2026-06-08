"""
AI-based risk scoring engine for Aegis-Gate.
Uses behavioral signals to compute a 0–1 risk score (high = high risk).
"""

import json
from datetime import datetime, timedelta
from db.database import get_db
from config import Config


class RiskFactor:
    FAILED_ATTEMPTS  = "failed_attempts"
    ODD_HOUR_LOGIN   = "odd_hour_login"
    NEW_DEVICE       = "new_device"
    DEVICE_SWITCHING = "device_switching"
    TRUST_SCORE_LOW  = "trust_score_low"
    BLOCKED_DEVICE   = "blocked_device"
    RAPID_REQUESTS   = "rapid_requests"
    NEW_IP           = "new_ip"
    OTP_FAILURES     = "otp_failures"
    ANOMALY_SCORE    = "anomaly_score"
    BEHAVIOR_ANOMALY = "behavior_anomaly"


def compute_risk_score(user_id: int, device_fingerprint: str = None,
                       ip_address: str = None, user_agent: str = None,
                       behavioral_data: str = None) -> dict:
    """
    Evaluate multiple behavioral signals and return a risk score + factor breakdown.
    Now includes ML anomaly adjustment and returns explainable textual reasons.
    """
    factors = {}
    reasons = []
    score   = 0.0

    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return {
                "score": 1.0,
                "category": "Critical Risk",
                "reasons": ["User not found"],
                "factors": {"user_not_found": 1.0},
                "action": "block"
            }

        # ── Factor 1: Failed login attempts ───────────────────────
        failed = user["failed_attempts"] or 0
        if failed >= Config.MAX_FAILED_ATTEMPTS:
            factors[RiskFactor.FAILED_ATTEMPTS] = 1.0
            score += 0.4
            reasons.append(f"Maximum failed attempts reached ({failed})")
        elif failed >= 3:
            factors[RiskFactor.FAILED_ATTEMPTS] = 0.6
            score += 0.2
            reasons.append(f"Multiple failed attempts ({failed})")
        elif failed >= 1:
            factors[RiskFactor.FAILED_ATTEMPTS] = 0.2
            score += 0.05
            reasons.append(f"Recent failed attempt ({failed})")

        # ── Factor 2: Odd-hour login (2 AM – 5 AM UTC) ────────────
        hour = datetime.utcnow().hour
        if 2 <= hour <= 5:
            factors[RiskFactor.ODD_HOUR_LOGIN] = 0.5
            score += 0.1
            reasons.append("Unusual login time (Late Night)")

        # ── Factor 3 & 4: Device trust score + new device ─────────
        device_age_days = 0.0
        login_count = 0
        if device_fingerprint:
            device = conn.execute(
                "SELECT * FROM devices WHERE device_fingerprint=?", (device_fingerprint,)
            ).fetchone()

            if device:
                reg_date = datetime.fromisoformat(device["registered_at"])
                device_age_days = (datetime.utcnow() - reg_date).days
                login_count = device["login_count"]

                trust = device["trust_score"]
                if trust < 0.3:
                    factors[RiskFactor.TRUST_SCORE_LOW] = 1.0 - trust
                    score += 0.25
                    reasons.append(f"Low device trust score ({round(trust, 2)})")
                elif trust < 0.6:
                    factors[RiskFactor.TRUST_SCORE_LOW] = 0.5
                    score += 0.1
                    reasons.append(f"Moderate device trust score ({round(trust, 2)})")

                if device["is_blocked"]:
                    factors[RiskFactor.BLOCKED_DEVICE] = 1.0
                    score += 0.5
                    reasons.append("Device is explicitly blocked")

                if device["login_count"] == 0:
                    factors[RiskFactor.NEW_DEVICE] = 0.4
                    score += 0.15
                    reasons.append("First login from this registered device")
            else:
                # Completely unknown device
                factors[RiskFactor.NEW_DEVICE] = 0.8
                score += 0.3
                reasons.append("Unrecognized new device")
        else:
            reasons.append("No device fingerprint provided")
            score += 0.2

        # ── Factor 5: Device switching frequency ──────────────────
        switching_factor = _compute_device_switching(user_id, conn)
        if switching_factor > 0:
            factors[RiskFactor.DEVICE_SWITCHING] = switching_factor
            score += switching_factor * 0.2
            reasons.append("High frequency of device switching")

        # ── Factor 6: Rapid repeated requests ─────────────────────
        if _detect_rapid_requests(user_id, conn):
            factors[RiskFactor.RAPID_REQUESTS] = 0.7
            score += 0.2
            reasons.append("Rapid successive login requests detected")

        # ── Factor 7: New IP address ──────────────────────────────
        if ip_address:
            ip_factor = _check_new_ip(user_id, ip_address, conn)
            if ip_factor > 0:
                factors[RiskFactor.NEW_IP] = ip_factor
                score += ip_factor * 0.15
                reasons.append("Login from a previously unseen IP address")

        # ── Factor 8: OTP Failures ────────────────────────────────
        try:
            otp_failures = conn.execute(
                "SELECT SUM(failed_attempts) as cnt FROM otps WHERE user_id=? AND created_at > datetime('now', '-1 day')",
                (user_id,)
            ).fetchone()
            if otp_failures and otp_failures["cnt"]:
                cnt = otp_failures["cnt"]
                factors[RiskFactor.OTP_FAILURES] = min(1.0, cnt * 0.2)
                score += min(1.0, cnt * 0.2) * 0.2
                reasons.append(f"{cnt} recent OTP verification failures")
        except Exception:
            pass

        # ── Factor 9: Behavioral Biometrics ───────────────────────
        if behavioral_data:
            try:
                current_behavior = json.loads(behavioral_data)
                saved_behavior_str = user.get("behavioral_profile")
                
                if saved_behavior_str:
                    saved_behavior = json.loads(saved_behavior_str)
                    # Compare typing speed
                    old_speed = saved_behavior.get("typing_speed_kps", 0)
                    new_speed = current_behavior.get("typing_speed_kps", 0)
                    
                    if old_speed > 0 and new_speed > 0:
                        diff_ratio = abs(new_speed - old_speed) / old_speed
                        if diff_ratio > 0.4:  # >40% difference in typing speed
                            factors[RiskFactor.BEHAVIOR_ANOMALY] = 0.3
                            score += 0.15
                            reasons.append("Atypical typing behavior detected")
                            
                    # Update running average (alpha = 0.2)
                    updated_behavior = {
                        "avg_dwell_ms": (saved_behavior.get("avg_dwell_ms", current_behavior["avg_dwell_ms"]) * 0.8) + (current_behavior["avg_dwell_ms"] * 0.2),
                        "avg_flight_ms": (saved_behavior.get("avg_flight_ms", current_behavior["avg_flight_ms"]) * 0.8) + (current_behavior["avg_flight_ms"] * 0.2),
                        "typing_speed_kps": (saved_behavior.get("typing_speed_kps", current_behavior["typing_speed_kps"]) * 0.8) + (current_behavior["typing_speed_kps"] * 0.2),
                    }
                    conn.execute("UPDATE users SET behavioral_profile=? WHERE id=?", (json.dumps(updated_behavior), user_id))
                    conn.commit()
                else:
                    # Save initial profile
                    conn.execute("UPDATE users SET behavioral_profile=? WHERE id=?", (json.dumps(current_behavior), user_id))
                    conn.commit()
            except Exception:
                pass

    finally:
        conn.close()

    # ── ML Anomaly Adjustment ─────────────────────────────────
    from ai.anomaly_detector import get_ml_risk_adjustment
    ml_adj = get_ml_risk_adjustment(user_id, hour, failed, score, device_age_days, login_count)
    if ml_adj > 0:
        factors[RiskFactor.ANOMALY_SCORE] = ml_adj
        score += ml_adj
        reasons.append(f"AI Anomaly Score: {round(ml_adj * 100)}% unusual pattern")

    score = min(1.0, score)

    # If no reasons were added, it means it's a completely normal login
    if not reasons:
        reasons.append("Standard login behavior")

    if score >= Config.RISK_THRESHOLD_BLOCK:
        action = "block"
        category = "High Risk"
    elif score >= Config.RISK_THRESHOLD_CHALLENGE:
        action = "OTP"
        category = "Medium Risk"
    else:
        action = "allow"
        category = "Low Risk"

    result = {
        "score": round(score, 4),
        "category": category,
        "reasons": reasons,
        "factors": factors,
        "action": action
    }
    _save_risk_score(user_id, device_fingerprint, result)
    return result


def _compute_device_switching(user_id: int, conn) -> float:
    """Count unique devices used in the last 24 hours (successful logins only)."""
    rows = conn.execute("""
        SELECT COUNT(DISTINCT device_fingerprint) as cnt
        FROM login_attempts
        WHERE user_id=? AND attempted_at > datetime('now', '-1 day')
          AND status='allow'
    """, (user_id,)).fetchone()

    if rows and rows["cnt"] > 2:
        return min(1.0, (rows["cnt"] - 2) / 5.0)
    return 0.0


def _detect_rapid_requests(user_id: int, conn) -> bool:
    """Return True if more than 5 attempts in the last 60 seconds."""
    row = conn.execute("""
        SELECT COUNT(*) as cnt FROM login_attempts
        WHERE user_id=? AND attempted_at > datetime('now', '-1 minute')
    """, (user_id,)).fetchone()
    return bool(row and row["cnt"] > 5)


def _check_new_ip(user_id: int, ip_address: str, conn) -> float:
    """Return 0.5 if this IP has never been seen on a successful login, 0 otherwise."""
    row = conn.execute("""
        SELECT COUNT(*) as cnt FROM login_attempts
        WHERE user_id=? AND ip_address=? AND status='allow'
    """, (user_id, ip_address)).fetchone()
    return 0.5 if (row and row["cnt"] == 0) else 0.0


def _save_risk_score(user_id: int, device_fingerprint: str, result: dict):
    """Persist the computed risk score to the risk_scores table."""
    conn = get_db()
    try:
        try:
            conn.execute("ALTER TABLE risk_scores ADD COLUMN category TEXT DEFAULT 'Low Risk'")
            conn.execute("ALTER TABLE risk_scores ADD COLUMN reasons TEXT")
        except Exception:
            pass  # Columns already exist

        device_id = None
        if device_fingerprint:
            dev = conn.execute(
                "SELECT id FROM devices WHERE device_fingerprint=?", (device_fingerprint,)
            ).fetchone()
            if dev:
                device_id = dev["id"]

        conn.execute(
            "INSERT INTO risk_scores (user_id, device_id, score, category, reasons, factors, action_taken) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, device_id, result["score"], result.get("category", "Low Risk"), json.dumps(result.get("reasons", [])), json.dumps(result["factors"]), result["action"]),
        )
        conn.commit()
    finally:
        conn.close()


def decay_trust_score(device_id: int, penalty: float = 0.1):
    """Reduce a device's trust score on suspicious activity."""
    conn = get_db()
    try:
        row = conn.execute("SELECT trust_score FROM devices WHERE id=?", (device_id,)).fetchone()
        if row:
            new_score = max(0.0, row["trust_score"] - penalty)
            conn.execute("UPDATE devices SET trust_score=? WHERE id=?", (new_score, device_id))
            conn.commit()
    finally:
        conn.close()


def boost_trust_score(device_id: int, boost: float = 0.05):
    """Increase a device's trust score on successful logins."""
    conn = get_db()
    try:
        row = conn.execute("SELECT trust_score FROM devices WHERE id=?", (device_id,)).fetchone()
        if row:
            new_score = min(1.0, row["trust_score"] + boost)
            conn.execute("UPDATE devices SET trust_score=? WHERE id=?", (new_score, device_id))
            conn.commit()
    finally:
        conn.close()


def get_risk_history(user_id: int, limit: int = 20):
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT r.*, d.device_name FROM risk_scores r
            LEFT JOIN devices d ON r.device_id = d.id
            WHERE r.user_id=?
            ORDER BY r.evaluated_at DESC LIMIT ?
        """, (user_id, limit)).fetchall()
        
        results = []
        for r in rows:
            rd = dict(r)
            try:
                rd["factors"] = json.loads(rd["factors"]) if rd["factors"] else {}
            except Exception:
                rd["factors"] = {}
            try:
                rd["reasons"] = json.loads(rd["reasons"]) if rd.get("reasons") else []
            except Exception:
                rd["reasons"] = []
            results.append(rd)
        return results
    finally:
        conn.close()
