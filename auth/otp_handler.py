"""
OTP generation and verification for device registration in Aegis-Gate.
"""

import secrets
import string
from datetime import datetime, timedelta
from db.database import get_db
from config import Config


def generate_otp(user_id: int, purpose: str = "device_registration") -> str:
    """Generate a 6-digit OTP, store it, and return the code."""
    otp_code = "".join(secrets.choice(string.digits) for _ in range(6))
    expires_at = datetime.utcnow() + timedelta(seconds=Config.OTP_VALIDITY_SECONDS)

    conn = get_db()
    try:
        # Invalidate any existing unused OTPs for this user/purpose
        conn.execute(
            "UPDATE otps SET used=1 WHERE user_id=? AND purpose=? AND used=0",
            (user_id, purpose),
        )

        conn.execute(
            """
            INSERT INTO otps (user_id, otp_code, purpose, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, otp_code, purpose, expires_at.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()

    return otp_code


def verify_otp(user_id: int, otp_code: str, purpose: str = "device_registration") -> tuple[bool, str]:
    """
    Verify an OTP:
    - Must match, belong to user, not be expired, and not be used.
    - Limits to 5 failed attempts per OTP.
    Returns (success, message).
    """
    conn = get_db()
    try:
        # Attempt to add failed_attempts column if it doesn't exist (migration)
        try:
            conn.execute("ALTER TABLE otps ADD COLUMN failed_attempts INTEGER DEFAULT 0")
        except Exception:
            pass  # Column likely already exists

        # Fetch the latest active OTP for this user/purpose
        row = conn.execute(
            """
            SELECT id, otp_code, expires_at, used, failed_attempts FROM otps
            WHERE user_id=? AND purpose=? AND used=0
            ORDER BY created_at DESC LIMIT 1
            """,
            (user_id, purpose),
        ).fetchone()

        if not row:
            return False, "Invalid or expired OTP."

        otp_id = row["id"]
        correct_code = row["otp_code"]
        failed_attempts = row["failed_attempts"] if "failed_attempts" in row.keys() else 0

        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.utcnow() > expires_at:
            return False, "OTP has expired."

        if failed_attempts >= 5:
            # Locked out due to too many failed attempts
            return False, "Too many failed attempts. Please login again to request a new OTP."

        import secrets
        if not secrets.compare_digest(correct_code, otp_code):
            failed_attempts += 1
            if failed_attempts >= 5:
                # Lock it
                conn.execute("UPDATE otps SET failed_attempts=?, used=1 WHERE id=?", (failed_attempts, otp_id))
                conn.commit()
                return False, "Too many failed attempts. Please login again to request a new OTP."
            else:
                conn.execute("UPDATE otps SET failed_attempts=? WHERE id=?", (failed_attempts, otp_id))
                conn.commit()
                return False, f"Incorrect OTP. {5 - failed_attempts} attempts remaining."

        # Success!
        conn.execute("UPDATE otps SET used=1 WHERE id=?", (otp_id,))
        conn.commit()
    finally:
        conn.close()

    return True, "OTP verified successfully."


def deliver_otp(user_id: int, username: str, user_email: str, otp_code: str, purpose: str = "device_registration") -> bool:
    """
    Send OTP via real email using SMTP.
    Logs the generation and delivery status to audit log.
    """
    from utils.email_service import EmailService
    from utils.logger import log_audit
    
    # Log Generation
    log_audit(user_id, "otp_generated", f"purpose={purpose}")
    
    success = EmailService.send_otp_email(username, user_email, otp_code)
    status = "Delivered" if success else "Failed"
    
    # Log Sent
    log_audit(user_id, "otp_sent", f"email={user_email} | status={status}")
    
    # Fallback log (for debugging and local delivery)
    try:
        with open("logs/otp_delivery.log", "a") as f:
            f.write(f"[{datetime.utcnow().isoformat()}] OTP for {user_email}: {otp_code}\n")
    except Exception:
        pass
    
    return success
