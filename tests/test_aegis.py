import unittest
import os
import json
import time
from datetime import datetime, timedelta
import tempfile
from unittest.mock import patch, MagicMock

# Set environment variables for testing before importing the app
os.environ["SECRET_KEY"] = "test_secret_key_1234567890abcdef"
os.environ["ADMIN_PASSWORD"] = "TestAdmin@123"

from app import create_app
from db.database import init_db, get_db
from config import Config
from auth.device_registry import register_device, get_user_device_count
from auth.otp_handler import generate_otp, verify_otp
from auth.nonce_handler import generate_nonce, validate_nonce
from auth.rsa_handler import verify_signature
from auth.session_manager import create_session, validate_session
from ai.risk_engine import compute_risk_score
from werkzeug.security import generate_password_hash

class AegisGateTestCase(unittest.TestCase):
    def setUp(self):
        # Create a temporary database file
        self.db_fd, self.db_path = tempfile.mkstemp()
        Config.DATABASE_PATH = Path(self.db_path)
        
        self.app = create_app()
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Initialize the database
        init_db()
        
        # Add a test user
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                ("testuser", "test@aegis.local", generate_password_hash("password123", method="pbkdf2:sha256"))
            )
            conn.commit()
            self.user_id = conn.execute("SELECT id FROM users WHERE username='testuser'").fetchone()["id"]
        finally:
            conn.close()

    def tearDown(self):
        self.app_context.pop()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    # 1. Test Password Auth (simulated via db check)
    def test_password_auth(self):
        from werkzeug.security import check_password_hash
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username='testuser'").fetchone()
        conn.close()
        
        self.assertIsNotNone(user)
        self.assertTrue(check_password_hash(user["password_hash"], "password123"))
        self.assertFalse(check_password_hash(user["password_hash"], "wrongpassword"))

    # 2. Test OTP Verification
    def test_otp_verification(self):
        otp = generate_otp(self.user_id, "test_purpose")
        self.assertIsNotNone(otp)
        
        # Correct OTP
        success, msg = verify_otp(self.user_id, otp, "test_purpose")
        self.assertTrue(success)
        
        # Already used OTP
        success, msg = verify_otp(self.user_id, otp, "test_purpose")
        self.assertFalse(success)
        
        # Wrong OTP
        otp2 = generate_otp(self.user_id, "test_purpose")
        success, msg = verify_otp(self.user_id, "000000", "test_purpose")
        self.assertFalse(success)

    # 3. Test Nonce Expiry
    def test_nonce_expiry(self):
        nonce = generate_nonce(self.user_id, "device_fp_123", "auth")
        self.assertTrue(validate_nonce(nonce, "auth"))
        
        # Verify it can only be used once
        self.assertFalse(validate_nonce(nonce, "auth"))
        
        # Test expiration manually by modifying DB
        nonce2 = generate_nonce(self.user_id, "device_fp_123", "auth")
        conn = get_db()
        past_time = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
        conn.execute("UPDATE nonces SET expires_at=? WHERE nonce=?", (past_time, nonce2))
        conn.commit()
        conn.close()
        
        self.assertFalse(validate_nonce(nonce2, "auth"))

    # 4. Test RSA Verification (using a dummy signature logic or the real one if keys are known)
    def test_rsa_verification(self):
        # We can test the failure case easily
        self.assertFalse(verify_signature("bad_key", "challenge_data", "bad_signature"))

    # 5. Test Device Limit
    def test_device_limit(self):
        # Register 2 devices (MAX_DEVICES_PER_USER is 2)
        register_device(self.user_id, "Device 1", "fp1", "pk1")
        register_device(self.user_id, "Device 2", "fp2", "pk2")
        
        self.assertEqual(get_user_device_count(self.user_id), 2)
        
        # Trying to register a 3rd device should raise ValueError
        with self.assertRaises(ValueError):
            register_device(self.user_id, "Device 3", "fp3", "pk3")

    # 6. Test Session Validation
    def test_session_validation(self):
        device = register_device(self.user_id, "Device 1", "fp1", "pk1")
        token = create_session(self.user_id, device["id"], "127.0.0.1", "TestAgent", trusted=True)
        
        session_data = validate_session(token)
        self.assertIsNotNone(session_data)
        self.assertEqual(session_data["user_id"], self.user_id)
        
        # Invalid token
        self.assertIsNone(validate_session("invalid_token"))

    # 7. Test Risk Scoring
    def test_risk_scoring(self):
        # Baseline risk
        risk = compute_risk_score(self.user_id, device_fingerprint="unknown_fp", ip_address="127.0.0.1", user_agent="TestAgent")
        self.assertGreater(risk["score"], 0)
        self.assertIn("Unrecognized new device", risk["reasons"])
        
        # Test failed attempts risk
        conn = get_db()
        conn.execute("UPDATE users SET failed_attempts=4 WHERE id=?", (self.user_id,))
        conn.commit()
        conn.close()
        
        risk2 = compute_risk_score(self.user_id, device_fingerprint="unknown_fp", ip_address="127.0.0.1", user_agent="TestAgent")
        self.assertGreater(risk2["score"], risk["score"])

    # 8. Test Network Controller
    def test_network_allocation(self):
        from network.network_controller import SimulatedNetworkController, NetworkAllocationError
        
        # Create a device and a session to satisfy foreign keys
        device = register_device(self.user_id, "NetDevice", "net_fp", "net_pk")
        device_id = device["id"]
        
        # Insert a fake session to satisfy session_id FK
        conn = get_db()
        conn.execute(
            "INSERT INTO sessions (user_id, device_id, session_token, expires_at) VALUES (?, ?, ?, ?)",
            (self.user_id, device_id, "net_session_1", "2030-01-01T00:00:00")
        )
        session1_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        conn.execute(
            "INSERT INTO sessions (user_id, device_id, session_token, expires_at) VALUES (?, ?, ?, ?)",
            (self.user_id, device_id, "net_session_2", "2030-01-01T00:00:00")
        )
        session2_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
        conn.close()
        
        # Test basic allocation
        alloc1 = SimulatedNetworkController.allocate_network(session_id=session1_id, user_id=self.user_id, device_id=device_id, is_admin=False)
        self.assertEqual(alloc1["status"], "allocated")
        self.assertEqual(alloc1["vlan_id"], SimulatedNetworkController.VLAN_USER)
        self.assertIsNotNone(alloc1["ip_address"])
        
        # Test duplicate session allocation returns existing
        alloc1_dup = SimulatedNetworkController.allocate_network(session_id=session1_id, user_id=self.user_id, device_id=device_id, is_admin=False)
        self.assertEqual(alloc1_dup["ip_address"], alloc1["ip_address"])
        
        # Test admin VLAN
        alloc2 = SimulatedNetworkController.allocate_network(session_id=session2_id, user_id=self.user_id, device_id=device_id, is_admin=True)
        self.assertEqual(alloc2["vlan_id"], SimulatedNetworkController.VLAN_ADMIN)
        self.assertNotEqual(alloc1["ip_address"], alloc2["ip_address"])
        
        # Test release
        SimulatedNetworkController.release_network(session_id=session1_id)
        conn = get_db()
        row = conn.execute("SELECT status FROM network_allocations WHERE session_id=?", (session1_id,)).fetchone()
        conn.close()
        self.assertEqual(row["status"], "released")


    # 9. Test OTP Brute Force Limits
    def test_otp_brute_force_lockout(self):
        otp = generate_otp(self.user_id, "bruteforce_test")
        
        # Fail 4 times
        for _ in range(4):
            success, msg = verify_otp(self.user_id, "000000", "bruteforce_test")
            self.assertFalse(success)
            
        # 5th attempt should lock out and return lockout message
        success, msg = verify_otp(self.user_id, "000000", "bruteforce_test")
        self.assertFalse(success)
        self.assertIn("Too many failed attempts", msg)
        
        # 6th attempt with correct code should fail because OTP was marked as used/locked
        success, msg = verify_otp(self.user_id, otp, "bruteforce_test")
        self.assertFalse(success)

from pathlib import Path
if __name__ == '__main__':
    unittest.main()
