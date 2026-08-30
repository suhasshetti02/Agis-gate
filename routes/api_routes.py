"""
API routes for device verification and nonce requesting.
"""

from flask import Blueprint, request, jsonify, session
from auth.nonce_handler import generate_nonce
from auth.device_registry import get_device_by_fingerprint
from config import Config

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/request-nonce", methods=["POST"])
def request_nonce():
    """Issue a nonce for a device fingerprint during challenge-response."""
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400
        
    device_fp = data.get("device_fingerprint", "")
    if not device_fp or not isinstance(device_fp, str) or len(device_fp) > 256:
        return jsonify({"error": "Invalid or missing device_fingerprint"}), 400

    user_id = session.get("challenge_user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    device = get_device_by_fingerprint(device_fp)
    if not device:
        return jsonify({"error": "Unknown device"}), 404

    nonce = generate_nonce(user_id, device_fp, "auth")
    return jsonify({"nonce": nonce})


@api_bp.route("/device-status", methods=["POST"])
def device_status():
    """Check if a device fingerprint is registered."""
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400
        
    device_fp = data.get("device_fingerprint", "")
    if not device_fp or not isinstance(device_fp, str) or len(device_fp) > 256:
        return jsonify({"error": "Invalid or missing device_fingerprint"}), 400
        
    device = get_device_by_fingerprint(device_fp)

    if not device:
        return jsonify({"registered": False})

    return jsonify({
        "registered": True,
        "trusted": bool(device["is_trusted"]),
        "blocked": bool(device["is_blocked"]),
        "trust_score": device["trust_score"]
    }), 200

@api_bp.route("/health", methods=["GET"])
def health_check():
    """Liveness probe: checks if the application is running."""
    return jsonify({"status": "healthy"}), 200

@api_bp.route("/readiness", methods=["GET"])
def readiness_check():
    """Readiness probe: checks if dependencies (DB, ML) are available."""
    from db.database import get_db
    status = {"db": "unavailable"}
    code = 503
    
    try:
        conn = get_db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        status["db"] = "available"
        code = 200
    except Exception as e:
        status["error"] = str(e)
        
    status["overall"] = "ready" if code == 200 else "not_ready"
    return jsonify(status), code
