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
    device_fp = data.get("device_fingerprint", "")
    user_id = session.get("challenge_user_id")

    if not device_fp:
        return jsonify({"error": "device_fingerprint required"}), 400

    device = get_device_by_fingerprint(device_fp)
    if not device:
        return jsonify({"error": "Unknown device"}), 404

    nonce = generate_nonce(user_id, device_fp, "auth")
    return jsonify({"nonce": nonce})


@api_bp.route("/device-status", methods=["POST"])
def device_status():
    """Check if a device fingerprint is registered."""
    data = request.get_json()
    device_fp = data.get("device_fingerprint", "")
    device = get_device_by_fingerprint(device_fp)

    if not device:
        return jsonify({"registered": False})

    return jsonify({
        "registered": True,
        "trusted": bool(device["is_trusted"]),
        "blocked": bool(device["is_blocked"]),
        "trust_score": device["trust_score"]
    })
