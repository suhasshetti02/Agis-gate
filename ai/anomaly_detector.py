"""
Anomaly detection using Isolation Forest for Aegis-Gate.
Trained on historical login features; supplements the rule-based risk engine.
"""

import os
import pickle
import numpy as np
from db.database import get_db
from config import BASE_DIR

MODEL_DIR = BASE_DIR / "models"


def _extract_features_from_db(user_id: int):
    """Extract training/prediction feature rows from login history."""
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT
                strftime('%H', attempted_at) as hour,
                CASE WHEN status='allow' THEN 0 ELSE 1 END as failed,
                risk_score
            FROM login_attempts
            WHERE user_id=?
            ORDER BY attempted_at DESC LIMIT 200
        """, (user_id,)).fetchall()
    finally:
        conn.close()
    return rows


def build_feature_vector(hour: int, failed: int, risk_score: float,
                         device_age_days: float = 0.0, login_count: int = 0) -> np.ndarray:
    """Convert raw signals into a numeric feature vector."""
    hour_sin = np.sin(2 * np.pi * hour / 24)
    hour_cos = np.cos(2 * np.pi * hour / 24)
    return np.array([[
        hour_sin,
        hour_cos,
        float(failed),
        float(risk_score),
        min(device_age_days / 30.0, 1.0),
        min(login_count / 50.0, 1.0),
    ]])


def train_anomaly_model(user_id: int):
    """
    Train an Isolation Forest on a user's login history and save it to disk.
    Returns the trained model, or None if insufficient data / sklearn unavailable.
    """
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return None

    rows = _extract_features_from_db(user_id)
    if len(rows) < 10:
        return None  # Not enough data yet

    X = []
    for r in rows:
        hour   = int(r["hour"]) if r["hour"] else 12
        failed = int(r["failed"])
        risk   = float(r["risk_score"]) if r["risk_score"] else 0.0
        h_sin  = np.sin(2 * np.pi * hour / 24)
        h_cos  = np.cos(2 * np.pi * hour / 24)
        X.append([h_sin, h_cos, float(failed), risk, 0.0, 0.0])

    X     = np.array(X)
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(X)

    os.makedirs(MODEL_DIR, exist_ok=True)
    model_file = MODEL_DIR / f"anomaly_{user_id}.pkl"
    with open(model_file, "wb") as f:
        pickle.dump(model, f)

    return model


def predict_anomaly(user_id: int, feature_vector: np.ndarray) -> float:
    """
    Return anomaly score from 0 (normal) to 1 (anomalous).
    Uses per-user model if available; returns 0.0 when no model exists.
    """
    model_file = MODEL_DIR / f"anomaly_{user_id}.pkl"

    if not model_file.exists():
        return 0.0

    try:
        with open(model_file, "rb") as f:
            model = pickle.load(f)

        # IsolationForest: -1 = anomaly, 1 = normal
        score_raw     = model.score_samples(feature_vector)[0]
        # score_raw is typically in [-0.5, 0.5]; negate so higher = more anomalous
        anomaly_score = max(0.0, min(1.0, -score_raw))
        return round(anomaly_score, 4)

    except Exception:
        return 0.0


def get_ml_risk_adjustment(user_id: int, hour: int, failed: int,
                            risk_score: float, device_age_days: float,
                            login_count: int) -> float:
    """
    Run the ML anomaly detector and return a risk adjustment in [0, 0.3].
    """
    fv      = build_feature_vector(hour, failed, risk_score, device_age_days, login_count)
    anomaly = predict_anomaly(user_id, fv)
    return round(anomaly * 0.3, 4)
