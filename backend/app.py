"""
app.py
------
Flask entry-point for the Cloud Credential Risk Intelligence Platform.

Single endpoint:  POST /analyze
    Accepts an AWS access key, secret key, and IAM username.
    Returns a JSON report covering permissions, observed activity,
    possible attack paths, risk level, and a remediation recommendation.
"""

import json
import os

from flask import Flask, request, jsonify
from flask_cors import CORS

from aws_connector import get_user_policies
from permission_analyzer import extract_permissions
from attack_engine import simulate_attacks
from risk_engine import calculate_risk

# ── App setup ──────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)  # Allow requests from the frontend HTML file

# Load mock activity logs once at startup (avoids repeated disk reads)
_MOCK_LOGS_PATH = os.path.join(os.path.dirname(__file__), "mock_logs.json")

with open(_MOCK_LOGS_PATH, encoding="utf-8") as _f:
    MOCK_ACTIVITY: list[str] = json.load(_f)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.post("/analyze")
def analyze():
    """
    POST /analyze
    -------------
    Request body (JSON):
        {
            "access_key": "AKIA...",
            "secret_key": "...",
            "username":   "john-dev"
        }

    Response (JSON):
        {
            "permissions":      ["IAM_ACCESS", "S3_ACCESS"],
            "activity":         ["s3:ListBucket", "iam:CreateUser"],
            "attack_paths":     [{"attack": "...", "description": "..."}],
            "risk_score":       85,
            "risk_level":       "CRITICAL",
            "recommendation":   "Disable this key immediately ..."
        }
    """
    body = request.get_json(silent=True)

    # ── Input validation ───────────────────────────────────────────────────────
    if not body:
        return jsonify({"error": "Request body must be JSON."}), 400

    access_key = (body.get("access_key") or "").strip()
    secret_key = (body.get("secret_key") or "").strip()
    username   = (body.get("username")   or "").strip()

    if not access_key or not secret_key or not username:
        return jsonify({
            "error": "Fields 'access_key', 'secret_key', and 'username' are all required."
        }), 400

    # Basic sanity check — AWS access keys always start with "AKIA" or "ASIA"
    if not (access_key.startswith("AKIA") or access_key.startswith("ASIA")):
        return jsonify({
            "error": "The access_key does not look like a valid AWS access key."
        }), 400

    # ── Step 1: Fetch IAM policies from AWS ────────────────────────────────────
    try:
        policy_documents = get_user_policies(access_key, secret_key, username)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 401

    # ── Step 2: Convert policies to permission labels ──────────────────────────
    permissions = extract_permissions(policy_documents)

    # ── Step 3: Use mock logs as the activity feed ────────────────────────────
    activity = MOCK_ACTIVITY

    # ── Step 4: Simulate attack paths ─────────────────────────────────────────
    attack_paths = simulate_attacks(permissions, activity)

    # ── Step 5: Calculate risk ─────────────────────────────────────────────────
    risk = calculate_risk(permissions, activity)

    # ── Step 6: Build and return the response ─────────────────────────────────
    return jsonify({
        "permissions":    permissions,
        "activity":       activity,
        "attack_paths":   attack_paths,
        "risk_score":     risk["score"],
        "risk_level":     risk["level"],
        "recommendation": risk["recommendation"],
    }), 200


@app.get("/health")
def health():
    """Simple liveness check — useful for smoke-testing the server."""
    return jsonify({"status": "ok"}), 200


# ── Dev server ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # debug=True is fine for local development; never use it in production
    app.run(debug=True, host="127.0.0.1", port=5000)
