"""
app.py
------
Flask entry-point for the Cloud Credential Risk Intelligence Platform (CCRIP).

Endpoints:
    POST /scan     -- New primary endpoint: scan a GitHub repo for leaked credentials
    POST /analyze  -- Legacy: manual credential input (kept for backward compatibility)
    GET  /health   -- Liveness check
"""

import json
import os
from typing import Optional

from flask import Flask, request, jsonify
from flask_cors import CORS

# Pipeline modules
from scanner            import scan_github_repo
from ingestion          import normalize_and_deduplicate
from validator          import validate_credential
from aws_connector      import get_user_policies
from permission_analyzer import extract_permissions
from intelligence       import analyze_intelligence
from attack_engine      import simulate_attacks
from correlation        import correlate_credentials
from risk_engine        import calculate_risk
from decision_engine    import make_decision

# App setup
app = Flask(__name__)
CORS(app)

# Load mock CloudTrail activity once at startup
_LOGS_PATH = os.path.join(os.path.dirname(__file__), "mock_logs.json")
with open(_LOGS_PATH, encoding="utf-8") as _f:
    MOCK_ACTIVITY: list[str] = json.load(_f)

_RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _username_from_arn(arn: Optional[str]) -> Optional[str]:
    """Extract IAM username from arn:aws:iam::123:user/john-dev -> john-dev"""
    if not arn or ":user/" not in arn:
        return None
    return arn.split(":user/")[-1]


def _analyze_credential(access_key: str, secret_key: Optional[str], occurrences: list[dict]) -> dict:
    """Run the full analysis pipeline on a single credential."""

    # Validation
    validation = validate_credential(access_key, secret_key)

    # Enrichment (IAM policies, only for ACTIVE credentials)
    permissions: list[str] = []
    if validation["status"] == "ACTIVE" and secret_key:
        username = _username_from_arn(validation.get("arn"))
        if username:
            try:
                policy_docs = get_user_policies(access_key, secret_key, username)
                permissions = extract_permissions(policy_docs)
            except ValueError:
                permissions = []

    # Activity (mock CloudTrail)
    activity = MOCK_ACTIVITY

    # Intelligence Analysis
    intelligence = analyze_intelligence(activity)

    # Attack Simulation
    attack_paths = simulate_attacks(permissions, activity)

    # Risk Scoring
    risk = calculate_risk(permissions, activity)

    # Adjust risk down for inactive credentials
    if validation["status"] == "INACTIVE":
        risk["score"]          = max(10, risk["score"] - 30)
        risk["level"]          = "LOW" if risk["score"] < 15 else risk["level"]
        risk["recommendation"] = (
            "This key appears to be inactive or already revoked. "
            "Verify it is fully deleted and remove it from the codebase."
        )

    # Decision
    decision = make_decision(risk["level"], validation, attack_paths)

    return {
        "access_key":     access_key,
        "has_secret":     bool(secret_key),
        "occurrences":    occurrences,
        "validation":     validation,
        "permissions":    permissions,
        "activity":       activity,
        "intelligence":   intelligence,
        "attack_paths":   attack_paths,
        "risk_score":     risk["score"],
        "risk_level":     risk["level"],
        "recommendation": risk["recommendation"],
        "decision":       decision,
    }


@app.post("/scan")
def scan():
    """
    POST /scan
    Input:  { "repo_url": "https://github.com/owner/repo", "github_token": "..." }
    Output: Full risk intelligence report for all leaked credentials found.
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON."}), 400

    repo_url     = (body.get("repo_url")     or "").strip()
    github_token = (body.get("github_token") or "").strip() or None

    if not repo_url:
        return jsonify({"error": "'repo_url' is required."}), 400

    if not repo_url.startswith("https://github.com/"):
        return jsonify({"error": "Only GitHub repositories are supported. URL must start with 'https://github.com/'."}), 400

    # Step 1: Scan
    try:
        scan_result = scan_github_repo(repo_url, github_token)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    # Step 2: Ingestion
    records = normalize_and_deduplicate(scan_result["credentials"])

    # Steps 3-10: Analyze each credential
    analyzed: list[dict] = []
    for record in records:
        result = _analyze_credential(
            access_key=record.access_key,
            secret_key=record.secret_key,
            occurrences=record.occurrences,
        )
        analyzed.append(result)

    # Step 11: Correlation
    correlation = correlate_credentials(analyzed)

    # Overall risk
    overall_risk = "LOW"
    for cred in analyzed:
        level = cred["risk_level"]
        if _RISK_ORDER.index(level) > _RISK_ORDER.index(overall_risk):
            overall_risk = level

    active_count = sum(1 for c in analyzed if c["validation"]["status"] == "ACTIVE")

    return jsonify({
        "repo": repo_url,
        "scan_summary": {
            "branch":             scan_result["branch"],
            "files_scanned":      scan_result["files_scanned"],
            "credentials_found":  len(records),
            "active_credentials": active_count,
        },
        "overall_risk": overall_risk,
        "credentials":  analyzed,
        "correlation":  correlation,
    }), 200


@app.post("/analyze")
def analyze():
    """Legacy endpoint - manual credential input."""
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON."}), 400

    access_key = (body.get("access_key") or "").strip()
    secret_key = (body.get("secret_key") or "").strip()
    username   = (body.get("username")   or "").strip()

    if not access_key or not secret_key or not username:
        return jsonify({"error": "Fields 'access_key', 'secret_key', and 'username' are required."}), 400

    if not (access_key.startswith("AKIA") or access_key.startswith("ASIA")):
        return jsonify({"error": "The access_key does not look like a valid AWS access key."}), 400

    try:
        policy_docs = get_user_policies(access_key, secret_key, username)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 401

    permissions  = extract_permissions(policy_docs)
    activity     = MOCK_ACTIVITY
    attack_paths = simulate_attacks(permissions, activity)
    risk         = calculate_risk(permissions, activity)

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
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
