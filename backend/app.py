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

from ccrip_logger import get_logger
log = get_logger(__name__)

# Pipeline modules
from scanner              import scan_github_repo
from ingestion            import normalize_and_deduplicate
from validator            import validate_credential
from aws_connector        import get_user_policies
from permission_analyzer  import extract_permissions, get_resource_analysis
from cloudtrail_fetcher   import fetch_activity
from intelligence         import analyze_intelligence
from attack_engine        import simulate_attacks
from blast_radius         import calculate_blast_radius
from dependency_analyzer  import analyze_dependencies
from event_trigger        import evaluate_event_rules, extract_lambda_payload
from correlation          import correlate_credentials
from risk_engine          import calculate_risk
from decision_engine      import make_decision

# App setup
app = Flask(__name__)
CORS(app)

_RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _username_from_arn(arn: Optional[str]) -> Optional[str]:
    """Extract IAM username from arn:aws:iam::123:user/john-dev -> john-dev"""
    if not arn or ":user/" not in arn:
        return None
    return arn.split(":user/")[-1]


def _analyze_credential(access_key: str, secret_key: Optional[str], occurrences: list[dict]) -> dict:
    """Run the full analysis pipeline on a single credential."""
    safe_key = access_key[:8] + "..."
    log.info("[PIPELINE] Analyzing credential %s (has_secret=%s, occurrences=%d)",
             safe_key, bool(secret_key), len(occurrences))

    # ── Validation ────────────────────────────────────────────────────────────
    log.debug("[VALIDATE] Calling STS GetCallerIdentity for %s", safe_key)
    validation = validate_credential(access_key, secret_key)
    log.info("[VALIDATE] %s → status=%s", safe_key, validation['status'])

    # ── Enrichment: IAM policies ──────────────────────────────────────────────
    permissions: list[str] = []
    resource_analysis: list[dict] = []
    if validation["status"] == "ACTIVE" and secret_key:
        username = _username_from_arn(validation.get("arn"))
        if username:
            log.debug("[IAM] Fetching policies for user '%s' (%s)", username, safe_key)
            try:
                policy_docs = get_user_policies(access_key, secret_key, username)
                permissions       = extract_permissions(policy_docs)
                resource_analysis = get_resource_analysis(policy_docs)
                log.info("[IAM] %s permissions found: %s", safe_key, permissions)
            except ValueError as exc:
                log.warning("[IAM] Could not fetch policies for %s: %s", safe_key, exc)
                permissions = []
        else:
            log.warning("[IAM] Could not extract username from ARN for %s", safe_key)

    # ── Activity — real CloudTrail first, mock fallback ───────────────────────
    log.debug("[CLOUDTRAIL] Fetching activity for %s", safe_key)
    log_result = fetch_activity(access_key, secret_key)
    activity   = log_result["activity"]
    metadata   = log_result.get("metadata", [])   # IP, region, timestamps
    log_source = log_result["source"]
    log_note   = log_result["note"]
    log.info("[CLOUDTRAIL] %s → source=%s | %s", safe_key, log_source, log_note)

    # ── Event Trigger (simulates EventBridge + Lambda) ────────────────────────
    event_trigger  = evaluate_event_rules(activity)
    lambda_payload = extract_lambda_payload(access_key, validation, activity)

    # ── Intelligence Analysis + Anomaly Detection ─────────────────────────────
    intelligence = analyze_intelligence(activity, metadata)

    # ── Attack Simulation ─────────────────────────────────────────────────────
    attack_paths = simulate_attacks(permissions, activity)
    log.info("[ATTACK] %s → %d attack path(s): %s", safe_key, len(attack_paths),
             [a['attack'] for a in attack_paths])

    # ── Dependency Analysis ───────────────────────────────────────────────────
    dependency_analysis = analyze_dependencies(permissions, activity)

    # ── Blast Radius Calculation ──────────────────────────────────────────────
    blast_radius = calculate_blast_radius(permissions, activity)

    # ── Risk Engine: Permission + Activity + Anomaly + Blast Radius ───────────
    risk = calculate_risk(
        permissions,
        activity,
        anomalies=intelligence["anomalies"],
        blast_radius_score=blast_radius["score"],
    )
    log.info("[RISK] %s → score=%s level=%s breakdown=%s",
             safe_key, risk['score'], risk['level'], risk['score_breakdown'])

    # ── Adjust risk down for inactive credentials ─────────────────────────────
    if validation["status"] == "INACTIVE":
        risk["score"]          = max(10, risk["score"] - 30)
        risk["level"]          = "LOW" if risk["score"] < 15 else risk["level"]
        risk["recommendation"] = (
            "This key appears to be inactive or already revoked. "
            "Verify it is fully deleted and remove it from the codebase."
        )

    # ── Decision Engine ───────────────────────────────────────────────────────
    decision = make_decision(risk["level"], validation, attack_paths)

    return {
        "access_key":          access_key,
        "has_secret":          bool(secret_key),
        "occurrences":         occurrences,
        "validation":          validation,
        "permissions":         permissions,
        "resource_analysis":   resource_analysis,
        "log_source":          log_source,
        "log_note":            log_note,
        "activity":            activity,
        "intelligence":        intelligence,
        "event_trigger":       event_trigger,
        "lambda_payload":      lambda_payload,
        "attack_paths":        attack_paths,
        "dependency_analysis": dependency_analysis,
        "blast_radius":        blast_radius,
        "risk_score":          risk["score"],
        "risk_level":          risk["level"],
        "risk_breakdown":      risk["score_breakdown"],
        "recommendation":      risk["recommendation"],
        "decision":            decision,
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
        log.warning("[SCAN] Request rejected: missing repo_url")
        return jsonify({"error": "'repo_url' is required."}), 400

    if not repo_url.startswith("https://github.com/"):
        log.warning("[SCAN] Request rejected: invalid repo URL '%s'", repo_url)
        return jsonify({"error": "Only GitHub repositories are supported. URL must start with 'https://github.com/'."}), 400

    log.info("[SCAN] ===== New scan request: %s =====", repo_url)

    # Step 1: Scan
    try:
        scan_result = scan_github_repo(repo_url, github_token)
    except ValueError as exc:
        log.error("[SCAN] Scan failed (invalid input) for %s: %s", repo_url, exc)
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        log.error("[SCAN] Scan failed unexpectedly for %s: %s", repo_url, exc, exc_info=True)
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    # Step 2: Ingestion
    records = normalize_and_deduplicate(scan_result["credentials"])
    log.info("[SCAN] %s → files_scanned=%d, raw_findings=%d, unique_credentials=%d",
             repo_url, scan_result['files_scanned'], len(scan_result['credentials']), len(records))

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
    log.info("[SCAN] ===== Scan complete: %s | overall_risk=%s | active=%d/%d =====",
             repo_url, overall_risk, active_count, len(analyzed))

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
