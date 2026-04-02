"""
risk_engine.py
--------------
Calculates a risk score (0–100) from the permission labels and
observed activity, then maps it to a severity band and recommendation.

Scoring is additive — each matching condition adds points.
The final score is capped at 100.
"""

# ── Score weights ──────────────────────────────────────────────────────────────

# Points awarded per permission label found
PERMISSION_WEIGHTS: dict[str, int] = {
    "FULL_ACCESS":      60,
    "IAM_ACCESS":       40,
    "STS_ACCESS":       25,
    "SECRETS_ACCESS":   25,
    "KMS_ACCESS":       20,
    "EC2_ACCESS":       15,
    "S3_ACCESS":        15,
    "LAMBDA_ACCESS":    15,
    "RDS_ACCESS":       15,
    "DYNAMODB_ACCESS":  10,
}

# Points awarded per observed log action
ACTIVITY_WEIGHTS: dict[str, int] = {
    "iam:CreateUser":           30,
    "iam:AttachUserPolicy":     25,
    "iam:CreateAccessKey":      25,
    "sts:AssumeRole":           20,
    "s3:GetObject":             10,
    "s3:PutObject":             10,
    "s3:DeleteObject":          15,
    "ec2:RunInstances":         15,
    "secretsmanager:GetSecretValue": 20,
}

# ── Severity bands ─────────────────────────────────────────────────────────────

def _band(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


# ── Recommendations per band ───────────────────────────────────────────────────

RECOMMENDATIONS: dict[str, str] = {
    "CRITICAL": (
        "Disable this AWS access key immediately via the IAM console. "
        "Rotate all credentials in the account, audit CloudTrail for the "
        "past 90 days, and check for newly created IAM users or roles."
    ),
    "HIGH": (
        "Review and reduce the permissions attached to this key (apply "
        "least-privilege). Rotate the key within 24 hours and investigate "
        "recent CloudTrail activity for anomalies."
    ),
    "MEDIUM": (
        "Monitor CloudTrail for unusual activity from this key. Consider "
        "rotating it and restricting permissions to only what is required."
    ),
    "LOW": (
        "No immediate action required. Continue monitoring CloudTrail and "
        "rotate credentials routinely (every 90 days)."
    ),
}


# ── Public API ─────────────────────────────────────────────────────────────────

def calculate_risk(permissions: list[str], activity: list[str]) -> dict:
    """
    Return a dict with:
        - "score":          int  0-100
        - "level":          str  LOW / MEDIUM / HIGH / CRITICAL
        - "recommendation": str  plain-English action to take
    """
    score = 0

    # Add points for each permission label present
    for label in permissions:
        score += PERMISSION_WEIGHTS.get(label, 0)

    # Add points for each risky action observed in the logs
    for action in activity:
        score += ACTIVITY_WEIGHTS.get(action, 0)

    # Cap at 100
    score = min(score, 100)

    level = _band(score)

    return {
        "score": score,
        "level": level,
        "recommendation": RECOMMENDATIONS[level],
    }
