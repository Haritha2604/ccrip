"""
risk_engine.py
--------------
RISK ENGINE — Computes the final risk score using the formula from the
flowchart:

    Risk Score = Permission Score + Activity Score + Anomaly Score + Blast Radius Score

Each component is capped independently, then summed (max 100):

  Component             Max   What it measures
  ─────────────────────────────────────────────────────────────────────
  Permission Score       40   Which IAM permissions the key carries
  Activity Score         25   Which risky API actions were observed
  Anomaly Score          15   How many behavioural anomalies were detected
  Blast Radius Score     20   Imported directly from blast_radius.py
  ─────────────────────────────────────────────────────────────────────
  TOTAL                 100
"""

from ccrip_logger import get_logger
log = get_logger(__name__)

# ── Component 1 — Permission weights (max 40 per credential) ─────────────────

PERMISSION_WEIGHTS: dict[str, int] = {
    "FULL_ACCESS":     40,
    "IAM_ACCESS":      34,
    "STS_ACCESS":      22,
    "SECRETS_ACCESS":  22,
    "KMS_ACCESS":      18,
    "EC2_ACCESS":      14,
    "S3_ACCESS":       14,
    "LAMBDA_ACCESS":   14,
    "RDS_ACCESS":      12,
    "DYNAMODB_ACCESS":  8,
}

# ── Component 2 — Activity weights (max 25, summed then capped) ───────────────

ACTIVITY_WEIGHTS: dict[str, int] = {
    "iam:CreateUser":                30,   # will be capped at 25
    "iam:AttachUserPolicy":          22,
    "iam:CreateAccessKey":           22,
    "sts:AssumeRole":                18,
    "secretsmanager:GetSecretValue": 18,
    "s3:DeleteObject":               14,
    "ec2:RunInstances":              14,
    "s3:GetObject":                   8,
    "s3:PutObject":                   8,
}

_ACTIVITY_CAP = 25

# ── Component 3 — Anomaly weights (5 points each, max 15) ────────────────────

_ANOMALY_POINTS_EACH = 5
_ANOMALY_CAP         = 15

# ── Component 4 — Blast Radius cap ───────────────────────────────────────────

_BLAST_CAP = 20

# ── Severity bands ─────────────────────────────────────────────────────────────

def _band(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


# ── Recommendations ────────────────────────────────────────────────────────────

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

def calculate_risk(
    permissions:        list[str],
    activity:           list[str],
    anomalies:          list[str] | None = None,
    blast_radius_score: int = 0,
) -> dict:
    """
    Calculate risk using the 4-component formula:
        Risk = Permission + Activity + Anomaly + Blast Radius

    Args:
        permissions:        Labels from permission_analyzer.extract_permissions()
        activity:           Actions from cloudtrail_fetcher.fetch_activity()
        anomalies:          Anomaly strings from intelligence.analyze_intelligence()
        blast_radius_score: Score (0-20) from blast_radius.calculate_blast_radius()

    Returns:
        {
            "score":              int  0-100,
            "level":              str  LOW / MEDIUM / HIGH / CRITICAL,
            "recommendation":     str,
            "score_breakdown": {
                "permission":    int,
                "activity":      int,
                "anomaly":       int,
                "blast_radius":  int,
            }
        }
    """
    anomalies = anomalies or []

    # ── Component 1: Permission score ─────────────────────────────────────────
    perm_score = min(
        sum(PERMISSION_WEIGHTS.get(label, 0) for label in permissions),
        40,
    )

    # ── Component 2: Activity score ───────────────────────────────────────────
    act_score = min(
        sum(ACTIVITY_WEIGHTS.get(action, 0) for action in activity),
        _ACTIVITY_CAP,
    )

    # ── Component 3: Anomaly score ────────────────────────────────────────────
    anom_score = min(len(anomalies) * _ANOMALY_POINTS_EACH, _ANOMALY_CAP)

    # ── Component 4: Blast radius score ───────────────────────────────────────
    br_score = min(blast_radius_score, _BLAST_CAP)

    total = perm_score + act_score + anom_score + br_score
    total = min(total, 100)

    level = _band(total)

    log.info(
        "[RISK] score=%d level=%s | perm=%d activity=%d anomaly=%d blast=%d",
        total, level, perm_score, act_score, anom_score, br_score,
    )

    return {
        "score":          total,
        "level":          level,
        "recommendation": RECOMMENDATIONS[level],
        "score_breakdown": {
            "permission":   perm_score,
            "activity":     act_score,
            "anomaly":      anom_score,
            "blast_radius": br_score,
        },
    }
