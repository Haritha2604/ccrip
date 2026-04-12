"""
blast_radius.py
---------------
BLAST RADIUS CALCULATION — Core feature of the CCRIP pipeline.

Estimates the total damage potential of a leaked credential by answering:
  "If an attacker used this key, how many AWS services and resources
   could they reach, and how severe is the impact?"

Inputs:
  - permissions: list of labels from permission_analyzer.py
  - activity:    list of observed API actions from cloudtrail_fetcher.py

Output:
  {
    "level":             "LOW" | "MEDIUM" | "HIGH",
    "score":             int (0-20),   -- fed into risk_engine.py
    "services_affected": [str],        -- AWS services reachable
    "resource_types":    [str],        -- specific resource types accessible
    "permission_level":  str,          -- plain-English capability summary
  }
"""

from ccrip_logger import get_logger
log = get_logger(__name__)

# ── Resource type map: permission label → affected AWS resources ──────────────

_RESOURCE_MAP: dict[str, list[str]] = {
    "FULL_ACCESS":     [
        "All IAM Identities", "All S3 Buckets", "All EC2 Instances",
        "All RDS Databases", "All Lambda Functions", "All AWS Services",
    ],
    "IAM_ACCESS":      [
        "IAM Users", "IAM Roles", "IAM Policies", "AWS Console Access",
        "Access Keys (create/delete)",
    ],
    "S3_ACCESS":       ["S3 Buckets", "S3 Objects (files/data)"],
    "EC2_ACCESS":      [
        "EC2 Instances", "Security Groups", "VPCs", "AMIs", "Key Pairs",
    ],
    "LAMBDA_ACCESS":   ["Lambda Functions", "Lambda Event Triggers", "Function Code"],
    "STS_ACCESS":      ["IAM Roles (via AssumeRole)", "Temporary Session Credentials"],
    "SECRETS_ACCESS":  [
        "AWS Secrets Manager entries", "SSM Parameter Store values",
        "Database passwords", "Third-party API keys",
    ],
    "KMS_ACCESS":      ["KMS Encryption Keys", "Encrypted S3 data", "Encrypted RDS data"],
    "RDS_ACCESS":      ["RDS Database instances", "RDS Snapshots", "Database contents"],
    "DYNAMODB_ACCESS": ["DynamoDB Tables", "DynamoDB Item data"],
}

# ── Blast radius score per permission label (0–20 scale) ─────────────────────

_BLAST_WEIGHTS: dict[str, int] = {
    "FULL_ACCESS":     20,
    "IAM_ACCESS":      18,
    "STS_ACCESS":      14,
    "SECRETS_ACCESS":  14,
    "KMS_ACCESS":      12,
    "EC2_ACCESS":      10,
    "S3_ACCESS":       10,
    "LAMBDA_ACCESS":   10,
    "RDS_ACCESS":       8,
    "DYNAMODB_ACCESS":  6,
}

# ── Permission level labels ───────────────────────────────────────────────────

def _permission_level(permissions: list[str]) -> str:
    if "FULL_ACCESS" in permissions:
        return "Administrator — unrestricted access to all AWS services"
    if "IAM_ACCESS" in permissions:
        return "High — IAM control enables escalation to Administrator"
    if any(p in permissions for p in ("SECRETS_ACCESS", "KMS_ACCESS", "STS_ACCESS")):
        return "Medium-High — access to sensitive data and credential services"
    if any(p in permissions for p in ("S3_ACCESS", "EC2_ACCESS", "LAMBDA_ACCESS", "RDS_ACCESS")):
        return "Medium — access to compute and storage services"
    if permissions:
        return "Low — limited access scope"
    return "None — no IAM permissions retrieved"


# ── Public API ────────────────────────────────────────────────────────────────

def calculate_blast_radius(permissions: list[str], activity: list[str]) -> dict:
    """
    Calculate blast radius for a credential.

    Returns:
        {
            "level":             "LOW" | "MEDIUM" | "HIGH",
            "score":             int (0-20),
            "services_affected": list[str],
            "resource_types":    list[str],
            "permission_level":  str,
        }
    """
    if not permissions:
        log.debug("[BLAST] No permissions — blast radius is LOW (score=0)")
        return {
            "level":             "LOW",
            "score":             0,
            "services_affected": [],
            "resource_types":    [],
            "permission_level":  "None — no IAM permissions retrieved",
        }

    # Highest single-label score drives the blast score (not additive)
    # because blast radius means "worst-case reach", not accumulation
    score = min(max(_BLAST_WEIGHTS.get(p, 0) for p in permissions), 20)

    # Derive affected services from permission labels
    services: set[str] = set()
    for p in permissions:
        service = p.replace("_ACCESS", "").replace("FULL", "ALL SERVICES").title()
        services.add(service)

    # Collect all affected resource types
    resource_types: set[str] = set()
    for p in permissions:
        resource_types.update(_RESOURCE_MAP.get(p, []))

    # Factor in activity: if attacker already touched extra services, add them
    for action in activity:
        if ":" in action:
            svc = action.split(":")[0].upper()
            services.add(svc)

    # Level band
    if score >= 14:
        level = "HIGH"
    elif score >= 8:
        level = "MEDIUM"
    else:
        level = "LOW"

    perm_level = _permission_level(permissions)

    log.info("[BLAST] score=%d level=%s services=%d resource_types=%d",
             score, level, len(services), len(resource_types))

    return {
        "level":             level,
        "score":             score,
        "services_affected": sorted(services),
        "resource_types":    sorted(resource_types),
        "permission_level":  perm_level,
    }
