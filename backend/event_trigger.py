"""
event_trigger.py
----------------
EVENT TRIGGER LAYER — Simulates Amazon EventBridge + AWS Lambda behavior.

In a production CCRIP deployment:
  1. AWS CloudTrail streams all API events to Amazon EventBridge in real time
  2. EventBridge rules filter events matching suspicious patterns
  3. Matching events trigger an AWS Lambda function (the "execution layer")
  4. Lambda extracts the AccessKeyId and sends a structured payload to the
     analysis pipeline backend

This module simulates that behaviour locally so the architecture matches
the production design without requiring real AWS infrastructure.

EventBridge rules implemented:
  RULE-001  Sensitive IAM action detected
  RULE-002  Data exfiltration pattern detected
  RULE-003  Privilege escalation sequence (create user + attach policy)
  RULE-004  High-frequency API calls (>10 unique actions in one session)
  RULE-005  Cross-service lateral movement (≥3 different AWS services)
"""

from ccrip_logger import get_logger
log = get_logger(__name__)

# ── EventBridge rule definitions ──────────────────────────────────────────────

_SENSITIVE_IAM_ACTIONS: set[str] = {
    "iam:CreateUser", "iam:CreateAccessKey",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy",
    "iam:CreateRole", "iam:AddUserToGroup", "iam:UpdateLoginProfile",
}

_EXFILTRATION_ACTIONS: set[str] = {
    "s3:GetObject", "s3:CopyObject",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "ssm:GetParameter", "ssm:GetParameters",
    "dynamodb:Scan", "dynamodb:GetItem",
    "rds:CreateDBSnapshot",
}

_ESCALATION_PAIR: tuple[str, str] = ("iam:CreateUser", "iam:AttachUserPolicy")

_HIGH_FREQ_THRESHOLD = 10     # unique actions before RULE-004 fires
_LATERAL_SVC_THRESHOLD = 3    # distinct AWS services before RULE-005 fires


# ── Public API ────────────────────────────────────────────────────────────────

def evaluate_event_rules(activity: list[str]) -> dict:
    """
    Apply EventBridge-style filtering rules to observed activity.

    Args:
        activity: List of "service:ActionName" strings from cloudtrail_fetcher

    Returns:
        {
            "triggered_rules":         [{"rule_id", "name", "description"}],
            "should_trigger_pipeline": bool,
            "trigger_reason":          str,
        }
    """
    activity_set = set(activity)
    triggered: list[dict] = []

    # RULE-001: Sensitive IAM action
    matched_iam = activity_set & _SENSITIVE_IAM_ACTIONS
    if matched_iam:
        triggered.append({
            "rule_id":     "RULE-001",
            "name":        "Sensitive IAM Action Detected",
            "description": (
                f"IAM control actions observed: "
                f"{', '.join(sorted(matched_iam))}. "
                "These actions can create backdoor accounts or escalate privileges."
            ),
        })
        log.info("[EVENTTRIGGER] RULE-001 fired: %s", sorted(matched_iam))

    # RULE-002: Data exfiltration
    matched_exfil = activity_set & _EXFILTRATION_ACTIONS
    if matched_exfil:
        triggered.append({
            "rule_id":     "RULE-002",
            "name":        "Data Exfiltration Pattern Detected",
            "description": (
                f"Data access actions observed: "
                f"{', '.join(sorted(matched_exfil))}. "
                "Sensitive data may have been copied or downloaded."
            ),
        })
        log.info("[EVENTTRIGGER] RULE-002 fired: %s", sorted(matched_exfil))

    # RULE-003: Privilege escalation sequence
    if all(a in activity_set for a in _ESCALATION_PAIR):
        triggered.append({
            "rule_id":     "RULE-003",
            "name":        "Privilege Escalation Sequence",
            "description": (
                "iam:CreateUser followed by iam:AttachUserPolicy detected — "
                "classic attacker privilege escalation pattern."
            ),
        })
        log.info("[EVENTTRIGGER] RULE-003 fired: escalation sequence")

    # RULE-004: High-frequency API calls
    if len(activity_set) > _HIGH_FREQ_THRESHOLD:
        triggered.append({
            "rule_id":     "RULE-004",
            "name":        "High-Frequency API Calls",
            "description": (
                f"{len(activity_set)} unique API actions detected in this session. "
                f"Threshold is {_HIGH_FREQ_THRESHOLD}. "
                "Automated attacker tooling or credential abuse script suspected."
            ),
        })
        log.info("[EVENTTRIGGER] RULE-004 fired: %d unique actions", len(activity_set))

    # RULE-005: Cross-service lateral movement
    services = {a.split(":")[0] for a in activity if ":" in a}
    if len(services) >= _LATERAL_SVC_THRESHOLD:
        triggered.append({
            "rule_id":     "RULE-005",
            "name":        "Cross-Service Lateral Movement",
            "description": (
                f"Activity detected across {len(services)} AWS services "
                f"({', '.join(sorted(services))}). "
                "Credential used to move laterally through the AWS environment."
            ),
        })
        log.info("[EVENTTRIGGER] RULE-005 fired: services=%s", sorted(services))

    should_trigger = bool(triggered)

    if not triggered:
        reason = (
            "No EventBridge rules triggered — "
            "this activity would not raise an alert in production."
        )
    elif len(triggered) == 1:
        reason = f"1 EventBridge rule triggered: {triggered[0]['name']}"
    else:
        names = ", ".join(r["name"] for r in triggered)
        reason = f"{len(triggered)} EventBridge rules triggered: {names}"

    log.info("[EVENTTRIGGER] should_trigger=%s total_rules_fired=%d",
             should_trigger, len(triggered))

    return {
        "triggered_rules":         triggered,
        "should_trigger_pipeline": should_trigger,
        "trigger_reason":          reason,
    }


def extract_lambda_payload(
    access_key: str,
    validation: dict,
    activity: list[str],
) -> dict:
    """
    Simulate the AWS Lambda execution layer.

    In production, Lambda receives the filtered CloudTrail event from
    EventBridge, extracts the AccessKeyId, and structures a payload to
    send to the analysis backend API.

    Args:
        access_key:  The leaked AWS access key ID
        validation:  Result dict from validator.py
        activity:    Observed CloudTrail actions list

    Returns:
        Structured payload dict representing what Lambda would produce.
    """
    services_seen = sorted({a.split(":")[0] for a in activity if ":" in a})

    payload = {
        "lambda_invoked":    True,
        "access_key_id":     access_key,
        "account_id":        validation.get("account_id"),
        "iam_arn":           validation.get("arn"),
        "credential_status": validation.get("status"),
        "event_count":       len(activity),
        "services_seen":     services_seen,
    }

    log.debug("[LAMBDA] Payload constructed for %s...: services=%s events=%d",
              access_key[:8], services_seen, len(activity))

    return payload
