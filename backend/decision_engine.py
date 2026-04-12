"""
decision_engine.py
------------------
DECISION ENGINE — Converts risk analysis into actionable decisions.

Given a risk level, validation status, and triggered attack paths, this
module returns:
  1. A named priority level  (P1 / P2 / P3 / P4)
  2. An ordered list of remediation steps
  3. A dependency warning if disabling the key could break live services
"""

from ccrip_logger import get_logger
log = get_logger(__name__)# ── Priority labels ───────────────────────────────────────────────────────────

PRIORITY_MAP = {
    'CRITICAL': 'P1 — Respond Immediately (within 1 hour)',
    'HIGH':     'P2 — Respond Urgently (within 24 hours)',
    'MEDIUM':   'P3 — Respond Soon (within 72 hours)',
    'LOW':      'P4 — Monitor (next maintenance window)',
}

# ── Base remediation steps per severity ──────────────────────────────────────

BASE_STEPS: dict[str, list[str]] = {
    'CRITICAL': [
        'Immediately disable the access key via IAM console → Users → Security credentials → Set to Inactive.',
        'Delete the key once you have confirmed no live service depends on it.',
        'List all active keys: aws iam list-access-keys --user-name <user>',
        'Audit CloudTrail for all actions by this key over the last 90 days.',
        'Search for newly created IAM users, roles, or access keys in your account.',
        'Rotate ALL credentials (passwords, keys, secrets) in the affected account.',
        'Enable AWS GuardDuty if not already active.',
        'File an internal security incident report immediately.',
    ],
    'HIGH': [
        'Rotate the access key: create a new one → update all services → delete the old one.',
        'Restrict IAM permissions to least-privilege (remove unused policies).',
        'Audit CloudTrail for suspicious activity in the last 30 days.',
        'Check for unauthorized resource creation (EC2, Lambda, S3 buckets, RDS snapshots).',
        'Enable AWS Config to track future resource changes.',
    ],
    'MEDIUM': [
        'Schedule key rotation within 72 hours.',
        'Review attached IAM policies and remove permissions not actively used.',
        'Enable CloudTrail in all AWS regions if not already enabled.',
        'Set up CloudWatch alarms for anomalous IAM activity.',
    ],
    'LOW': [
        'Monitor CloudTrail for unusual activity from this key.',
        'Rotate the credential during the next maintenance window.',
        'Consider replacing the long-term key with an IAM role where possible.',
    ],
}

# ── Extra steps triggered by specific attack paths ────────────────────────────

ATTACK_SPECIFIC_STEPS: dict[str, list[str]] = {
    'Persistence': [
        'Search for IAM users created after the key exposure date: aws iam list-users',
        'Look for unknown IAM access keys: aws iam list-access-keys for each user.',
    ],
    'Data Exfiltration': [
        'Audit S3 server access logs and CloudTrail for GetObject/CopyObject events.',
        'Enable S3 Object Lock on sensitive buckets to prevent future tampering.',
    ],
    'Privilege Escalation': [
        'Audit all admin-level policy attachments: aws iam list-attached-user-policies.',
        'Enable IAM Access Analyzer to detect overly permissive policies.',
    ],
    'Secret / Key Access': [
        'Rotate every secret stored in AWS Secrets Manager.',
        'Review KMS key usage logs for unexpected decrypt operations.',
    ],
    'Lateral Movement': [
        'Audit EC2 security group rules for unexpected inbound access.',
        'Enforce IMDSv2 on all EC2 instances to prevent SSRF-based key theft.',
    ],
    'Role Assumption / Token Abuse': [
        'Review all IAM trust policies to ensure only expected principals can assume roles.',
        'Check STS temporary credential sessions in CloudTrail for unauthorized AssumeRole calls.',
    ],
}


# ── Public API ────────────────────────────────────────────────────────────────

def make_decision(risk_level: str, validation: dict, attack_paths: list[dict]) -> dict:
    """
    Build a structured decision record for one credential.

    Returns:
        {
            "priority":           str,
            "remediation_steps":  [str],
            "dependency_warning": str | None
        }
    """
    priority = PRIORITY_MAP.get(risk_level, PRIORITY_MAP['LOW'])
    log.info("[DECISION] risk_level=%s → priority=%s", risk_level, priority)
    # Start with the base steps for this risk level
    steps: list[str] = list(BASE_STEPS.get(risk_level, BASE_STEPS['LOW']))

    # Append attack-specific steps for every triggered attack path
    triggered = {ap['attack'] for ap in attack_paths}
    log.debug("[DECISION] triggered attack paths: %s", triggered)
    for attack_name, extra in ATTACK_SPECIFIC_STEPS.items():
        if attack_name in triggered:
            steps.extend(extra)

    # Warn if the key is still ACTIVE — disabling it might break services
    dependency_warning = None
    if validation.get('status') == 'ACTIVE':
        dependency_warning = (
            'This key is currently ACTIVE. Before deleting it, identify '
            'any CI/CD pipelines, Lambda functions, or applications that '
            'use it — disabling it without updating them will cause outages.'
        )

    return {
        'priority':           priority,
        'remediation_steps':  steps,
        'dependency_warning': dependency_warning,
    }
