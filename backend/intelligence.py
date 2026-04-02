"""
intelligence.py
---------------
INTELLIGENCE ANALYSIS LAYER — Core brain of CCRIP.

Analyses observed API activity to answer:
  "What is the attacker trying to do?"

Three sub-analyses:
  1. Timeline reconstruction  — ordered sequence of events with phase labels
  2. Intent classification    — which attack phases are present (Recon, Exploitation, …)
  3. Anomaly detection        — suspicious behavioural patterns
"""


# ── Action-to-phase mappings ──────────────────────────────────────────────────

RECON_ACTIONS = {
    'iam:ListUsers', 'iam:ListRoles', 'iam:ListPolicies', 'iam:ListGroups',
    'iam:GetUser', 'iam:GetAccountSummary', 'iam:GetAccountAuthorizationDetails',
    'ec2:DescribeInstances', 'ec2:DescribeSecurityGroups', 'ec2:DescribeVpcs',
    's3:ListBuckets', 's3:ListObjects', 's3:ListObjectsV2',
    'sts:GetCallerIdentity',
}

EXPLOITATION_ACTIONS = {
    'iam:CreateUser', 'iam:CreateAccessKey',
    'iam:AttachUserPolicy', 'iam:PutUserPolicy',
    'iam:CreateRole', 'iam:AttachRolePolicy',
    'ec2:RunInstances', 'ec2:AuthorizeSecurityGroupIngress',
    'lambda:CreateFunction', 'lambda:InvokeFunction',
}

EXFILTRATION_ACTIONS = {
    's3:GetObject', 's3:CopyObject',
    'secretsmanager:GetSecretValue',
    'ssm:GetParameter', 'ssm:GetParameters',
    'rds:CreateDBSnapshot',
    'dynamodb:Scan', 'dynamodb:GetItem',
    'kms:Decrypt',
}

PERSISTENCE_ACTIONS = {
    'iam:CreateUser', 'iam:CreateAccessKey',
    'iam:AddUserToGroup', 'iam:AttachUserPolicy',
    'iam:UpdateLoginProfile',
}

# Flat map: action → phase (for timeline labelling)
_PHASE_MAP: dict[str, str] = {
    **{a: 'Reconnaissance' for a in RECON_ACTIONS},
    **{a: 'Exploitation'   for a in EXPLOITATION_ACTIONS},
    **{a: 'Exfiltration'   for a in EXFILTRATION_ACTIONS},
    **{a: 'Persistence'    for a in PERSISTENCE_ACTIONS},
}


# ── Sub-analyses ──────────────────────────────────────────────────────────────

def _build_timeline(activity: list[str]) -> list[dict]:
    """
    Assign each log action a sequential step number and a phase label.
    (In a real system each entry would carry a real CloudTrail timestamp.)
    """
    return [
        {
            'step':   idx + 1,
            'action': action,
            'phase':  _PHASE_MAP.get(action, 'Unknown'),
        }
        for idx, action in enumerate(activity)
    ]


def _classify_intent(activity: list[str]) -> list[str]:
    """Return the distinct attack phases detected in the activity list."""
    action_set = set(activity)
    phases = []
    if action_set & RECON_ACTIONS:
        phases.append('Reconnaissance')
    if action_set & EXPLOITATION_ACTIONS:
        phases.append('Exploitation')
    if action_set & EXFILTRATION_ACTIONS:
        phases.append('Exfiltration')
    if action_set & PERSISTENCE_ACTIONS:
        phases.append('Persistence')
    return phases or ['Unknown / Benign']


def _detect_anomalies(activity: list[str]) -> list[str]:
    """Flag suspicious patterns in the observed activity."""
    action_set = set(activity)
    anomalies  = []

    if action_set & RECON_ACTIONS and action_set & EXPLOITATION_ACTIONS:
        anomalies.append(
            'Recon-to-Exploitation sequence detected — classic attacker pattern.'
        )

    if 'iam:CreateUser' in action_set:
        anomalies.append(
            'New IAM user created — possible backdoor account established.'
        )

    if 'iam:CreateAccessKey' in action_set:
        anomalies.append(
            'New access key created — attacker may have established persistent access.'
        )

    if 'secretsmanager:GetSecretValue' in action_set:
        anomalies.append(
            'AWS Secrets Manager accessed — database passwords or API keys may be stolen.'
        )

    if 's3:GetObject' in action_set and 'iam:CreateUser' in action_set:
        anomalies.append(
            'Data exfiltration combined with persistence — high-severity breach pattern.'
        )

    return anomalies


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_intelligence(activity: list[str]) -> dict:
    """
    Run all intelligence sub-analyses on the observed activity.

    Returns:
        {
            "timeline":  [{step, action, phase}, ...],
            "intent":    ["Reconnaissance", "Exploitation", ...],
            "anomalies": ["Recon-to-Exploitation detected ...", ...]
        }
    """
    return {
        'timeline':  _build_timeline(activity),
        'intent':    _classify_intent(activity),
        'anomalies': _detect_anomalies(activity),
    }
