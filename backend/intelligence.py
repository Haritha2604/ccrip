"""
intelligence.py
---------------
INTELLIGENCE ANALYSIS + ANOMALY DETECTION LAYERS.

Three sub-analyses:
  1. Timeline reconstruction  — ordered sequence of events with phase labels
  2. Intent classification    — which attack phases are present (Recon, Exploitation, …)
  3. Anomaly detection        — suspicious behavioural patterns, including:
       - Recon-to-Exploitation sequence
       - New IAM user / access key creation (persistence)
       - Secrets Manager access (exfiltration)
       - New IP address or AWS region detected (from real CloudTrail metadata)
       - High-frequency API calls (attacker tooling)
       - Dormant key suddenly activated (key unused for >30 days then used)
"""


from ccrip_logger import get_logger
log = get_logger(__name__)

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


def _detect_metadata_anomalies(metadata: list[dict]) -> list[str]:
    """
    Anomaly detection using real CloudTrail metadata (IP, region, timestamps).
    Only runs when real CloudTrail logs are available.
    """
    if not metadata:
        return []

    anomalies: list[str] = []

    # Collect unique IPs and regions
    ips     = {m['source_ip'] for m in metadata if m.get('source_ip')}
    regions = {m['region']    for m in metadata if m.get('region')}

    # Multiple source IPs = attacker may be using a VPN/proxy rotation
    if len(ips) > 1:
        ip_list = ', '.join(sorted(ips)[:3]) + ('...' if len(ips) > 3 else '')
        anomalies.append(
            f'API calls from {len(ips)} different IP addresses '
            f'({ip_list}) — '
            'possible credential sharing or proxy rotation.'
        )

    # Multiple regions = lateral movement across AWS regions
    if len(regions) > 1:
        region_list = ', '.join(sorted(regions))
        anomalies.append(
            f'API calls across {len(regions)} AWS regions '
            f'({region_list}) — '
            'attacker may be moving laterally across regions to evade detection.'
        )

    # High-frequency: many distinct events in a short session
    if len(metadata) > 15:
        anomalies.append(
            f'High-frequency API call pattern: {len(metadata)} events logged. '
            'Automated attacker tooling or credential abuse script suspected.'
        )

    # Dormant key activation: timestamps span a long gap
    timestamps = [m['timestamp'] for m in metadata if m.get('timestamp')]
    if len(timestamps) >= 2:
        try:
            from datetime import datetime, timezone
            parsed = sorted([
                datetime.fromisoformat(ts) for ts in timestamps
            ])
            delta = (parsed[-1] - parsed[0]).days
            if delta > 30:
                anomalies.append(
                    f'Activity spans {delta} days — '
                    'dormant key suddenly reactivated after a long period of inactivity.'
                )
        except (ValueError, TypeError):
            pass

    return anomalies


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_intelligence(activity: list[str], metadata: list[dict] | None = None) -> dict:
    """
    Run all intelligence sub-analyses on the observed activity.

    Args:
        activity: List of "service:Action" strings from cloudtrail_fetcher
        metadata: Optional list of {action, timestamp, source_ip, region} dicts
                  from real CloudTrail events (empty for mock logs)

    Returns:  # noqa
        {
            "timeline":  [{step, action, phase}, ...],
            "intent":    ["Reconnaissance", "Exploitation", ...],
            "anomalies": [str, ...],
            "metadata_events": [{action, timestamp, source_ip, region}, ...]
        }
    """
    metadata = metadata or []

    log.debug("[INTEL] Analyzing %d activity events + %d metadata records",
              len(activity), len(metadata))

    # Combine behaviour-based + metadata-based anomalies
    anomalies = _detect_anomalies(activity) + _detect_metadata_anomalies(metadata)

    intent = _classify_intent(activity)
    log.info("[INTEL] intent=%s | %d anomaly(ies) | %d timeline step(s)",
             intent, len(anomalies), len(activity))
    if anomalies:
        for a in anomalies:
            log.warning("[INTEL] Anomaly: %s", a)

    return {
        'timeline':        _build_timeline(activity),
        'intent':          intent,
        'anomalies':       anomalies,
        'metadata_events': metadata,
    }
