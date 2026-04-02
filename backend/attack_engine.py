"""
attack_engine.py
----------------
Rule-based attack simulation.

Given a list of permission labels (from permission_analyzer) and a list of
observed actions (from the mock logs), this module returns the realistic
attack paths an adversary could follow with those credentials.

Rules are plain Python conditions — easy to read and extend.
"""

from typing import NamedTuple


class AttackRule(NamedTuple):
    """A single detection rule."""
    name: str           # Short attack name shown in the API response
    description: str    # Human-readable explanation


# ── Rule definitions ───────────────────────────────────────────────────────────
# Each function returns True when the rule fires.

def _rule_privilege_escalation(permissions: list[str], _activity: list[str]) -> bool:
    """Attacker can create a new IAM user and attach admin policies."""
    return "IAM_ACCESS" in permissions or "FULL_ACCESS" in permissions


def _rule_data_exfiltration(permissions: list[str], _activity: list[str]) -> bool:
    """Attacker can read and download S3 objects (data theft)."""
    return "S3_ACCESS" in permissions or "FULL_ACCESS" in permissions


def _rule_persistence(permissions: list[str], activity: list[str]) -> bool:
    """
    Attacker has already created a user OR has the permission to do so
    (they could come back later via the new account).
    """
    already_created = "iam:CreateUser" in activity
    can_create = "IAM_ACCESS" in permissions or "FULL_ACCESS" in permissions
    return already_created or can_create


def _rule_lateral_movement(permissions: list[str], _activity: list[str]) -> bool:
    """Attacker can spin up EC2 instances to pivot to other services."""
    return "EC2_ACCESS" in permissions or "FULL_ACCESS" in permissions


def _rule_secret_access(permissions: list[str], _activity: list[str]) -> bool:
    """Attacker can read Secrets Manager or KMS keys."""
    return (
        "SECRETS_ACCESS" in permissions
        or "KMS_ACCESS" in permissions
        or "FULL_ACCESS" in permissions
    )


def _rule_sts_token_abuse(permissions: list[str], activity: list[str]) -> bool:
    """Attacker can assume roles to gain higher-level access."""
    assume_seen = "sts:AssumeRole" in activity
    has_sts = "STS_ACCESS" in permissions or "FULL_ACCESS" in permissions
    return assume_seen or has_sts


# ── Registry: (check_function, AttackRule) ────────────────────────────────────

RULES: list[tuple] = [
    (
        _rule_privilege_escalation,
        AttackRule(
            name="Privilege Escalation",
            description=(
                "IAM access allows an attacker to create a new admin user "
                "or attach AdministratorAccess to an existing account."
            ),
        ),
    ),
    (
        _rule_data_exfiltration,
        AttackRule(
            name="Data Exfiltration",
            description=(
                "S3 access enables bulk download of sensitive files "
                "stored in any accessible bucket."
            ),
        ),
    ),
    (
        _rule_persistence,
        AttackRule(
            name="Persistence",
            description=(
                "A backdoor IAM user or access key has been (or can be) "
                "created to maintain long-term access after the original "
                "credential is rotated."
            ),
        ),
    ),
    (
        _rule_lateral_movement,
        AttackRule(
            name="Lateral Movement",
            description=(
                "EC2 access lets an attacker launch instances inside the "
                "VPC and pivot to internal services."
            ),
        ),
    ),
    (
        _rule_secret_access,
        AttackRule(
            name="Secret / Key Access",
            description=(
                "Access to Secrets Manager or KMS lets an attacker read "
                "database passwords, API keys, or decrypt encrypted data."
            ),
        ),
    ),
    (
        _rule_sts_token_abuse,
        AttackRule(
            name="Role Assumption / Token Abuse",
            description=(
                "STS permissions allow the attacker to assume higher-privileged "
                "roles, bypassing permission boundaries on the original user."
            ),
        ),
    ),
]


# ── Public API ─────────────────────────────────────────────────────────────────

def simulate_attacks(permissions: list[str], activity: list[str]) -> list[dict]:
    """
    Evaluate every rule and return a list of attack dictionaries for
    rules that fire.

    Each dict contains:
        - "attack":      short name
        - "description": plain-English explanation
    """
    triggered = []

    for check_fn, rule in RULES:
        if check_fn(permissions, activity):
            triggered.append({
                "attack": rule.name,
                "description": rule.description,
            })

    return triggered
