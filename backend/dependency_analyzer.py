"""
dependency_analyzer.py
----------------------
DEPENDENCY ANALYSIS LAYER — Detects persistence mechanisms established
by an attacker using a leaked credential.

Analyzes observed API activity and permissions to determine whether
the attacker:
  - Created new IAM users (backdoor accounts)
  - Generated new access keys (persistent long-term access)
  - Attached policies to users or roles (privilege injection)
  - Created new IAM roles (cross-account/cross-service access)
  - Updated login profiles (console access granted)

This layer is critical for the cleanup strategy.
Before disabling a key, the security team must know what backdoors
already exist — otherwise the attacker retains access even after
the original key is revoked.
"""

from ccrip_logger import get_logger
log = get_logger(__name__)

# ── Persistence indicator definitions ────────────────────────────────────────

# Each entry: API action → human-readable description of the threat
_PERSISTENCE_INDICATORS: dict[str, str] = {
    "iam:CreateUser":
        "New IAM user created — attacker may have established a backdoor account.",
    "iam:CreateAccessKey":
        "New access key generated — attacker may have created a secondary persistent key.",
    "iam:AttachUserPolicy":
        "Policy directly attached to a user — privileges granted to a potentially malicious account.",
    "iam:PutUserPolicy":
        "Inline policy injected into a user — direct permission escalation.",
    "iam:AddUserToGroup":
        "User added to an IAM group — attacker may have silently gained additional permissions.",
    "iam:CreateRole":
        "New IAM role created — possible cross-account or cross-service backdoor.",
    "iam:AttachRolePolicy":
        "Policy attached to a role — privilege escalation via role assumption.",
    "iam:UpdateLoginProfile":
        "Console login profile updated — attacker may have changed the AWS Console password.",
    "iam:CreateLoginProfile":
        "Console login profile created — attacker enabled AWS Console access for a user.",
}


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_dependencies(permissions: list[str], activity: list[str]) -> dict:
    """
    Detect persistence mechanisms from observed activity and permissions.

    Returns:
        {
            "detected":           bool,
            "mechanisms":         [{"action": str, "description": str}],
            "new_iam_users":      bool,
            "new_access_keys":    bool,
            "policy_attachments": bool,
            "new_roles":          bool,
            "cleanup_required":   bool,
            "summary":            str,
        }
    """
    activity_set = set(activity)

    # Check which persistence indicators fired
    mechanisms: list[dict] = []
    for action, description in _PERSISTENCE_INDICATORS.items():
        if action in activity_set:
            mechanisms.append({"action": action, "description": description})
            log.info("[DEPENDENCY] Persistence mechanism detected: %s", action)

    # Derived boolean flags for easy UI rendering
    new_iam_users      = "iam:CreateUser"         in activity_set
    new_access_keys    = "iam:CreateAccessKey"     in activity_set
    policy_attachments = bool(
        {"iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy"}
        & activity_set
    )
    new_roles          = "iam:CreateRole"          in activity_set

    # Even if no persistence in logs, IAM_ACCESS = could still have done it
    has_iam_capability = bool(
        {"IAM_ACCESS", "FULL_ACCESS"} & set(permissions)
    )

    detected        = bool(mechanisms)
    cleanup_required = detected or has_iam_capability

    # Build a summary for the UI
    if not detected and not has_iam_capability:
        summary = (
            "No persistence mechanisms detected. "
            "No IAM access — attacker cannot create backdoor accounts."
        )
    elif not detected and has_iam_capability:
        summary = (
            "No persistence detected in observed logs. "
            "However, this credential has IAM_ACCESS — persistence could have been "
            "established outside the current 90-day CloudTrail window."
        )
    elif len(mechanisms) == 1:
        summary = (
            f"1 persistence mechanism detected. "
            "Manual cleanup required before disabling this key."
        )
    else:
        summary = (
            f"{len(mechanisms)} persistence mechanisms detected. "
            "Thorough account audit and cleanup required before remediation."
        )

    log.info("[DEPENDENCY] detected=%s mechanisms=%d cleanup_required=%s",
             detected, len(mechanisms), cleanup_required)

    return {
        "detected":           detected,
        "mechanisms":         mechanisms,
        "new_iam_users":      new_iam_users,
        "new_access_keys":    new_access_keys,
        "policy_attachments": policy_attachments,
        "new_roles":          new_roles,
        "cleanup_required":   cleanup_required,
        "summary":            summary,
    }
