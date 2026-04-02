"""
permission_analyzer.py
----------------------
Converts raw AWS IAM policy documents into simple, human-readable
permission labels used throughout the rest of the pipeline.

Labels are deliberately coarse-grained so the risk engine stays simple.
"""

# Map an IAM action prefix to a label.
# Order matters: more specific prefixes should come first.
SERVICE_LABEL_MAP = {
    "s3":               "S3_ACCESS",
    "iam":              "IAM_ACCESS",
    "ec2":              "EC2_ACCESS",
    "lambda":           "LAMBDA_ACCESS",
    "sts":              "STS_ACCESS",
    "secretsmanager":   "SECRETS_ACCESS",
    "kms":              "KMS_ACCESS",
    "rds":              "RDS_ACCESS",
    "dynamodb":         "DYNAMODB_ACCESS",
}

# The wildcard action "*" implies every service
WILDCARD_LABEL = "FULL_ACCESS"


def extract_permissions(policy_documents: list[dict]) -> list[str]:
    """
    Walk through a list of IAM policy documents and return a
    de-duplicated, sorted list of permission labels.

    Each *policy_document* has the standard AWS structure:
        {"Statement": [{"Effect": "Allow", "Action": [...], ...}]}
    """
    labels: set[str] = set()

    for document in policy_documents:
        for statement in document.get("Statement", []):
            # Only care about Allow statements
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])

            # Actions can be a single string or a list
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                label = _action_to_label(action)
                if label:
                    labels.add(label)

    return sorted(labels)


# ── Private helpers ────────────────────────────────────────────────────────────

def _action_to_label(action: str) -> str | None:
    """
    Convert a single IAM action string (e.g. "s3:GetObject") to a label.
    Returns None when no matching label exists.
    """
    if action.strip() == "*":
        return WILDCARD_LABEL

    # Actions are formatted as "service:Operation"
    parts = action.split(":", 1)
    if len(parts) != 2:
        return None

    service = parts[0].lower()
    return SERVICE_LABEL_MAP.get(service)
