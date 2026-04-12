"""
permission_analyzer.py
----------------------
PERMISSION + RESOURCE ANALYSIS — Core engine layer.

Two functions:

  extract_permissions(policy_documents)
    → Returns coarse-grained permission LABELS (e.g. "IAM_ACCESS")
      used throughout the rest of the pipeline for risk scoring.

  get_resource_analysis(policy_documents)
    → Returns a detailed breakdown per IAM statement:
        {service, action, operation, resource_type}
      This implements the flowchart's "map actions → specific AWS resources"
      and "expand wildcard permissions (s3:*, iam:*)" requirement.
"""

from ccrip_logger import get_logger
log = get_logger(__name__)

# ── Coarse-grained label map (used by risk engine) ────────────────────────────

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

WILDCARD_LABEL = "FULL_ACCESS"

# ── Detailed resource type map (used by get_resource_analysis) ────────────────
# Format: service → { action_or_wildcard → resource_description }

_RESOURCE_TYPE_MAP: dict[str, dict[str, str]] = {
    "s3": {
        "*":              "All S3 operations (buckets + objects)",
        "GetObject":      "S3 object read (file download)",
        "PutObject":      "S3 object write (file upload)",
        "DeleteObject":   "S3 object deletion",
        "ListBucket":     "S3 bucket enumeration",
        "ListBuckets":    "All S3 bucket names enumeration",
        "CopyObject":     "S3 object copy (exfiltration path)",
        "CreateBucket":   "S3 bucket creation",
        "DeleteBucket":   "S3 bucket deletion",
    },
    "iam": {
        "*":                  "All IAM operations (full identity control)",
        "CreateUser":         "IAM user creation",
        "DeleteUser":         "IAM user deletion",
        "CreateAccessKey":    "IAM access key creation",
        "AttachUserPolicy":   "IAM user policy attachment",
        "AttachRolePolicy":   "IAM role policy attachment",
        "PutUserPolicy":      "Inline policy injection",
        "CreateRole":         "IAM role creation",
        "AddUserToGroup":     "IAM group membership modification",
        "UpdateLoginProfile": "AWS Console password change",
        "ListUsers":          "IAM user enumeration",
        "ListRoles":          "IAM role enumeration",
        "ListPolicies":       "IAM policy enumeration",
    },
    "ec2": {
        "*":                              "All EC2 operations (full compute control)",
        "RunInstances":                   "EC2 instance launch (crypto mining / C2 risk)",
        "DescribeInstances":              "EC2 instance enumeration (reconnaissance)",
        "DescribeSecurityGroups":         "Security group enumeration",
        "AuthorizeSecurityGroupIngress":  "Security group rule modification (backdoor)",
        "TerminateInstances":             "EC2 instance termination (destructive)",
        "CreateKeyPair":                  "EC2 key pair creation",
    },
    "lambda": {
        "*":                "All Lambda operations",
        "CreateFunction":   "Lambda function creation (code execution)",
        "InvokeFunction":   "Lambda function invocation",
        "UpdateFunctionCode": "Lambda function code modification",
    },
    "sts": {
        "*":             "All STS operations",
        "AssumeRole":    "Role assumption (cross-account / privilege pivot)",
        "GetCallerIdentity": "Identity verification (reconnaissance)",
    },
    "secretsmanager": {
        "*":                    "All Secrets Manager operations",
        "GetSecretValue":       "Secret read (passwords / API keys)",
        "ListSecrets":          "Secret enumeration",
        "DeleteSecret":         "Secret deletion (destructive)",
        "CreateSecret":         "Secret creation",
    },
    "kms": {
        "*":        "All KMS operations",
        "Decrypt":  "KMS key decryption (reveals encrypted data)",
        "Encrypt":  "KMS encryption",
        "GenerateDataKey": "Data key generation",
    },
    "rds": {
        "*":                  "All RDS operations",
        "CreateDBSnapshot":   "RDS snapshot creation (data exfiltration path)",
        "DescribeDBInstances":"RDS instance enumeration",
        "DeleteDBInstance":   "RDS instance deletion (destructive)",
    },
    "dynamodb": {
        "*":       "All DynamoDB operations",
        "Scan":    "Full table scan (data exfiltration)",
        "GetItem": "DynamoDB item read",
        "PutItem": "DynamoDB item write",
        "DeleteItem": "DynamoDB item deletion",
    },
}


# ── Public API ─────────────────────────────────────────────────────────────────

def extract_permissions(policy_documents: list[dict]) -> list[str]:
    """
    Walk through IAM policy documents and return a de-duplicated, sorted
    list of coarse-grained permission labels.
    """
    labels: set[str] = set()

    for document in policy_documents:
        for statement in document.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                label = _action_to_label(action)
                if label:
                    labels.add(label)

    result = sorted(labels)
    log.debug("[PERMISSIONS] extract_permissions → %s", result)
    return result


def get_resource_analysis(policy_documents: list[dict]) -> list[dict]:
    """
    Detailed permission + resource breakdown — implements the flowchart's
    'expand wildcard permissions' and 'map actions → specific AWS resources'.

    Returns a list of dicts, one per unique (service, action, resource_type):
        [
            {
                "service":       "s3",
                "action":        "s3:GetObject",
                "resource_type": "S3 object read (file download)",
                "sensitive":     bool,
            },
            ...
        ]
    """
    _SENSITIVE_ACTIONS = {
        "iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy",
        "iam:CreateRole", "s3:GetObject", "s3:CopyObject",
        "secretsmanager:GetSecretValue", "kms:Decrypt",
        "sts:AssumeRole", "ec2:RunInstances",
    }

    seen: set[str] = set()
    result: list[dict] = []

    for document in policy_documents:
        for statement in document.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                action = action.strip()
                if action in seen:
                    continue
                seen.add(action)

                if action == "*":
                    result.append({
                        "service":       "all",
                        "action":        "*",
                        "resource_type": "Unrestricted — all AWS services and actions",
                        "sensitive":     True,
                    })
                    continue

                parts = action.split(":", 1)
                if len(parts) != 2:
                    continue

                service, operation = parts[0].lower(), parts[1]
                svc_map = _RESOURCE_TYPE_MAP.get(service, {})

                # Resolve wildcard (e.g. "s3:*")
                if operation == "*":
                    resource_type = svc_map.get("*", f"All {service.upper()} operations")
                else:
                    resource_type = svc_map.get(operation, f"{service}:{operation}")

                result.append({
                    "service":       service,
                    "action":        action,
                    "resource_type": resource_type,
                    "sensitive":     action in _SENSITIVE_ACTIONS,
                })

    log.debug("[PERMISSIONS] get_resource_analysis → %d entries", len(result))
    return result


# ── Private helpers ────────────────────────────────────────────────────────────

def _action_to_label(action: str) -> str | None:
    if action.strip() == "*":
        return WILDCARD_LABEL
    parts = action.split(":", 1)
    if len(parts) != 2:
        return None
    service = parts[0].lower()
    return SERVICE_LABEL_MAP.get(service)
