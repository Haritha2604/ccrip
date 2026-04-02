"""
aws_connector.py
----------------
Connects to AWS using the provided credentials and fetches
the IAM policies attached to a given IAM user.

Only IAM read operations are used — no paid services involved.
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_user_policies(access_key: str, secret_key: str, username: str) -> list[dict]:
    """
    Create a boto3 IAM client with the supplied credentials and return
    a list of policy documents attached to *username*.

    Returns an empty list when the user has no attached policies.
    Raises ValueError for authentication / authorisation failures so
    the caller can return a clean error response to the API consumer.
    """

    # Build a scoped IAM client — no default profile is touched
    try:
        iam = boto3.client(
            "iam",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1",
        )
    except Exception as exc:
        raise ValueError(f"Failed to initialise AWS client: {exc}") from exc

    policies = []

    # ── 1. Fetch managed policies attached directly to the user ──────────────
    try:
        paginator = iam.get_paginator("list_attached_user_policies")
        for page in paginator.paginate(UserName=username):
            for policy_meta in page.get("AttachedPolicies", []):
                policy_arn = policy_meta["PolicyArn"]

                # Get the default version id for this policy
                policy_detail = iam.get_policy(PolicyArn=policy_arn)
                version_id = policy_detail["Policy"]["DefaultVersionId"]

                # Fetch the actual policy document
                version = iam.get_policy_version(
                    PolicyArn=policy_arn, VersionId=version_id
                )
                policies.append(version["PolicyVersion"]["Document"])

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_msg = exc.response["Error"]["Message"]

        if error_code in ("InvalidClientTokenId", "AuthFailure", "SignatureDoesNotMatch"):
            raise ValueError("Invalid AWS credentials provided.") from exc

        if error_code == "AccessDenied":
            raise ValueError(
                "Credentials are valid but lack permission to read IAM policies."
            ) from exc

        if error_code == "NoSuchEntity":
            # User does not exist — return empty list rather than crashing
            return []

        raise ValueError(f"AWS error [{error_code}]: {error_msg}") from exc

    except NoCredentialsError as exc:
        raise ValueError("No AWS credentials supplied.") from exc

    return policies
