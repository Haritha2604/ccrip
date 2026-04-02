"""
validator.py
------------
VALIDATION LAYER — Verify whether a leaked credential is still ACTIVE.

Uses AWS STS GetCallerIdentity:
  - Free API call (never charges)
  - Requires zero IAM permissions
  - Instantly returns account ID, user ARN, and user ID if valid
  - Fails with a clear error code if the key is revoked or invalid
"""

from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def validate_credential(access_key: str, secret_key: Optional[str]) -> dict:
    """
    Attempt to call STS:GetCallerIdentity with the provided credential.

    Returns:
        {
            "status":     "ACTIVE" | "INACTIVE" | "NO_SECRET",
            "account_id": str | None,
            "user_id":    str | None,
            "arn":        str | None,
            "reason":     str
        }
    """
    # We cannot validate without the secret key
    if not secret_key:
        return {
            'status':     'NO_SECRET',
            'account_id': None,
            'user_id':    None,
            'arn':        None,
            'reason':     (
                'Secret key was not found in the repository. '
                'Credential existence is confirmed but active status is unknown.'
            ),
        }

    try:
        sts = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name='us-east-1',
        )
        identity = sts.get_caller_identity()

        return {
            'status':     'ACTIVE',
            'account_id': identity.get('Account'),
            'user_id':    identity.get('UserId'),
            'arn':        identity.get('Arn'),
            'reason':     'Credential is valid and currently active.',
        }

    except ClientError as exc:
        code = exc.response['Error']['Code']

        if code in ('InvalidClientTokenId', 'AuthFailure', 'SignatureDoesNotMatch'):
            return {
                'status':     'INACTIVE',
                'account_id': None,
                'user_id':    None,
                'arn':        None,
                'reason':     'Credential is invalid or has already been revoked.',
            }

        return {
            'status':     'INACTIVE',
            'account_id': None,
            'user_id':    None,
            'arn':        None,
            'reason':     f'AWS error [{code}] — credential may be inactive.',
        }

    except NoCredentialsError:
        return {
            'status':     'INACTIVE',
            'account_id': None,
            'user_id':    None,
            'arn':        None,
            'reason':     'No credentials were supplied.',
        }
