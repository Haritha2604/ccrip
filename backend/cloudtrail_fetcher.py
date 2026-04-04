"""
cloudtrail_fetcher.py
---------------------
Attempts to fetch REAL CloudTrail logs for a given access key
using the AWS CloudTrail LookupEvents API.

If real logs are unavailable (no permission, CloudTrail disabled,
or no secret key available), it falls back to the mock_logs.json file.

Why LookupEvents?
  - Free to call (no extra AWS charges)
  - Returns the last 90 days of events
  - Can filter by a specific access key ID

The function always returns a dict so the caller knows
whether data is real or mocked.
"""

import json
import os
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from ccrip_logger import get_logger
log = get_logger(__name__)


# Load mock logs once — used as the fallback
_MOCK_PATH = os.path.join(os.path.dirname(__file__), "mock_logs.json")
with open(_MOCK_PATH, encoding="utf-8") as _f:
    _MOCK_LOGS: list[str] = json.load(_f)

# Maximum number of events to retrieve per credential
MAX_EVENTS = 50


def fetch_activity(access_key: str, secret_key: Optional[str]) -> dict:
    """
    Try to fetch real CloudTrail events for *access_key*.

    Returns:
        {
            "source":   "cloudtrail" | "mock",
            "activity": ["s3:ListBucket", "iam:CreateUser", ...],
            "note":     str   -- explains why mock was used (if applicable)
        }
    """

    # ── Cannot call AWS without a secret key ──────────────────────────────────
    if not secret_key:
        log.warning("[CLOUDTRAIL] %s... → no secret key, using mock logs", access_key[:8])
        return {
            "source":   "mock",
            "activity": _MOCK_LOGS,
            "note":     "No secret key available — using mock logs.",
        }

    # ── Attempt real CloudTrail lookup ────────────────────────────────────────
    try:
        log.debug("[CLOUDTRAIL] Calling LookupEvents for %s...", access_key[:8])
        ct = boto3.client(
            "cloudtrail",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1",
        )

        # Filter events by the specific access key that was leaked
        response = ct.lookup_events(
            LookupAttributes=[{
                "AttributeKey":   "AccessKeyId",
                "AttributeValue": access_key,
            }],
            MaxResults=MAX_EVENTS,
        )

        events = response.get("Events", [])

        if not events:
            log.info("[CLOUDTRAIL] %s... → no events in last 90 days, using mock logs",
                     access_key[:8])
            return {
                "source":   "mock",
                "activity": _MOCK_LOGS,
                "note": (
                    "CloudTrail returned no events for this key "
                    "(key may be new, or no activity in the last 90 days). "
                    "Using mock logs."
                ),
            }

        # CloudTrail returns full event dicts — extract just "service:EventName"
        # EventName examples: "GetObject", "CreateUser"
        # EventSource examples: "s3.amazonaws.com", "iam.amazonaws.com"
        activity: list[str] = []
        for event in events:
            event_name   = event.get("EventName", "")
            event_source = event.get("EventSource", "")

            # Convert "s3.amazonaws.com" → "s3"
            service = event_source.replace(".amazonaws.com", "")

            if event_name and service:
                activity.append(f"{service}:{event_name}")

        # Remove duplicates while preserving order
        seen = set()
        deduplicated = []
        for action in activity:
            if action not in seen:
                seen.add(action)
                deduplicated.append(action)

        log.info("[CLOUDTRAIL] %s... → REAL logs fetched: %d unique events",
                 access_key[:8], len(deduplicated))
        return {
            "source":   "cloudtrail",
            "activity": deduplicated,
            "note":     f"Fetched {len(deduplicated)} real CloudTrail events for this key.",
        }

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        log.error("[CLOUDTRAIL] %s... → ClientError code=%s, falling back to mock",
                  access_key[:8], code)

        if code == "AccessDeniedException":
            note = (
                "The leaked key lacks 'cloudtrail:LookupEvents' permission. "
                "Using mock logs as fallback."
            )
        elif code in ("InvalidClientTokenId", "AuthFailure"):
            note = "Credential is invalid — cannot query CloudTrail. Using mock logs."
        else:
            note = f"CloudTrail error [{code}] — using mock logs as fallback."

        return {
            "source":   "mock",
            "activity": _MOCK_LOGS,
            "note":     note,
        }

    except NoCredentialsError:
        log.error("[CLOUDTRAIL] %s... → NoCredentialsError", access_key[:8])
        return {
            "source":   "mock",
            "activity": _MOCK_LOGS,
            "note":     "No credentials available for CloudTrail query. Using mock logs.",
        }

    except Exception as exc:
        log.error("[CLOUDTRAIL] %s... → Unexpected error: %s", access_key[:8], exc, exc_info=True)
        return {
            "source":   "mock",
            "activity": _MOCK_LOGS,
            "note":     f"Unexpected error fetching CloudTrail: {exc}. Using mock logs.",
        }
