"""
ingestion.py
------------
INGESTION LAYER — Normalize and deduplicate raw scanner output.

A single access key may appear in multiple files (e.g. hardcoded in both
a config file and a CI/CD pipeline definition). This module consolidates
duplicates so each unique key is analysed only once.
"""

from dataclasses import dataclass, field
from typing import Optional

from scanner import LeakedCredential
from ccrip_logger import get_logger
log = get_logger(__name__)


@dataclass
class CredentialRecord:
    """A normalized, deduplicated credential ready for the analysis pipeline."""
    access_key:  str
    secret_key:  Optional[str]
    has_secret:  bool
    occurrences: list[dict] = field(default_factory=list)
    # Each occurrence: {file_path, line_number, context}


def normalize_and_deduplicate(raw: list[LeakedCredential]) -> list[CredentialRecord]:
    """
    1. Group all raw findings by access_key.
    2. For each group, pick the best secret_key (prefer entries that have one).
    3. Collect all file locations as an occurrences list.
    4. Return one CredentialRecord per unique access_key.
    """
    log.info("[INGEST] Received %d raw findings to deduplicate", len(raw))

    # Group by access key
    grouped: dict[str, list[LeakedCredential]] = {}
    for cred in raw:
        grouped.setdefault(cred.access_key, []).append(cred)

    records: list[CredentialRecord] = []

    for access_key, group in grouped.items():
        # Prefer any entry that includes a secret key
        with_secret = [c for c in group if c.secret_key]
        best = with_secret[0] if with_secret else group[0]

        occurrences = [
            {
                'file_path':   c.file_path,
                'line_number': c.line_number,
                'context':     c.context,
            }
            for c in group
        ]

        log.debug("[INGEST] Key %s... → %d occurrence(s), has_secret=%s",
                 access_key[:8], len(group), bool(best.secret_key))
        records.append(CredentialRecord(
            access_key=access_key,
            secret_key=best.secret_key,
            has_secret=bool(best.secret_key),
            occurrences=occurrences,
        ))

    log.info("[INGEST] Deduplicated %d raw findings → %d unique credential(s)",
             len(raw), len(records))
    return records
