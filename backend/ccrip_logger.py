"""
ccrip_logger.py
---------------
Centralised logging for the CCRIP pipeline.

Every module imports `get_logger(__name__)` and uses it exactly like
Python's standard logging.  All messages go to TWO destinations:

  1. logs/ccrip.log  – rotating file (10 MB max, keeps last 3 backups)
  2. Console (stdout) – coloured per-level output for live debugging

Log levels used across the pipeline:
  DEBUG   – fine-grained step-by-step trace (e.g. "scanning file X")
  INFO    – normal milestones (e.g. "scan started", "credential found")
  WARNING – recoverable issues (e.g. "no secret key – using mock logs")
  ERROR   – failures that stop a step (e.g. "CloudTrail access denied")
  CRITICAL– unrecoverable failures (e.g. "server startup error")

The log file is written to  backend/logs/ccrip.log
One line per event, format:
  2026-04-04 12:00:00 | INFO     | scanner        | Scanning file config.py
"""

import logging
import logging.handlers
import os
import sys

# ── Log directory ──────────────────────────────────────────────────────────────
_LOG_DIR  = os.path.join(os.path.dirname(__file__), "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "ccrip.log")

os.makedirs(_LOG_DIR, exist_ok=True)  # create logs/ folder if it does not exist

# ── Shared formatter ───────────────────────────────────────────────────────────
_FMT     = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"
_formatter = logging.Formatter(_FMT, datefmt=_DATEFMT)

# ── Root logger (configured once per process) ──────────────────────────────────
_root = logging.getLogger("ccrip")
_root.setLevel(logging.DEBUG)          # capture everything; handlers filter

if not _root.handlers:                 # avoid duplicate handlers on hot-reload
    # 1. Rotating file handler — 10 MB per file, keep 3 backups
    _fh = logging.handlers.RotatingFileHandler(
        _LOG_FILE,
        maxBytes=10 * 1024 * 1024,     # 10 MB
        backupCount=3,
        encoding="utf-8",
    )
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(_formatter)

    # 2. Console handler — INFO and above only (don't flood the terminal)
    _ch = logging.StreamHandler(sys.stdout)
    _ch.setLevel(logging.INFO)
    _ch.setFormatter(_formatter)

    _root.addHandler(_fh)
    _root.addHandler(_ch)


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger scoped to the calling module.

    Usage (in any pipeline module):
        from ccrip_logger import get_logger
        log = get_logger(__name__)
        log.info("Credential found: %s", access_key[:8] + "...")
    """
    # Strip the 'backend.' prefix if running as a package
    short = name.replace("backend.", "")
    return _root.getChild(short)
