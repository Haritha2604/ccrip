"""
scanner.py
----------
EXTERNAL INPUT LAYER — Gitleaks-inspired scanner.

Scans a public GitHub repository for leaked AWS credentials using
regex pattern matching. No external binary needed — pure Python.

Mirrors what Gitleaks CLI does:
  gitleaks detect --source <repo> --report-format json
"""

import re
import requests
from dataclasses import dataclass
from typing import Optional

from ccrip_logger import get_logger
log = get_logger(__name__)

# ── AWS credential regex patterns ─────────────────────────────────────────────

# AWS Access Key: starts with AKIA (long-term) or ASIA (temporary/STS)
ACCESS_KEY_RE = re.compile(r'\b((?:AKIA|ASIA)[0-9A-Z]{16})\b')

# AWS Secret Key: 40-char alphanumeric+special string near secret keywords
SECRET_KEY_RE = re.compile(
    r'(?i)'
    r'(?:aws[_\-\.]?secret|secret[_\-\.]?access[_\-\.]?key|aws_secret_access_key)'
    r'[^A-Za-z0-9/+=]{0,30}?'
    r'([A-Za-z0-9/+=]{40})'
)

# Fallback: any 40-char base64-like string directly after = : ' "
GENERIC_40_RE = re.compile(r'[\'"=:\s]([A-Za-z0-9/+=]{40})[\'"\s\n\r]')

# ── Scan configuration ────────────────────────────────────────────────────────

SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.rb', '.php', '.go',
    '.java', '.cs', '.sh', '.bash', '.zsh', '.fish',
    '.env', '.yaml', '.yml', '.json', '.xml', '.toml',
    '.ini', '.cfg', '.conf', '.config', '.properties',
    '.tf', '.tfvars', '.pem', '.key',
}

SKIP_DIRS = {
    'node_modules', 'venv', '.venv', '.git', '__pycache__',
    'dist', 'build', '.idea', '.vscode', 'vendor',
    '.terraform', 'coverage', 'target', 'out',
}

# Limit files per scan (keeps GitHub API usage reasonable)
MAX_FILES = 60


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class LeakedCredential:
    """One credential finding from the scanner."""
    access_key:  str
    secret_key:  Optional[str]
    file_path:   str
    line_number: int
    context:     str   # 3-line code snippet around the finding


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_github_url(repo_url: str) -> tuple[str, str]:
    """Return (owner, repo) parsed from a GitHub URL."""
    clean = repo_url.strip().rstrip('/').replace('.git', '')
    clean = clean.replace('https://', '').replace('http://', '')
    parts = clean.split('/')
    if len(parts) < 3 or parts[0] != 'github.com':
        raise ValueError(
            f"'{repo_url}' is not a valid GitHub URL. "
            "Expected: https://github.com/owner/repo"
        )
    return parts[1], parts[2]


def _api_get(url: str, headers: dict) -> requests.Response:
    """GET with basic GitHub API error handling."""
    resp = requests.get(url, headers=headers, timeout=20)
    if resp.status_code == 404:
        raise ValueError("Repository not found or is private.")
    if resp.status_code == 403:
        retry = resp.headers.get('X-RateLimit-Reset', 'soon')
        raise ValueError(
            f"GitHub API rate limit reached. Resets at timestamp {retry}. "
            "Provide a GitHub personal access token to increase the limit."
        )
    resp.raise_for_status()
    return resp


def _get_default_branch(owner: str, repo: str, headers: dict) -> str:
    """Fetch default branch name from GitHub repo metadata."""
    resp = _api_get(f'https://api.github.com/repos/{owner}/{repo}', headers)
    return resp.json().get('default_branch', 'main')


def _get_file_tree(owner: str, repo: str, branch: str, headers: dict) -> list[dict]:
    """Return all blob entries in the repository tree (recursive)."""
    resp = _api_get(
        f'https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1',
        headers,
    )
    return [e for e in resp.json().get('tree', []) if e.get('type') == 'blob']


def _should_scan(path: str) -> bool:
    """Return True if this file path should be scanned."""
    parts = path.split('/')
    # Skip known non-code directories
    for part in parts[:-1]:
        if part in SKIP_DIRS:
            return False
    filename = parts[-1].lower()
    # Allow extensionless config-like files
    if '.' not in filename:
        return filename in {'dockerfile', 'makefile', 'jenkinsfile', 'procfile'}
    ext = '.' + filename.rsplit('.', 1)[-1]
    return ext in SCANNABLE_EXTENSIONS


def _fetch_content(owner: str, repo: str, path: str, branch: str) -> Optional[str]:
    """
    Fetch raw file content from raw.githubusercontent.com.
    This URL does NOT count toward the GitHub API rate limit.
    """
    url = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}'
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.text
        log.debug("[SCANNER] Skipped %s (HTTP %s)", path, resp.status_code)
        return None
    except requests.RequestException as exc:
        log.warning("[SCANNER] Failed to fetch %s: %s", path, exc)
        return None


def _scan_content(content: str, file_path: str) -> list[LeakedCredential]:
    """Scan one file's text for AWS credential patterns."""
    findings: list[LeakedCredential] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines):
        match = ACCESS_KEY_RE.search(line)
        if not match:
            continue

        access_key  = match.group(1)
        line_number = idx + 1

        # Search ±8 lines around the hit for the paired secret key
        block_start = max(0, idx - 8)
        block_end   = min(len(lines), idx + 8)
        search_block = '\n'.join(lines[block_start:block_end])

        secret_key = None

        # Try explicit secret-key keyword pattern first
        sm = SECRET_KEY_RE.search(search_block)
        if sm:
            secret_key = sm.group(1)

        # Fallback: any nearby 40-char string that isn't the access key itself
        if not secret_key:
            for m in GENERIC_40_RE.finditer(search_block):
                candidate = m.group(1)
                if candidate != access_key:
                    secret_key = candidate
                    break

        # Build a 3-line context snippet for the report
        ctx_start = max(0, idx - 1)
        ctx_end   = min(len(lines), idx + 2)
        context   = '\n'.join(lines[ctx_start:ctx_end])

        findings.append(LeakedCredential(
            access_key=access_key,
            secret_key=secret_key,
            file_path=file_path,
            line_number=line_number,
            context=context,
        ))

    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def scan_github_repo(repo_url: str, github_token: Optional[str] = None) -> dict:
    """
    Scan a public GitHub repository for leaked AWS credentials.

    Args:
        repo_url:     e.g. https://github.com/owner/repo
        github_token: Optional PAT to raise rate limits (60 → 5000 req/hr)

    Returns:
        {
            "repo":          str,
            "branch":        str,
            "files_scanned": int,
            "credentials":   [LeakedCredential, ...]
        }
    """
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if github_token:
        headers['Authorization'] = f'token {github_token}'

    owner, repo = _parse_github_url(repo_url)
    branch      = _get_default_branch(owner, repo, headers)
    all_files   = _get_file_tree(owner, repo, branch, headers)

    # Filter and cap the file list
    to_scan = [f for f in all_files if _should_scan(f['path'])][:MAX_FILES]
    log.info("[SCANNER] Repo=%s branch=%s total_files=%d scannable=%d",
             repo_url, branch, len(all_files), len(to_scan))

    credentials: list[LeakedCredential] = []
    files_scanned = 0

    for entry in to_scan:
        log.debug("[SCANNER] Scanning file: %s", entry['path'])
        content = _fetch_content(owner, repo, entry['path'], branch)
        if content is None:
            continue
        files_scanned += 1
        found = _scan_content(content, entry['path'])
        if found:
            log.info("[SCANNER] Found %d credential(s) in %s", len(found), entry['path'])
        credentials.extend(found)

    log.info("[SCANNER] Done. files_scanned=%d total_credentials=%d",
             files_scanned, len(credentials))
    return {
        'repo':          repo_url,
        'branch':        branch,
        'files_scanned': files_scanned,
        'credentials':   credentials,
    }
