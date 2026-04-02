# Cloud Credential Risk Intelligence Platform (CCRIP)

> **MSc Project** — A Python/Flask system that scans GitHub repositories for leaked
> AWS credentials, validates them, analyses their risk, simulates attack paths,
> and recommends remediation actions.

---

## Table of Contents

1. [What is CCRIP?](#1-what-is-ccrip)
2. [How it Works — Big Picture](#2-how-it-works--big-picture)
3. [Features](#3-features)
4. [Tech Stack](#4-tech-stack)
5. [Project Structure](#5-project-structure)
6. [Setup Instructions](#6-setup-instructions)
7. [Running the Application](#7-running-the-application)
8. [Using the Web UI](#8-using-the-web-ui)
9. [API Reference](#9-api-reference)
10. [Pipeline Layers Explained](#10-pipeline-layers-explained)
11. [Risk Scoring System](#11-risk-scoring-system)
12. [AWS Safety Notes](#12-aws-safety-notes)
13. [Sending the Project to Someone Else](#13-sending-the-project-to-someone-else)

---

## 1. What is CCRIP?

AWS credentials (access keys) are frequently leaked by developers who accidentally
commit them to public GitHub repositories. CCRIP automates the process of:

1. **Scanning** a GitHub repository for hardcoded AWS credentials
2. **Validating** whether the credential is still active (using AWS STS)
3. **Enriching** active credentials with their real IAM permissions
4. **Analysing** what an attacker could do with those credentials
5. **Scoring** the risk from 0–100 and classifying it as LOW / MEDIUM / HIGH / CRITICAL
6. **Recommending** specific remediation actions

Everything is presented through a dark-themed web dashboard — no command line needed.

---

## 2. How it Works — Big Picture

```
User enters a GitHub repo URL in the browser
              |
              v
      [ scanner.py ]
      Scans every source file in the repo
      looking for AKIA.../ASIA... key patterns
              |
              v
      [ ingestion.py ]
      Removes duplicate findings
      (same key found in multiple files)
              |
              v
      [ validator.py ]
      Calls AWS STS GetCallerIdentity
      Marks credential: ACTIVE / INACTIVE / NO_SECRET
              |
              v
      [ aws_connector.py ]  (ACTIVE keys only)
      Fetches real IAM policies from AWS
              |
              v
      [ permission_analyzer.py ]
      Converts policy JSON into simple labels
      e.g. "s3:GetObject" -> S3_ACCESS
              |
              v
      [ intelligence.py ]
      Builds activity timeline
      Classifies intent (Recon / Exploitation / Exfiltration)
      Detects anomalies in behaviour
              |
              v
      [ attack_engine.py ]
      Runs 6 rule-based attack simulations
      e.g. IAM_ACCESS -> Privilege Escalation attack possible
              |
              v
      [ correlation.py ]  (when multiple credentials found)
      Groups credentials by AWS account
      Identifies shared risks and chained attack paths
              |
              v
      [ risk_engine.py ]
      Calculates score 0-100
      Maps to LOW / MEDIUM / HIGH / CRITICAL
              |
              v
      [ decision_engine.py ]
      Assigns priority P1-P4
      Generates ordered remediation steps
              |
              v
      Web Dashboard shows full report
```

---

## 3. Features

| Feature | Details |
|---|---|
| GitHub Repo Scanner | Regex-based scan — finds `AKIA...` / `ASIA...` AWS keys in source files |
| Credential Deduplication | Same key found in multiple files is analysed only once |
| STS Validation | Uses `GetCallerIdentity` to confirm if the key is still active (free API call) |
| IAM Enrichment | Fetches real attached policies for active credentials via boto3 |
| Permission Labels | Maps raw IAM actions to readable labels (`IAM_ACCESS`, `S3_ACCESS`, etc.) |
| Intelligence Analysis | Timeline reconstruction, intent classification, anomaly detection |
| Attack Simulation | 6 rule-based attacks: Privilege Escalation, Data Exfiltration, Persistence, Lateral Movement, Secret Access, Role Abuse |
| Correlation Engine | Groups credentials by AWS account, detects shared risks and chained attacks |
| Risk Scoring | Additive 0–100 score  LOW / MEDIUM / HIGH / CRITICAL |
| Decision Engine | P1-P4 priority with specific, ordered remediation steps |
| Web Dashboard | Dark-themed UI with 7-tab per-credential breakdown |
| Mock CloudTrail | Simulates API activity logs (replaces real CloudTrail for demo purposes) |

---

## 4. Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Web framework | Flask 3 + Flask-CORS |
| AWS SDK | boto3 / botocore |
| GitHub API | requests (REST v3) |
| Frontend | Plain HTML + CSS + JavaScript (no framework) |
| AWS services used | IAM (read-only), STS (free) — no paid services |
| Activity data | Local `mock_logs.json` (CloudTrail simulation) |

---

## 5. Project Structure

```
ccrip/
|
+-- backend/
|   |
|   +-- app.py                   # Flask server — orchestrates the pipeline
|   +-- scanner.py               # GitHub repo scanner (Gitleaks-style regex)
|   +-- ingestion.py             # Deduplicates raw findings
|   +-- validator.py             # STS credential validation (ACTIVE/INACTIVE)
|   +-- aws_connector.py         # IAM policy fetcher (real AWS)
|   +-- permission_analyzer.py   # IAM JSON -> permission labels
|   +-- intelligence.py          # Timeline, intent, anomaly detection
|   +-- attack_engine.py         # 6 rule-based attack simulations
|   +-- correlation.py           # Multi-credential cross-analysis
|   +-- risk_engine.py           # 0-100 risk score + level
|   +-- decision_engine.py       # Priority + remediation steps
|   +-- mock_logs.json           # Simulated CloudTrail activity
|   +-- requirements.txt         # Python dependencies
|   +-- README.md                # This file
|
+-- frontend/
|   +-- index.html               # Web dashboard (open in browser)
|
+-- DOCUMENTATION.md             # Full beginner-friendly explanation of every module
+-- .gitignore                   # Excludes venv, __pycache__, .env, etc.
```

---

## 6. Setup Instructions

### Prerequisites

- Python 3.11 or higher installed
- Internet access (to reach GitHub API and AWS)
- A public GitHub repository to scan (your own or any public repo)

> No AWS account is required just to try the scanner.
> An AWS account is only used when validating or enriching an ACTIVE credential found in a repo.

---

### Step 1 — Get the project

**Option A — Clone from GitHub:**
```bash
git clone https://github.com/your-org/ccrip.git
cd ccrip
```

**Option B — Extract from zip:**
```
Unzip ccrip_project.zip
Open the extracted ccrip/ folder
```

---

### Step 2 — Create a virtual environment

A virtual environment keeps this project's packages separate from your system Python.

```bash
# Windows
python -m venv venv

# macOS / Linux
python3 -m venv venv
```

---

### Step 3 — Activate the virtual environment

```bash
# Windows — PowerShell
.\venv\Scripts\Activate.ps1

# Windows — Command Prompt
venv\Scripts\activate.bat

# macOS / Linux
source venv/bin/activate
```

You will see `(venv)` at the start of your terminal prompt when it is active.

---

### Step 4 — Install dependencies

```bash
pip install -r backend/requirements.txt
```

This installs:
- `flask==3.0.3` — web server
- `flask-cors==4.0.1` — allows the browser to talk to Flask
- `boto3==1.34.84` — AWS SDK
- `botocore==1.34.84` — AWS core library
- `requests==2.31.0` — GitHub API calls

---

## 7. Running the Application

### Start the Flask server

```bash
# Make sure venv is active first
cd backend
python app.py
```

Expected output:
```
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

**Leave this terminal open.** The server must be running while you use the UI.

---

### Confirm the server is alive

Open this URL in your browser:
```
http://127.0.0.1:5000/health
```
Expected response: `{"status": "ok"}`

---

## 8. Using the Web UI

1. Open `frontend/index.html` by double-clicking it in File Explorer
2. Enter a public GitHub repository URL, for example:
   ```
   https://github.com/owner/repo
   ```
3. Optionally enter a GitHub personal access token (raises rate limit from 60 to 5000 requests/hour)
4. Click **Scan Repo**
5. Wait for the scan to complete — results appear automatically

### What you will see

| Section | What it shows |
|---|---|
| Scan Summary | Files scanned, credentials found, how many are still active |
| Overall Risk | Highest risk level across all credentials found |
| Credential Cards | One expandable card per unique credential |
| Location tab | Which file and line number the key was found |
| Validation tab | ACTIVE / INACTIVE status from AWS STS |
| Permissions tab | IAM labels + observed activity from mock logs |
| Intelligence tab | Attack timeline, intent classification, anomaly alerts |
| Attacks tab | Attack paths an adversary could take |
| Risk tab | Score (0-100) + level + recommendation |
| Decision tab | Priority (P1-P4) + specific remediation steps |
| Correlation panel | Shared risks when multiple credentials are found |

---

## 9. API Reference

The Flask backend exposes three endpoints.

---

### POST /scan   Primary endpoint

Scans a GitHub repository and returns a full risk report.

**Request:**
```json
{
  "repo_url": "https://github.com/owner/repo",
  "github_token": "ghp_..."
}
```
> `github_token` is optional. Without it, GitHub allows 60 API requests/hour.

**Response:**
```json
{
  "repo": "https://github.com/owner/repo",
  "scan_summary": {
    "branch": "main",
    "files_scanned": 23,
    "credentials_found": 2,
    "active_credentials": 1
  },
  "overall_risk": "CRITICAL",
  "credentials": [
    {
      "access_key": "AKIAIOSFODNN7EXAMPLE",
      "has_secret": true,
      "occurrences": [
        { "file_path": "config.py", "line_number": 12, "context": "..." }
      ],
      "validation": {
        "status": "ACTIVE",
        "account_id": "123456789012",
        "arn": "arn:aws:iam::123456789012:user/john-dev",
        "reason": "Credential is valid and currently active."
      },
      "permissions": ["IAM_ACCESS", "S3_ACCESS"],
      "activity": ["s3:ListBucket", "iam:CreateUser"],
      "intelligence": {
        "timeline": [{ "step": 1, "action": "s3:ListBucket", "phase": "Reconnaissance" }],
        "intent": ["Reconnaissance", "Persistence"],
        "anomalies": ["New IAM user created — possible backdoor account."]
      },
      "attack_paths": [
        { "attack": "Privilege Escalation", "description": "..." },
        { "attack": "Data Exfiltration",    "description": "..." }
      ],
      "risk_score": 100,
      "risk_level": "CRITICAL",
      "recommendation": "Disable this key immediately...",
      "decision": {
        "priority": "P1 — Respond Immediately (within 1 hour)",
        "remediation_steps": ["Disable the access key...", "Audit CloudTrail..."],
        "dependency_warning": "This key is ACTIVE. Check for services using it before deleting."
      }
    }
  ],
  "correlation": {
    "accounts": { "123456789012": ["AKIAIOSFODNN7EXAMPLE"] },
    "shared_risks": ["Multiple credentials belong to the SAME AWS account."],
    "summary": "2 credential(s) found across 1 AWS account(s). 1 currently active."
  }
}
```

---

### POST /analyze   Legacy endpoint

Manual credential input (from the original flow — kept for backward compatibility).

**Request:**
```json
{
  "access_key": "AKIAIOSFODNN7EXAMPLE",
  "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "username": "john-dev"
}
```

**Response:**
```json
{
  "permissions":    ["IAM_ACCESS", "S3_ACCESS"],
  "activity":       ["s3:ListBucket", "iam:CreateUser"],
  "attack_paths":   [{ "attack": "Privilege Escalation", "description": "..." }],
  "risk_score":     100,
  "risk_level":     "CRITICAL",
  "recommendation": "Disable this key immediately..."
}
```

---

### GET /health

Liveness check. Returns `{"status": "ok"}` if the server is running.

---

### HTTP Error Codes

| Code | Meaning |
|---|---|
| 400 | Missing/invalid input (bad URL, missing fields) |
| 401 | AWS credentials rejected |
| 500 | Unexpected server error |

---

## 10. Pipeline Layers Explained

| Layer | File | What it does |
|---|---|---|
| External Input | `scanner.py` | Regex-scans every file in the GitHub repo for `AKIA...` / `ASIA...` patterns and nearby secret keys |
| Ingestion | `ingestion.py` | Groups findings by access key, removes duplicates, picks the best secret key found |
| Validation | `validator.py` | Calls `sts:GetCallerIdentity` — the only free AWS call that confirms if a key is still active |
| Enrichment | `aws_connector.py` | For active keys only — fetches the actual IAM managed policies from AWS |
| Permission Processing | `permission_analyzer.py` | Converts raw IAM JSON statements into labels like `S3_ACCESS`, `IAM_ACCESS`, `FULL_ACCESS` |
| Intelligence | `intelligence.py` | Builds a timeline, classifies intent (Reconnaissance/Exploitation/Exfiltration/Persistence), flags anomalies |
| Attack Simulation | `attack_engine.py` | Runs 6 rule checks — if IAM_ACCESS is present, Privilege Escalation fires; if S3_ACCESS, Data Exfiltration fires; etc. |
| Correlation | `correlation.py` | Groups credentials by AWS account ID, detects shared risks when multiple keys are found |
| Risk Engine | `risk_engine.py` | Adds weighted points per permission label and per log action; caps at 100; bands into LOW/MEDIUM/HIGH/CRITICAL |
| Decision Engine | `decision_engine.py` | Maps risk level to P1-P4 priority; adds specific remediation steps based on which attacks fired |
| Output | `app.py` + `index.html` | Combines all results into one JSON response, rendered as an interactive web dashboard |

---

## 11. Risk Scoring System

### Points per permission label

| Label | Points |
|---|---|
| FULL_ACCESS | +60 |
| IAM_ACCESS | +40 |
| STS_ACCESS | +25 |
| SECRETS_ACCESS | +25 |
| KMS_ACCESS | +20 |
| EC2_ACCESS | +15 |
| S3_ACCESS | +15 |
| LAMBDA_ACCESS | +15 |
| RDS_ACCESS | +15 |
| DYNAMODB_ACCESS | +10 |

### Points per log action (mock CloudTrail)

| Action | Points |
|---|---|
| iam:CreateUser | +30 |
| iam:AttachUserPolicy | +25 |
| iam:CreateAccessKey | +25 |
| sts:AssumeRole | +20 |
| secretsmanager:GetSecretValue | +20 |
| s3:DeleteObject | +15 |
| ec2:RunInstances | +15 |
| s3:GetObject | +10 |
| s3:PutObject | +10 |

### Risk bands

| Score | Level | Response time |
|---|---|---|
| 0–14 | LOW | Next maintenance window |
| 15–39 | MEDIUM | Within 72 hours |
| 40–69 | HIGH | Within 24 hours |
| 70–100 | CRITICAL | Within 1 hour |

---

## 12. AWS Safety Notes

- **Never hardcode credentials** in source files — use environment variables or AWS Secrets Manager
- **Rotate access keys** every 90 days at most — use IAM's built-in key age reporting
- **Enable AWS CloudTrail** in every region to detect credential misuse early
- **Enable AWS GuardDuty** for automated anomaly detection (e.g. calls from unusual IPs)
- **Use IAM roles** instead of long-term access keys wherever possible (EC2, Lambda, ECS)
- **Enable MFA** on all IAM users, especially those with admin access
- The `sts:GetCallerIdentity` call used by CCRIP is **completely free** and does not require any IAM permissions
- CCRIP is an educational/research tool — it is not a replacement for a full CSPM solution

---

## 13. Sending the Project to Someone Else

The project is distributed as `ccrip_project.zip`. The zip contains only the
necessary source files — `venv/` and `__pycache__/` are excluded.

When someone receives the zip, they follow the same steps:

```bash
# 1. Extract the zip and go into the folder
cd ccrip

# 2. Create their own virtual environment
python -m venv venv

# 3. Activate it (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# 4. Install all packages
pip install -r backend/requirements.txt

# 5. Start the server
cd backend
python app.py

# 6. Open frontend/index.html in their browser
```

The Flask server runs on their machine (`http://127.0.0.1:5000`) — this is not the internet,
it is just their own laptop talking to itself.

They can then scan any public GitHub repo URL they choose.

---

*CCRIP — Cloud Credential Risk Intelligence Platform — MSc Project*
