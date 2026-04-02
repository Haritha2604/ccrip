# CCRIP — Complete Beginner's Documentation

> **Cloud Credential Risk Intelligence Platform**
> Written for someone completely new to cloud, cybersecurity, and Python web apps.

---

## Table of Contents

1. [What is this project?](#1-what-is-this-project)
2. [What is a Flask Server?](#2-what-is-a-flask-server)
3. [Why does the browser show 404?](#3-why-does-the-browser-show-404)
4. [What are AWS Credentials?](#4-what-are-aws-credentials)
5. [How aws_connector.py works](#5-how-aws_connectorpy-works)
6. [How permission_analyzer.py works](#6-how-permission_analyzerpy-works)
7. [How mock_logs.json works with real data](#7-how-mock_logsjson-works-with-real-data)
8. [How attack_engine.py detects attacks](#8-how-attack_enginepy-detects-attacks)
9. [How risk_engine.py scores risk](#9-how-risk_enginepy-scores-risk)
10. [How recommendations are generated](#10-how-recommendations-are-generated)
11. [How app.py ties everything together](#11-how-apppy-ties-everything-together)
12. [How the Frontend UI works](#12-how-the-frontend-ui-works)
13. [Complete flow from click to result](#13-complete-flow-from-click-to-result)
14. [File structure explained](#14-file-structure-explained)
15. [How to run the project](#15-how-to-run-the-project)

---

## 1. What is this project?

Imagine someone leaked their AWS cloud account password on the internet.
AWS accounts are like online bank accounts for companies — they store files, run servers, hold databases.

If someone gets your AWS credentials (access key + secret key), they can:
- Steal all your files
- Create hidden backdoor accounts
- Delete everything
- Run up a massive AWS bill

**CCRIP answers the question:**
> "If this credential is leaked — how dangerous is it and what should the owner do?"

It does this by:
1. Connecting to AWS with the leaked key to see what permissions it has
2. Checking mock logs to see what it was used for
3. Simulating what an attacker could do with it
4. Giving a risk score and a clear recommendation

---

## 2. What is a Flask Server?

Flask is a **Python web framework** — it lets Python code listen for requests from a browser or any app and send back responses.

Think of it like a restaurant:

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   BROWSER (Customer)    FLASK (Waiter + Kitchen)        │
│                                                         │
│   "I want to analyze                                    │
│    this credential"  ──────────────────────────────►   │
│                                                         │
│                         Flask receives the request,     │
│                         runs the Python code,           │
│                         prepares the result             │
│                                                         │
│   Gets the report   ◄──────────────────────────────     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

When you run `python app.py`, Flask starts and **listens** for requests at:

```
http://127.0.0.1:5000
     │        │
     │        └── Port 5000 (like a door number in a building)
     └── 127.0.0.1 means "this computer only" (not the internet)
```

It keeps running until you press Ctrl+C.

---

## 3. Why does the browser show 404?

Flask only responds to URLs (routes) you have defined. Our app defines:

```
POST  /analyze   ← the main endpoint (analysis happens here)
GET   /health    ← just says "I am alive"
```

```
What happens when you visit different URLs:

  http://127.0.0.1:5000/          → 404 ❌  No route defined for "/"
  http://127.0.0.1:5000/favicon   → 404 ❌  No route defined
  http://127.0.0.1:5000/health    → 200 ✅  Returns {"status": "ok"}
  http://127.0.0.1:5000/analyze   → needs POST request with JSON body
```

**The 404 is NOT a bug.** It is Flask correctly saying "there is nothing at that address."
Think of it like knocking on door number 5000 — room 1 (/) does not exist, but room /health and room /analyze do.

To confirm the server is alive, open this in your browser:
```
http://127.0.0.1:5000/health
```
You will see: `{"status": "ok"}`
That means everything is working perfectly.

---

## 4. What are AWS Credentials?

AWS (Amazon Web Services) is a cloud platform — it provides storage, servers, databases online.

When a company uses AWS, they create **IAM Users** (like employee accounts).
Each user gets a unique key pair to authenticate themselves:

```
┌──────────────────────────────────────────────────────────┐
│  Access Key ID     →  AKIAIOSFODNN7EXAMPLE               │
│                       (like a username — public ID)       │
│                                                           │
│  Secret Access Key →  wJalrXUtnFEMI/K7MDENG/bPxRfiCY... │
│                       (like a password — must be secret)  │
│                                                           │
│  IAM Username      →  john-dev                           │
│                       (the name of the user in AWS)       │
└──────────────────────────────────────────────────────────┘
```

If someone gets all three of these — they can pretend to be that user and do
whatever that user is allowed to do in AWS.

**Can you use your friend's AWS credentials?**
Yes. AWS credentials are just text strings.
It does not matter which laptop created them or who owns the account.
You can type them into our form and the app will work.

---

## 5. How `aws_connector.py` works

This file is the **only part that talks to real AWS**.

```
aws_connector.py receives:
   access_key = "AKIA..."
   secret_key = "abc123..."
   username   = "john-dev"

         │
         │  Uses boto3 (official AWS Python library)
         │  to create a secure connection to AWS IAM service
         ▼

AWS IAM Service  (Identity and Access Management)
   • Free service — no charges
   • Manages users, permissions, and access keys

         │
         │  boto3 asks AWS:
         │  "List the policies attached to user john-dev"
         │
         │  AWS checks: are these credentials valid?
         ▼

┌─────────────────────────────────────────────────┐
│  INVALID credentials                            │
│  → AWS says "Who are you?"                      │
│  → We catch this and return:                    │
│    {"error": "Invalid AWS credentials"}         │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  VALID credentials                              │
│  → AWS returns policy documents like this:      │
│                                                 │
│  {                                              │
│    "Statement": [{                              │
│      "Effect": "Allow",                         │
│      "Action": [                                │
│         "s3:GetObject",                         │
│         "s3:ListBucket",                        │
│         "iam:CreateUser"                        │
│      ],                                         │
│      "Resource": "*"                            │
│    }]                                           │
│  }                                              │
└─────────────────────────────────────────────────┘
```

These policy documents are raw AWS JSON — complex and technical.
The next module simplifies them.

**Errors handled:**
| AWS Error Code | Meaning | What we return |
|---|---|---|
| `InvalidClientTokenId` | Access key is fake/wrong | "Invalid AWS credentials" |
| `AuthFailure` | Secret key is wrong | "Invalid AWS credentials" |
| `AccessDenied` | Key is valid but can't read IAM | Clear error message |
| `NoSuchEntity` | Username doesn't exist | Empty list (no policies) |

---

## 6. How `permission_analyzer.py` works

AWS policy documents are complex JSON. This module **translates** them into
simple labels that the rest of the system can understand.

```
INPUT: Raw AWS policy document
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "iam:CreateUser", "ec2:RunInstances"]
  }]
}

         │
         │  Loops through every "Allow" statement
         │  Reads each Action
         │  Extracts the service name (part before the colon)
         ▼

"s3:GetObject"     → service = "s3"   → label = S3_ACCESS
"iam:CreateUser"   → service = "iam"  → label = IAM_ACCESS
"ec2:RunInstances" → service = "ec2"  → label = EC2_ACCESS

         │
         ▼

OUTPUT: ["EC2_ACCESS", "IAM_ACCESS", "S3_ACCESS"]
        (sorted alphabetically, duplicates removed)
```

**Label mapping table:**
```
AWS Service     →  Label
─────────────────────────────
s3              →  S3_ACCESS
iam             →  IAM_ACCESS
ec2             →  EC2_ACCESS
lambda          →  LAMBDA_ACCESS
sts             →  STS_ACCESS
secretsmanager  →  SECRETS_ACCESS
kms             →  KMS_ACCESS
rds             →  RDS_ACCESS
dynamodb        →  DYNAMODB_ACCESS
*  (wildcard)   →  FULL_ACCESS  ← Most dangerous!
```

The wildcard `*` means "everything" — a user with `*` action can do
absolutely anything in AWS. That maps to `FULL_ACCESS` which triggers maximum risk.

---

## 7. How `mock_logs.json` works with real data

### What is CloudTrail?

AWS CloudTrail is a service that **records every API call** made using any credential.
It is like CCTV footage for your AWS account.

If someone uses your key to list your S3 files, CloudTrail logs:
```
{
  "eventName": "ListBucket",
  "eventSource": "s3.amazonaws.com",
  "userIdentity": {"userName": "john-dev"}
}
```

### Why we use mock logs instead

Querying real CloudTrail requires:
- CloudTrail to be enabled in the AWS account
- Additional IAM permissions (`cloudtrail:LookupEvents`)
- Can return thousands of events

For this MSc project, we use `mock_logs.json` as a **stand-in** for CloudTrail.
It simulates what the key has been used for.

```
mock_logs.json contains:
[
  "s3:ListBucket",         ← Someone listed S3 buckets
  "s3:GetObject",          ← Someone downloaded a file
  "iam:CreateUser",        ← Someone created a new user ⚠️
  "iam:AttachUserPolicy",  ← Someone gave that user permissions ⚠️
  "ec2:DescribeInstances"  ← Someone checked EC2 instances
]
```

### How this would work with REAL CloudTrail data

In a production system, you would replace the mock file with this boto3 call:

```python
cloudtrail = boto3.client("cloudtrail", ...)
events = cloudtrail.lookup_events(
    LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": username}]
)
# Extract event names from the response
```

The rest of the pipeline (attack engine, risk engine) would work **identically** —
they only care about the list of action strings, not where those strings came from.

---

## 8. How `attack_engine.py` detects attacks

This module contains **6 security rules**. Each rule is a simple True/False check.

Think of it like a checklist a security analyst would use:

```
RULE 1: Privilege Escalation
───────────────────────────
Question: Does the credential have IAM_ACCESS or FULL_ACCESS?
If YES → The attacker can:
         • Create a new hidden admin user in AWS
         • Attach AdministratorAccess policy to it
         • Use that new user forever (even after original key is deleted)
Result: Attack path added ⚡

RULE 2: Data Exfiltration
──────────────────────────
Question: Does the credential have S3_ACCESS or FULL_ACCESS?
If YES → The attacker can:
         • List all storage buckets
         • Download every file (customer data, source code, secrets)
Result: Attack path added ⚡

RULE 3: Persistence
────────────────────
Question: Is "iam:CreateUser" in the logs OR does credential have IAM_ACCESS?
If YES → Either:
         • A backdoor user WAS ALREADY created (seen in logs)
         • A backdoor user CAN be created (has the permission)
Result: Attack path added ⚡

RULE 4: Lateral Movement
─────────────────────────
Question: Does the credential have EC2_ACCESS or FULL_ACCESS?
If YES → The attacker can:
         • Launch new virtual machines inside the company's network
         • From those machines, access internal databases and services
         • Move sideways to systems not directly accessible from internet
Result: Attack path added ⚡

RULE 5: Secret / Key Access
────────────────────────────
Question: Does the credential have SECRETS_ACCESS or KMS_ACCESS or FULL_ACCESS?
If YES → The attacker can:
         • Read AWS Secrets Manager (stores database passwords, API keys)
         • Use KMS to decrypt encrypted data
Result: Attack path added ⚡

RULE 6: Role Assumption / Token Abuse
───────────────────────────────────────
Question: Is "sts:AssumeRole" in logs OR does credential have STS_ACCESS?
If YES → The attacker can:
         • Temporarily become a different, higher-privileged role
         • Bypass permission limits on the original user
Result: Attack path added ⚡
```

Only rules that **fire (return True)** appear in the output. If a credential only has
S3 access, only Rules 2 and possibly 3 would fire.

---

## 9. How `risk_engine.py` scores risk

The risk engine gives a **score from 0 to 100** using an additive points system.
More dangerous permissions and actions = more points.

### Scoring table

**Permissions found (from permission_analyzer):**
```
Permission Label   Points
──────────────────────────
FULL_ACCESS    →   +60
IAM_ACCESS     →   +40
STS_ACCESS     →   +25
SECRETS_ACCESS →   +25
KMS_ACCESS     →   +20
EC2_ACCESS     →   +15
S3_ACCESS      →   +15
LAMBDA_ACCESS  →   +15
RDS_ACCESS     →   +15
DYNAMODB_ACCESS→   +10
```

**Actions seen in logs (from mock_logs.json):**
```
Log Action                        Points
──────────────────────────────────────────
iam:CreateUser              →     +30
iam:AttachUserPolicy        →     +25
iam:CreateAccessKey         →     +25
sts:AssumeRole              →     +20
secretsmanager:GetSecretValue →   +20
s3:DeleteObject             →     +15
ec2:RunInstances            →     +15
s3:GetObject                →     +10
s3:PutObject                →     +10
```

### Example calculation

```
Permissions: IAM_ACCESS (+40), S3_ACCESS (+15)
Logs: iam:CreateUser (+30), s3:GetObject (+10)

Total = 40 + 15 + 30 + 10 = 95
Capped at 100 → Score = 95
```

### Score bands

```
Score       Level      Meaning
──────────────────────────────────────────────────────
 0 – 14  →  LOW      → Minimal risk, routine monitoring
15 – 39  →  MEDIUM   → Some concern, review permissions
40 – 69  →  HIGH     → Significant risk, rotate key soon
70 – 100 →  CRITICAL → Immediate action required
```

---

## 10. How recommendations are generated

Recommendations are **pre-written text** selected based on the risk level.
There is no AI — just four fixed strings, one per severity band.

```
risk_level = "CRITICAL"
     │
     │  risk_engine looks up RECOMMENDATIONS["CRITICAL"]
     ▼

"Disable this AWS access key immediately via the IAM console.
 Rotate all credentials in the account, audit CloudTrail for
 the past 90 days, and check for newly created IAM users or roles."
```

| Level | Recommendation |
|---|---|
| LOW | Monitor CloudTrail, rotate credentials every 90 days |
| MEDIUM | Monitor for unusual activity, consider restricting permissions |
| HIGH | Review and reduce permissions, rotate the key within 24 hours |
| CRITICAL | Disable key immediately, audit everything, check for backdoors |

---

## 11. How `app.py` ties everything together

`app.py` is the **coordinator**. It receives the request and calls each module
in the correct order.

```python
POST /analyze  receives:
{
  "access_key": "AKIA...",
  "secret_key": "...",
  "username":   "john-dev"
}

Step 1: Validate input
        → Are all fields present?
        → Does access_key start with AKIA or ASIA?
        → If not → return error immediately

Step 2: aws_connector.get_user_policies(...)
        → Talks to real AWS
        → Returns policy documents

Step 3: permission_analyzer.extract_permissions(...)
        → Converts policies → labels
        → Returns ["IAM_ACCESS", "S3_ACCESS"]

Step 4: Load mock_logs.json
        → Returns ["s3:ListBucket", "iam:CreateUser", ...]

Step 5: attack_engine.simulate_attacks(permissions, activity)
        → Runs all 6 rules
        → Returns list of triggered attack paths

Step 6: risk_engine.calculate_risk(permissions, activity)
        → Calculates score, level, recommendation

Step 7: Build final response and return to browser
{
  "permissions":    ["IAM_ACCESS", "S3_ACCESS"],
  "activity":       ["s3:ListBucket", "iam:CreateUser"],
  "attack_paths":   [{"attack": "Privilege Escalation", "description": "..."}],
  "risk_score":     85,
  "risk_level":     "CRITICAL",
  "recommendation": "Disable this key immediately..."
}
```

---

## 12. How the Frontend UI works

The frontend is a single HTML file (`frontend/index.html`).
It runs entirely in your browser — no second server needed.

```
index.html contains:

┌─────────────────────────────────────────────────────────┐
│  HTML  →  The structure (form, panels, cards)           │
│  CSS   →  The dark theme, colors, layout                │
│  JS    →  The logic (read inputs, call API, show result)│
└─────────────────────────────────────────────────────────┘
```

### What JavaScript does step by step

```
1. User fills 3 inputs and clicks "Analyze"
        │
2. JS reads the values from the input boxes
        │
3. JS sends a POST request to http://127.0.0.1:5000/analyze
   (this is called fetch() — like the browser making a form submission)
        │
4. Flask receives it, runs all the modules, sends back JSON
        │
5. JS reads the JSON response
        │
6. JS updates the page:
   • Fills the risk badge with CRITICAL / HIGH / MEDIUM / LOW
   • Animates the progress bar to the score
   • Creates blue pills for each permission
   • Creates green pills for each log action
   • Creates red attack cards for each attack path
   • Shows the recommendation text
```

### Security note

All text from the API response is **HTML-escaped** before being shown on screen.
This prevents a malicious API response from injecting fake HTML into your page (XSS attack).

---

## 13. Complete flow from click to result

```
[BROWSER]  You open frontend/index.html
           Fill: Access Key, Secret Key, Username
           Click: "Analyze Credential"
               │
               │ fetch() sends HTTP POST
               │ to http://127.0.0.1:5000/analyze
               │
               ▼
[FLASK]    app.py receives the request
               │
               ├─ Validate inputs ──────────────────────────► Error if invalid
               │
               ▼
[MODULE 1] aws_connector.py
           Uses boto3 to call AWS IAM
               │
               │ Real network request to AWS servers
               │
               ▼
[AWS]      IAM Service checks credentials
               │
               ├─ Invalid key ──────────────────────────────► 401 error back
               │
               └─ Valid key → returns policy JSON
               │
               ▼
[MODULE 2] permission_analyzer.py
           Reads policy JSON
           Maps actions → labels
           Output: ["IAM_ACCESS", "S3_ACCESS"]
               │
               ▼
[FILE]     mock_logs.json
           Loaded at startup
           Output: ["s3:ListBucket", "iam:CreateUser", ...]
               │
               ▼
[MODULE 3] attack_engine.py
           Checks 6 rules using permissions + logs
           Output: [
             {attack: "Privilege Escalation", description: "..."},
             {attack: "Data Exfiltration",    description: "..."},
             {attack: "Persistence",          description: "..."}
           ]
               │
               ▼
[MODULE 4] risk_engine.py
           Adds up points from permissions + logs
           Score: 85 → Level: CRITICAL
           Output: {score: 85, level: "CRITICAL", recommendation: "Disable..."}
               │
               ▼
[FLASK]    app.py builds final JSON response
               │
               │ HTTP response sent back to browser
               │
               ▼
[BROWSER]  JavaScript receives the JSON
           Updates the page:
           • 🔴 CRITICAL badge appears
           • Progress bar fills to 85%
           • Permission pills shown
           • Activity pills shown
           • Attack cards shown
           • Recommendation shown
```

---

## 14. File structure explained

```
ccrip/
│
├── backend/                    ← All Python / Flask code lives here
│   │
│   ├── app.py                  ← Entry point. Starts Flask. Defines /analyze route.
│   │                             Receives request → calls all modules → returns result
│   │
│   ├── aws_connector.py        ← The only file that talks to REAL AWS
│   │                             Uses boto3. Fetches IAM policy documents.
│   │
│   ├── permission_analyzer.py  ← Takes raw AWS policy JSON
│   │                             Converts it to simple labels like IAM_ACCESS
│   │
│   ├── attack_engine.py        ← 6 security rules
│   │                             Checks which attacks are possible given the labels
│   │
│   ├── risk_engine.py          ← Adds up points for each permission and log action
│   │                             Returns score 0-100 + level + recommendation
│   │
│   ├── mock_logs.json          ← Fake CloudTrail activity log
│   │                             List of API calls the key has made
│   │
│   └── requirements.txt        ← Python packages needed to run the project
│
├── frontend/
│   └── index.html              ← The web UI. Open this in your browser.
│                                 Has the form, sends POST to Flask, shows results.
│
├── .gitignore                  ← Tells git which files NOT to upload
│                                 (venv folder, __pycache__, .env files etc.)
│
└── DOCUMENTATION.md            ← This file
```

---

## 15. How to run the project

### First time setup

```bash
# 1. Go to the project folder
cd C:\Users\MHa668\ccrip

# 2. Create a virtual environment
#    (isolated Python environment — like a clean room just for this project)
python -m venv venv

# 3. Activate it (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# 4. Install all packages
pip install -r backend/requirements.txt
```

### Every time after that

```bash
# 1. Go to project folder and activate venv
cd C:\Users\MHa668\ccrip
.\venv\Scripts\Activate.ps1

# 2. Start Flask
cd backend
python app.py

# 3. Open the UI
#    Double-click: C:\Users\MHa668\ccrip\frontend\index.html
```

### Test without real AWS

Open PowerShell and run:
```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/health -Method GET
```
Expected: `{"status": "ok"}`

### Use with real AWS credentials

1. Create an AWS free account at https://aws.amazon.com/free
2. Go to IAM → Create User (e.g. `test-user`)
3. Attach policy: `IAMReadOnlyAccess`
4. Create an Access Key for that user
5. Open `frontend/index.html` in browser
6. Fill in the 3 fields and click Analyze

---

## Quick Reference — What each module does in one sentence

| File | One-line purpose |
|---|---|
| `app.py` | Receives HTTP requests and calls all other modules in order |
| `aws_connector.py` | Asks AWS "what permissions does this user have?" |
| `permission_analyzer.py` | Converts complex AWS policy JSON into simple labels |
| `mock_logs.json` | Pretends to be CloudTrail — a list of past API calls |
| `attack_engine.py` | Checks 6 rules to find what attacks are possible |
| `risk_engine.py` | Adds up points and assigns LOW / MEDIUM / HIGH / CRITICAL |
| `frontend/index.html` | The web page with the form and results dashboard |

---

*CCRIP — MSc Project — Cloud Credential Risk Intelligence Platform*
