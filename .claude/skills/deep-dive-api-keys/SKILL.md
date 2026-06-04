---
name: deep-dive-api-keys
description: Use when the user wants to investigate Google API key exposure on an already-audited app — confirm restrictions, identify abuse vectors (SMS pumping, user enumeration, quota burn, billable APIs), and produce a per-key remediation list. Triggers when the user mentions a specific AIzaSy key, asks "are these keys safe?", asks about API restrictions, asks about Firebase Auth abuse, or references an existing clawditor run.
---

# deep-dive-api-keys

You're investigating Google API key exposure on an Android app that has already been audited (or you can audit it first). The static pipeline (`clawditor`) already enumerates keys and runs a 36-service restriction matrix per key; your job is to interpret the results and follow specific leads.

## Pre-reqs

- A completed `clawditor` run, OR a list of AIzaSy keys to test. If no run exists, run `clawditor run <pkg or apk>` first.

## Decision tree

```
For each key in probe/google_keys.json:
├── verdict contains "LEAKED"
│   └── CRITICAL — Google's leaked-key detector flagged it
│       → rotate immediately; check GCP billing for last 90 days
├── any service verdict is "SUCCESS"
│   └── That service accepts the key with no restriction
│       → If Translate / Vision / TextToSpeech / NL / Speech / Video / YouTube:
│           billable-API drain vector
│       → If Identity Toolkit signUp: anonymous-user spawn vector
│       → If Identity Toolkit createAuthUri: user-enumeration vector
├── "REACHED_ERR" on Identity Toolkit sendVerificationCode
│   └── SMS pumping vector — disable phone auth, restrict countries, enable App Check
├── "REACHED_ERR" on Identity Toolkit sendOobCode
│   └── password-reset spam vector
├── No "BLOCKED_ANDROID" anywhere
│   └── Key has no Android package restriction
│       → add package + SHA-1 restriction in GCP Console
└── Mostly "BLOCKED_METHOD" / "API_DISABLED"
    └── Well-restricted; note exact restriction posture
```

## Commands

```bash
# Inspect an existing run's key matrix
cd ~/Documents/auditor
uv run clawditor show <run_id> --keys

# Re-probe a single key in detail (prints colored table)
uv run clawditor probe-key AIzaSyXXX...

# Read structured data directly
cat data/<run>/probe/google_keys.json | jq '.[] | select(.summary.SUCCESS or .summary.LEAKED)'
```

## What to report to the user

1. Per-key one-line verdict: `RESTRICTED / METHOD-LOCKED / OPEN / LEAKED`.
2. List of abusable services per key (the SUCCESS + REACHED_ERR ones, grouped by abuse class).
3. Concrete rotation/restriction actions (use `reports/next-steps.md` as a starting point — that file already contains hints for each finding type).
4. Estimated financial impact only if a key has SUCCESS on a billable API (Translate, Vision, Speech, TextToSpeech, NL, Video Intelligence, YouTube) AND signUp succeeds (so an attacker can chain abuse with auth context).

## Boundaries

- Never actually trigger an SMS or email. The probe uses deliberately invalid params; if extending, preserve that property.
- Never use a minted anonymous Firebase identity for anything beyond the rule-boundary tests already in `probe/firebase_firestore.py` and `probe/firebase_rtdb.py`.
- The leaked-key detector running on a key (LEAKED verdict) means Google found the key in a public corpus; reporting this to the user is just confirming public information — but treat the underlying compromise as real.
