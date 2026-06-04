---
name: deep-dive-firebase
description: Use when investigating Firebase exposure on an audited Android app — RTDB rules, Firestore rules, Storage bucket policies, App Check enforcement. Triggers when the user asks about Firebase misconfigurations, public databases, "are the buckets safe", or references specific Firebase project IDs from a prior audit.
---

# deep-dive-firebase

You're investigating Firebase Realtime DB / Firestore / Storage exposure on an Android app. The static pipeline produces unauthenticated AND authenticated (anonymous-Firebase-identity) probes; your job is to interpret them and follow leads.

## How the probes work (important)

- **RTDB**: tries `.json` GETs on common path names, unauthenticated and again with a freshly-minted anonymous Firebase identity.
- **Firestore**: with anon identity, tries: (a) read of `/users/{my own uid}`, (b) list of common collections, (c) unfiltered structured query on `/users`. Rules-driven queries fail at *query time* if rules don't permit unfiltered list — so a 200 `[{readTime}]` response there is a strong signal of overly permissive rules.
- **Storage**: tries unauth bucket listing (Firebase REST + GCS REST) AND 31 common file paths.

A `200 {}` from a Firestore collection is **ambiguous**: could be empty + allowed, or empty + denied (Firebase doesn't differentiate). To resolve, you need a real document ID from dynamic analysis — flag this in the report.

## Decision tree

```
probe/firebase_rtdb.json
├── any path 200 unauthenticated → CRITICAL, fix database.rules.json
├── any path 200 authenticated (auth.uid==null fine) → HIGH, rules are auth!=null, tighten to per-doc owner
└── all 401/404 → ✓ locked (or DB not provisioned)

probe/firebase_firestore.json
├── structured_query_users HTTP 200 with "readTime" snippet → HIGH, rules permit unfiltered list
├── any collection_list returned non-empty body → HIGH, real data leaked
├── DB doesn't exist → ✓ not provisioned
└── all empty → AMBIGUOUS, recommend dynamic capture

probe/firebase_storage.json
├── listing HTTP 200 → CRITICAL, rules_version=2 with allow list
├── publicly_readable_paths non-empty → HIGH, those files are public
└── all 403/404 → ✓ locked (404 = file missing; rules unconfirmed but no exposure surface)
```

## Commands

```bash
cd ~/Documents/auditor

# Re-probe a single project (RTDB + Firestore + Storage in one shot)
uv run clawditor probe-firebase <project>

# Probe a single bucket's path enumeration
uv run clawditor probe-storage <bucket>

# Inspect existing run
uv run clawditor show <run_id> --firebase
cat data/<run>/probe/firebase_rtdb.json | jq .
```

## What to report

For each project (RTDB + Firestore + Storage as one unit):
1. **Status**: LOCKED / PARTIAL / OPEN / NOT-PROVISIONED.
2. If OPEN/PARTIAL, list the specific paths/collections/buckets and the response code that confirmed exposure.
3. If a Firestore collection returned ambiguous `200 {}`, recommend dynamic capture to disambiguate — don't claim it's exposed.
4. Concrete fix: link to the rules file (`firestore.rules`, `database.rules.json`, `storage.rules`) and the recommended deny-all default.

## App Check

If any Identity Toolkit method succeeded (per `probe/google_keys.json`), App Check is NOT enforced project-wide on that endpoint. Recommend enabling App Check with Play Integrity attestation; that's the modern defense against lifted-key abuse regardless of restrictions.

## Boundaries

- Only LIST and READ. Never write.
- The minted anonymous Firebase identity stays in-memory for the run; don't use it for anything else.
- Do not enumerate real users (don't bulk-test `createAuthUri` against real email addresses). The probe already tests with one fake address; that's the proof-of-concept.
