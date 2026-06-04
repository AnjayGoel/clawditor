---
name: understand-findings
description: Use when a user asks "what does this finding mean" / "is this real" / "how serious is this" about an entry in findings.json or SUMMARY.md from an clawditor run. Triggers when explaining audit results, justifying a severity rating, or unpacking a verdict like BLOCKED_METHOD vs API_DISABLED vs REACHED_ERR.
---

# understand-findings

Decode a finding from `reports/findings.json` or a verdict from `probe/google_keys.json` into a plain-English explanation: what it means, why it matters at the assigned severity, what would change that severity, and what the user should do.

## Files to consult

- `reports/findings.json` — structured findings list
- `reports/SUMMARY.md` — human-readable summary
- `reports/deep-dive-guide.md` — guidance per category
- `MANIFEST.md` — entry point for the whole run
- `docs/finding-categories.md` (in the clawditor project root) — reference for what each `category` value means
- `docs/probe-verdicts.md` — reference for what each probe verdict means

## How to explain a finding

For any finding, return:

1. **One-sentence plain-English summary** of what the finding actually is.
2. **Why this severity** — what the assigned `severity` is based on, and what would push it up or down (e.g. "MEDIUM because the WebView is non-exported; would become CRITICAL if the URL parameter ever comes from server config").
3. **Confidence** — is this a confirmed live issue (trufflehog verified, active probe SUCCESS), a high-confidence static signal (AIzaSy key present), or a heuristic (apkleaks Authorization_Basic regex)?
4. **Next investigation step** — which file to read, which subcommand to run, what to look for.
5. **Fix sketch** — one or two lines.

## How to explain a probe verdict

| Verdict | Plain English |
|---|---|
| `SUCCESS` | Call returned data. The key + endpoint combination is fully open. The worst outcome. |
| `LEAKED` | Google's automated leak detector has fired on this key. They found it in a public corpus they monitor (Github, paste sites, app stores). The key may still work on APIs other than the one(s) Google blocked. |
| `REACHED_ERR(...)` | The call passed all GCP-side gates (key valid, API enabled, method allowed, no Android/IP/referrer block) and was rejected only by the application layer (e.g. invalid argument we sent deliberately). **Means the endpoint is reachable**; with valid input it would succeed. |
| `BLOCKED_ANDROID` | Key has an Android-package + SHA-1 restriction; refuses calls without matching headers. The safest restriction posture. |
| `BLOCKED_API_RESTR` | Key has an API restriction list; this API isn't on it. Good. |
| `BLOCKED_METHOD` | Key has per-method restrictions; this method isn't allowed. Good. |
| `BLOCKED_REFERRER` / `BLOCKED_IP` | HTTP-referrer or IP restriction. Stronger than nothing but doesn't help on mobile apps. |
| `API_DISABLED` | The API isn't enabled on the project. The key reaches the project (so passes any Android/API restriction check); only the project-level "not enabled" gate is stopping it. Flipping the API on instantly opens the key. |
| `KEY_INVALID` | Key was revoked / never valid. Safe. |
| `QUOTA` | Rate-limited; verdict inconclusive. |
| `MAPS_REQUEST_DENIED` | Google Maps API rejected; check the inner message for the reason. |

## Boundaries

Don't invent severity rationales not present in `docs/finding-categories.md` or in this skill. If unsure, say so and propose what additional info would resolve it.
