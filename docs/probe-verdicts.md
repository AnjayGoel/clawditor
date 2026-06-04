# Probe verdicts — reference

The `clawditor.probe._http.classify()` function maps every probe response to one of these verdicts. This document tells you what each means, what it implies for the key/endpoint posture, and how it should be weighted in a report.

| Verdict | Meaning | Implication for security posture |
|---|---|---|
| `SUCCESS` | Call returned a 2xx with no error envelope. The endpoint is fully open. | **Worst outcome.** Key + endpoint accept arbitrary callers. Often billable. |
| `LEAKED` | Google's automated key-leak detector has flagged the key. The detector usually fires on Gemini specifically but the key may still work elsewhere. | **CRITICAL.** Google found the key in a public corpus. Rotate today. |
| `REACHED_ERR(STATUS)` | Call passed every GCP-side gate (key valid, API enabled, method allowed, no Android/IP/referrer restriction) and was rejected only by app-level validation (e.g. invalid argument we sent deliberately). | **Endpoint is reachable.** With valid input, this call would succeed. |
| `BLOCKED_ANDROID` | Response: "Requests from this Android client application … are blocked." | Key has package + SHA-1 restriction. **The safest posture.** Calls from non-app contexts (curl, server, attacker's tools) fail before reaching the API. |
| `BLOCKED_API_RESTR` | Response indicates API-restriction-list rejection ("not authorized to use this service / API restrictions"). | Key has an explicit allowlist of which Google APIs it can call; this API isn't on it. **Good** layer of defense. |
| `BLOCKED_METHOD` | Response indicates per-method restriction ("Requests to this API … method … are blocked"). | Key has per-method restrictions; this method isn't allowed. **Good** layer; per-method is more granular than per-API. |
| `BLOCKED_REFERRER` / `BLOCKED_IP` | HTTP Referer / IP restriction. | Defense exists but irrelevant for mobile apps (curl can fake Referer; mobile IPs change). |
| `API_DISABLED` | Response: "API has not been used in project N before or it is disabled." | Project owner hasn't turned on this API. **Key reaches the project**, so it passes any Android/API restriction check; only the project-level disable is stopping it. Flipping the API on instantly opens the key. |
| `KEY_INVALID` | Response: "API key not valid. Please pass a valid API key." | Key revoked or never existed. **Safe** — but worth knowing it's still shipping in the binary. |
| `QUOTA` | Rate-limited (HTTP 429 or `RESOURCE_EXHAUSTED`). | Inconclusive. Re-probe later. |
| `MAPS_REQUEST_DENIED` | Google Maps API returned `status: REQUEST_DENIED`. | Read `error_message` for the actual reason — could be API not activated, legacy API gone, or Maps-platform-specific restriction. |
| `HTTPNNN` | Got a non-2xx HTTP status with a non-JSON body. | Probably deprecated endpoint. |
| `NON_JSON` | Got 2xx but the body wasn't JSON. | Inspect the snippet — could be HTML error page, plain-text response. |

## How to read a key's full row

For a single key, the verdict counts across all ~36 services tell you the posture:

- **Mostly `BLOCKED_ANDROID`** — well-restricted at the package level. Best.
- **No `BLOCKED_ANDROID`, mostly `BLOCKED_METHOD` / `BLOCKED_API_RESTR`** — no Android restriction but method/API restrictions are in place. OK but vulnerable to lifted-key abuse.
- **Mostly `API_DISABLED`, no `BLOCKED_*`** — fragile; project owner enabling any API opens that surface.
- **Any `SUCCESS` or `LEAKED`** — actively abusable.

## The Identity Toolkit nuance

The `accounts:*` methods on `identitytoolkit.googleapis.com` are special: they're how Firebase Auth works, so they're enabled in essentially every Firebase project. The verdicts to watch:

- `signUp` SUCCESS → anyone can create anonymous Firebase identities. Becomes an auth context for Firestore/Storage rules requiring `auth != null`.
- `signUp` ADMIN_ONLY_OPERATION → anonymous auth is OFF in the project. Method reachable but blocked at config layer.
- `signUp` CONFIGURATION_NOT_FOUND → email/password auth not configured. Same shape as above.
- `sendVerificationCode` REACHED_ERR (INVALID_PHONE_NUMBER) → SMS endpoint reachable. **With a real phone number, this sends an SMS billed to the project.** SMS pumping vector.
- `sendOobCode` REACHED_ERR (EMAIL_NOT_FOUND) → email endpoint reachable. **With a real email, this sends a password-reset email.** Spam vector.
- `createAuthUri` SUCCESS with `registered: true/false` field → **user enumeration**. Bulk-testable.
- `signInWithPassword` REACHED_ERR → credential stuffing endpoint reachable.
