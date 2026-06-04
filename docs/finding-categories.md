# Finding categories — what each `category` value means in `findings.json`

| Category | Source JSON | What it indicates | Severity range |
|---|---|---|---|
| `manifest` | `scan/manifest.json` | AndroidManifest analysis: exported components, cleartext, backup, debuggable, deeplinks | LOW to HIGH |
| `secrets` | `scan/secrets.json` | Custom regex hits for API keys, JWTs, OAuth IDs, etc. | INFO to HIGH |
| `code` | `scan/code_patterns.json` | Dangerous code patterns: WebView misconfig, weak crypto, cert validation bypass, SQL string concat | INFO to CRITICAL |
| `apkleaks` | `scan/apkleaks.json` | apkleaks regex sweep — high volume, mixed signal | INFO to HIGH |
| `trufflehog` | `scan/trufflehog.json` | Trufflehog secret hits (verified = live) | MEDIUM to CRITICAL |
| `google_key` | `probe/google_keys.json` | Per-key restriction matrix verdicts (LEAKED, SUCCESS, REACHED_ERR per service) | INFO to CRITICAL |
| `firebase_rtdb` | `probe/firebase_rtdb.json` | RTDB rule probes (unauth + anon-auth common paths) | HIGH to CRITICAL |
| `firebase_firestore` | `probe/firebase_firestore.json` | Firestore rule probes (list, owner-doc read, unfiltered structured query) | HIGH |
| `firebase_storage` | `probe/firebase_storage.json` | Storage bucket probes (unauth listing + 31 path enumeration) | HIGH to CRITICAL |
| `ai_keys` | `probe/ai_keys.json` | Live-key probe against AI / SaaS / payment provider read-only endpoints (OpenAI, Anthropic, xAI, GitHub, Razorpay, Mapbox, Sentry). `VALID` verdict means provider confirmed the key. | LOW to CRITICAL |
| `intent_security` | `scan/intent_security.json` | Cross-reference: an exported component AND an unsafe extra-consumption pattern in its source (`loadUrl` / `Uri.parse` / `new File(...)` / `startActivity` fed by `getStringExtra` / `getSerializableExtra`). High-confidence signal. | HIGH |
| `sdk_inventory` | `scan/sdk_inventory.json` | Third-party SDK + version catalog extracted from META-INF/*.properties and *-version.txt; one summary finding per app | INFO |
| `network_security` | `scan/network_security.json` | NSC XML analysis: unresolved Gradle placeholders, user-CA trust overrides, cleartext domains, pin-sets | INFO to HIGH |
| `cert_pinning` | `scan/cert_pinning.json` | OkHttp `CertificatePinner` / TrustKit / Conscrypt detection in code; flags OkHttpClient builders without pinning (severity depends on whether the app looks sensitive — banking/wallet/auth/billing) | INFO to HIGH |
| `s3_buckets` | `probe/s3_buckets.json` | AWS S3 bucket probes (anonymous list-objects + common-path read + brute-suffix sibling guessing for `-staging`/`-backup`/`-uploads`/`-dev`/`-prod`) | INFO to CRITICAL |
| `payment_sdk` | `scan/payment_sdk.json` | Per-app inventory of detected payment SDKs (Razorpay, Juspay HyperSDK, PhonePe, Paytm, Stripe, Google Play Billing, Cashfree, PayU, Braintree) + extracted public/test/secret keys; one INFO row per SDK detected, HIGH for any `sk_live_` Stripe secret or `_test_` key in production, MEDIUM for `_live_` keys (verify intentional) | INFO to HIGH |
| `asset_inspector` | `scan/asset_inspector.json` | Substring/suffix scan of `zipfile.namelist()` over the universal APK for accidentally-bundled dev artifacts: `.git/`, `.svn/`, `.env*`, source maps (`*.js.map`, `*.ts.map`, `*.css.map`), backups (`*.bak`, `*.orig`, `*.rej`, `backup.zip`/`backup.tar`, `*.dump`), swap (`*.swp`), IDE configs (`.idea/`, `.vscode/`), test dirs (`/test/`, `/__tests__/`), build files (`BUILD.bazel`, `Makefile`, `.classpath`), DBs (`*.sqlite`, `*.db`), keys/keystores (`id_rsa`, `*.pem`, `*.p12`, `*.jks`, `*.keystore`), cloud configs (`.aws/credentials`, `gcloud-credentials.json`, `kubeconfig`). Filename-only — does not extract APK contents. | INFO to CRITICAL |
| `build_leaks` | `scan/build_leaks.json` | Broader sweep for build-config slip-ups that signal a debug/staging artifact shipped to prod: unresolved Gradle placeholders (`${myFlag}`) in resource XML / properties / manifest, staging/dev/preprod/sandbox/uat hostnames in strings + smali (`api-dev.example.com`, `sandbox.juspay.in`), hardcoded debug constants (`DEBUG:Z = true`, `ENABLE_LOGGING = true`, `IS_DEBUG = true`), test/dev `<meta-data>` URLs in the manifest, and APK signed by the well-known Android debug keystore (SHA-1 `61ed377e...`) or with `CN=Android Debug` in the cert subject. Complements `network_security` (which only inspects NSC); NSC-internal placeholder leaks are deduped to avoid double-counting. Each list is capped at 200 hits. | MEDIUM to CRITICAL |
| `applinks` | `scan/applinks.json` | Android App Links / deeplink audit: for every `https` intent-filter declared with `android:autoVerify="true"`, probes `https://<host>/.well-known/assetlinks.json` and validates that the document lists this app's package name. Missing / unreachable / wrong-package → App Links silently fall back to the disambiguation dialog (any other app can claim the URL). Also flags deeplinks with no path restriction (entire host space) and intent-filters with suspiciously high `android:priority` (>100). | LOW to HIGH |
| `privacy` | `scan/privacy.json` | PII / sensitive-identifier reads relevant to DPDP (India) / GDPR (EU) / CCPA (California): IMEI / IMSI / phone number / SIM serial / MAC / Bluetooth MAC / Android ID / device serial, contacts / SMS / call log / calendar / clipboard, account enumeration, installed-apps enumeration, Wi-Fi scan results, cell-tower info, location / mic / camera access. One finding per `kind`; vendor SDK reads (Branch, AppsFlyer, etc.) are split out via `split_vendor` and demoted by one severity tier. | INFO to HIGH |
| `jwt_analyzer` | `scan/jwt_analyzer.json` | Structural decode (header + payload, no signature verification) of every JWT surfaced by the secrets scanner. Classifies each token by `alg`, `iss`, expiry-vs-now, and whether the issuer is a real production endpoint (`securetoken.google.com/*`, `accounts.google.com`, Auth0, Cognito, Okta, ...) vs a known SDK / docs test fixture (`https://example.com`, `https://jwt.io`, `urn:example:issuer`, RFC 7519 `joe`, ...). `alg:none` tokens are flagged as an auth-bypass vector; live-issuer tokens with future `exp` are treated as leaked session tokens; expired live-issuer tokens are still noteworthy because they shipped in the APK. | INFO to CRITICAL |

## Severity guidance

| Severity | What earns it |
|---|---|
| **CRITICAL** | Verified live secret (trufflehog `Verified: true`), leaked-flagged Google key, public Firebase RTDB / Storage bucket, certificate validation completely bypassed, hardcoded production credentials with confirmed access |
| **HIGH** | Hardcoded AES fallback key for auth tokens, dangerous WebView config + JS bridge with sensitive methods, SMS pumping vector reachable, Firestore unfiltered list permitted, AWS/Stripe/Slack production key in binary |
| **MEDIUM** | Cleartext traffic permitted, `allowBackup=true` with inadequate rules, RSA/ECB/PKCS1 used for session tokens, exported activity with intent extras consumed unsafely, Google key with no Android restriction, password-reset spam vector reachable |
| **LOW** | Exported component with no permission but no obvious sink, JWT in binary (test fixture likely), zero-IV crypto without context, weak Random() in non-security path |
| **INFO** | SDK identifiers that are public by design (Branch keys, Facebook client tokens, Google OAuth client IDs, AppsFlyer dev keys), API endpoints listed in resource strings |

Severity is intentionally conservative: a Google API key alone is INFO; a Google API key + no Android restriction + Identity Toolkit signUp succeeds is HIGH+. The finding-collector in `report/findings.py` does the joining.

## Categories under consideration (not yet emitted)

- `crypto` — separate from `code` for fine-grained crypto findings
- `iap` — billing / in-app-purchase client-side trust issues
- `intent_redirection` — specific deeplink / intent extra abuse paths
- `cdn` — exposed CDN signing keys

To add a category: extend `report/findings.py:collect()` with a `_from_<source>` function and wire any new severity rules into the joining logic.
