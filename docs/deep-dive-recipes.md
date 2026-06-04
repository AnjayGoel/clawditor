# Deep-dive recipes

Recipes for the most common "I have a finding, now what?" moments. Each recipe is a sequence of commands that takes you from a finding to a concrete answer.

## A Google API key is flagged as LEAKED or SUCCESS

```bash
cd ~/Documents/auditor

# 1. Confirm with a fresh standalone probe
uv run clawditor probe-key AIzaSyXXX...

# 2. What project is it scoped to? (project number is in any API_DISABLED error message)
cat data/<run>/probe/google_keys.json | jq '.[].services[] | select(.detail | contains("project"))' | head

# 3. Where in the binary?
grep -rn AIzaSyXXX... data/<run>/decompiled/

# 4. Action — see reports/next-steps.md for the per-finding fix hints
```

## An RTDB returned 401 unauth — but is auth+rule combo safe?

```bash
# The standard probe already tests with a minted anon Firebase identity
cat data/<run>/probe/firebase_rtdb.json | jq '.[].auth'

# If every path returned 401 to authenticated reads → rules deny even auth users on these paths.
# If 200 anywhere → tighten that path.

# To probe an arbitrary RTDB you found elsewhere:
uv run clawditor probe-firebase <project>
```

## A Firestore collection returned 200 with empty body

This is the ambiguity the static pipeline can't resolve:
- Could be "collection doesn't exist" (safe, just permissive rules)
- Could be "collection exists but is empty" (semi-safe)
- Could be "collection exists with data but rules require a filter" (possibly safe)

Two resolutions:

```bash
# A. Try a structured query on the same collection — Firestore rules-driven queries fail
# at query-time, so a query that "returned 0 results" actually means rules permitted list.
# The probe already does this for /users; check probe/firebase_firestore.json:structured_query_users.

# B. Capture dynamic traffic from the app to discover real document IDs, then test those.
# (Dynamic phase not implemented yet — manual via mitmproxy + frida-server.)
```

## A WebView has setAllowUniversalAccessFromFileURLs(true)

Trace the URL pipeline:

```bash
RUN=data/<run>

# 1. Find the WebView activity class
grep -rn 'setAllowUniversalAccessFromFileURLs' "$RUN/decompiled/jadx/sources/"

# 2. Read the surrounding context to find loadUrl() and the URL source
WEBVIEW_FILE=<file from step 1>
grep -nE 'loadUrl|loadDataWithBaseURL|setJavaScriptEnabled|addJavascriptInterface' "$WEBVIEW_FILE"

# 3. Find every caller that builds the URL extra
ACTIVITY_NAME=<class name from manifest.json>
grep -rn "$ACTIVITY_NAME" "$RUN/decompiled/jadx/sources/" | grep -i 'putExtra\|setData\|new Intent'

# 4. Severity decision:
# - Hardcoded URL → MEDIUM (depends on what the page contains)
# - Server-pushed URL (e.g. from Remote Config) → HIGH
# - Intent extra from another exported activity → CRITICAL
```

## WebView audit checklist

WebViews are the #1 mobile attack surface — a single misconfiguration usually compounds (e.g. JS enabled + universal file access + a JS bridge → exfil of every file the app can read). Run through every pattern below for any class that creates / configures a `WebView`. All of these are emitted under the `code` category in `findings.json`.

```bash
RUN=data/<run>

# One pass: every WebView-flavoured pattern in code_patterns.json
jq 'to_entries | map(select(.key | startswith("webview_"))) | map(select(.value | length > 0))
    | map({pattern: .key, n: (.value | length), first: (.value[0].file + ":" + (.value[0].line // "?"))})' \
   $RUN/scan/code_patterns.json
```

Interpret each pattern and remediate:

| Pattern | What it catches | Remediation |
|---|---|---|
| `webview_universal_file_access` | `setAllowUniversalAccessFromFileURLs(true)` — `file://` page can XHR any origin | Set to `false`; never load attacker-controllable content via `file://` |
| `webview_file_url_access` | `setAllowFileAccessFromFileURLs(true)` — sibling-file read from `file://` | Set to `false`; default since API 16 already disables this |
| `webview_js_enabled` | `setJavaScriptEnabled(true)` | Disable unless absolutely required; pair with strict origin allow-list |
| `webview_addjs_interface` | `addJavascriptInterface(...)` — Java/Kotlin reachable from JS | Restrict to API 17+, annotate `@JavascriptInterface`, expose minimal surface |
| `webview_load_data_with_base_url` | `loadDataWithBaseURL("http://...")` — JS runs in HTTP origin | Use `https://` base URL or `about:blank` |
| `webview_mixed_content_always_allow` | `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` — HTTPS page loads HTTP subresources | Use `MIXED_CONTENT_NEVER_ALLOW` (default on API 26+); HIGH because session cookies leak under MITM |
| `webview_mixed_content_compatibility` | `MIXED_CONTENT_COMPATIBILITY_MODE` — browser-like heuristic | Prefer `NEVER_ALLOW`; only relax for known-broken legacy origins |
| `webview_safe_browsing_disabled` | `setSafeBrowsingEnabled(false)` in code | Remove the override; Google Safe Browsing is on by default and free protection |
| `webview_safe_browsing_manifest_disabled` | `EnableSafeBrowsing=false` `<meta-data>` in manifest | Delete the meta-data; if a captive use case needs it, scope it to that activity only |
| `webview_save_password` | `setSavePassword(true)` (deprecated) — autofill creds into the WebView's password DB | Remove; use platform-level autofill (`Autofill Service`) instead |
| `webview_save_form_data` | `setSaveFormData(true)` — autofills any form field including OTP / token | Set to `false` for any WebView that touches auth flows |
| `webview_geolocation_enabled` | `setGeolocationEnabled(true)` (INFO) | OK if paired with a real permission prompt; pair with the next row to confirm |
| `webview_geolocation_always_allow` | `onGeolocationPermissionsShowPrompt(...) { callback.invoke(origin, true, false); }` — auto-grants location to every origin | Show a real user prompt before granting; reject by default for unknown origins |
| `webview_database_enabled` | `setDatabaseEnabled(true)` — origin gets persistent SQL store | OK for trusted first-party content; risky if origin is attacker-controlled |
| `webview_content_access` | `setAllowContentAccess(true)` — `content://` URIs reachable from WebView | Set to `false` unless the WebView legitimately renders ContentProvider data |
| `webview_plugin_enabled` | `setPluginState(ON)` (Flash; deprecated) | Remove the call; modern WebView ignores plugins anyway |
| `webview_user_agent_set` | `setUserAgentString(...)` (INFO) | Inspect the value — if it removes the app identifier it can be used to evade backend rate-limits or impersonate browsers |
| `webview_debugging_enabled` | `WebView.setWebContentsDebuggingEnabled(true)` in production — attached Chrome dev tools can inspect every JS bridge | Gate on `BuildConfig.DEBUG`. **CRITICAL when combined with `android:debuggable=true` at manifest** (attacker can attach without a rooted device) |
| `webview_third_party_cookies` | `setAcceptThirdPartyCookies(webView, true)` — tracking / CSRF risk | Default-false; only enable for specific WebViews that need cross-site auth |

Quick triage when you find more than one:

```bash
# Compose a single rendered table from the above categories, plus the JS-bridge location
grep -rnE 'setJavaScriptEnabled\(true\)|addJavascriptInterface' \
   $RUN/decompiled/jadx/sources/ 2>/dev/null \
  | awk -F: '{print $1}' | sort -u | head
```

If the same class hits **≥3** of the patterns above (e.g. JS enabled + addJavascriptInterface + mixed-content always allow), escalate to HIGH irrespective of the per-pattern severity — the combination is a remote-code-style risk in mobile context.

## Hardcoded AES key suspected

```bash
RUN=data/<run>

# Common pattern: 24-40 char string passed to MessageDigest or SecretKeySpec
grep -rPnE '"[A-Za-z0-9_-]{24,40}"' "$RUN/decompiled/jadx/sources/" 2>/dev/null \
  | grep -iE 'encrypt|aes|key|secret|cipher|spec' | head -20

# Or trace SecretKeySpec usage
grep -rn SecretKeySpec "$RUN/decompiled/jadx/sources/" | head
```

If the result is a constant string used as key material AND the same code wraps user tokens → **HIGH** (same key on every install, no PFS).

## libsecretkeys.so or any suspicious .so

```bash
RUN=data/<run>
# The pipeline already runs `strings` on every .so under decompiled/native/
ls "$RUN/decompiled/native/"*/*.strings.txt

# Grep for the patterns of interest
grep -E 'AIzaSy|sk_live|AKIA|xox[abprs]-|key_live' "$RUN/decompiled/native/"*/*.strings.txt
```

## An S3 bucket appears listable — what next?

The S3 probe writes one entry per discovered bucket to `probe/s3_buckets.json`. A
`listable: true` finding is CRITICAL; a non-empty `publicly_readable_paths` is HIGH.

```bash
RUN=data/<run>

# 1. List every probed bucket with its verdict + size of the path-probe table
jq 'to_entries | map({bucket: .key, listable: .value.listable, exists: .value.exists,
                       guessed: .value.guessed, readable: (.value.publicly_readable_paths|length)})' \
   $RUN/probe/s3_buckets.json

# 2. Confirm by hand (no auth) — fetch the first page of objects
BUCKET=<bucket-name>
curl -sS "https://${BUCKET}.s3.amazonaws.com/?max-keys=10" | head -40

# 3. Enumerate paginated. AWS lists up to 1000 keys per page; pass marker for more.
curl -sS "https://${BUCKET}.s3.amazonaws.com/?max-keys=1000" \
  | xmllint --xpath '//*[local-name()="Key"]/text()' - 2>/dev/null | head

# 4. Pull one object to confirm read (CRITICAL if anything sensitive comes back)
KEY=<key-from-step-3>
curl -sS -o /tmp/peek "https://${BUCKET}.s3.amazonaws.com/${KEY}"
file /tmp/peek; head -c 200 /tmp/peek

# 5. Check for sibling buckets we already brute-suffix-guessed
jq 'to_entries | map(select(.value.guessed and .value.exists)) | .[].key' \
   $RUN/probe/s3_buckets.json

# 6. If guessed siblings don't exist, register/squat-protect them before someone else does.
#    Severity decision:
#    - listable → CRITICAL  (anyone can enumerate every object)
#    - public_partial + readable common paths → HIGH (specific paths leak)
#    - 403 listing but signed-URL endpoints accessible → MEDIUM (needs further probing)
#    - NoSuchBucket on a brute-suffix → INFO (squat-protect candidate)
```

The probe is intentionally read-only (no `PUT`, no multipart-init). If you want
to confirm write access, do it manually with `aws s3 cp` against your own
credentials and document the result — never write with anonymous credentials.

## End-to-end sanity check on a finished run

```bash
uv run clawditor show <run>                    # print SUMMARY.md
uv run clawditor show <run> --findings         # print findings table
uv run clawditor show <run> --keys             # per-key probe matrix
uv run clawditor show <run> --firebase         # raw Firebase probe outputs
cat data/<run>/MANIFEST.md                   # entry-point file
cat data/<run>/reports/deep-dive-guide.md    # follow-up instructions
cat data/<run>/reports/next-steps.md         # actionable checklist
```

## How to use the SDK inventory

`scan/sdk_inventory.json` lists every third-party SDK + version extracted from `META-INF/*.properties` and `*-version.txt` in the APK root. Each entry is one CVE search away from a finding.

```bash
RUN=data/<run>

# List every catalogued SDK
cat $RUN/scan/sdk_inventory.json | jq -r '.sdks[] | "\(.name)\t\(.version)"'

# Pull the OkHttp version (CVEs in <=4.9.0 etc.)
cat $RUN/scan/sdk_inventory.json | jq '.sdks[] | select(.name | contains("ok"))'

# Just the third-party (non-Google, non-AndroidX) SDKs — best CVE candidates
cat $RUN/scan/sdk_inventory.json | jq '.by_category.third_party'

# Count by category
cat $RUN/scan/sdk_inventory.json | jq '.by_category | to_entries | map({k: .key, n: (.value|length)})'

# Cross-check a version against the GitHub Advisory DB
gh api graphql -f query='query{securityVulnerabilities(ecosystem:MAVEN, package:"com.squareup.okhttp3:okhttp", first:5){nodes{advisory{ghsaId summary}}}}'
```

## How to read the Network Security Config output

`scan/network_security.json` parses the NSC XML referenced from the manifest. Highest-value fields:

```bash
RUN=data/<run>

# Did a Gradle ${placeholder} leak into production?
jq '.gradle_placeholders' $RUN/scan/network_security.json

# Did the build trust user-installed CAs (TLS interception trivially possible)?
jq '.user_trust_anchor' $RUN/scan/network_security.json

# Which real domains are explicitly permitted to use HTTP?
jq '.cleartext_domains' $RUN/scan/network_security.json
```

## How to read the cert-pinning output

`scan/cert_pinning.json` lists every file that hits OkHttp `CertificatePinner`, TrustKit, custom `sslSocketFactory`, or Conscrypt — and every file that builds an `OkHttpClient` without any pinning. The severity of the absence depends on whether the app looks sensitive (banking / wallet / auth / payment / billing).

```bash
RUN=data/<run>

jq '.pinners_found | group_by(.type) | map({type: .[0].type, count: length})' \
   $RUN/scan/cert_pinning.json

jq '.okhttp_without_pinning[:5]' $RUN/scan/cert_pinning.json
```

## Inspecting a single finding deeply

`clawditor inspect` is the entry point when you (or an agent) want every available context for a specific finding — full evidence, the source JSON record that produced it, surrounding source code, suggested next steps, and the CLI invocations that can verify it.

```bash
RUN=data/<run>

# By index in findings.json (sorted: CRITICAL first, then HIGH, …)
uv run clawditor inspect $RUN --finding 0

# All CRITICAL findings, one per page, separated by a rule
uv run clawditor inspect $RUN --severity CRITICAL

# Every finding in a category
uv run clawditor inspect $RUN --category secrets

# Substring match in title or evidence
uv run clawditor inspect $RUN --grep AIzaSy

# Cap the number rendered (default 20)
uv run clawditor inspect $RUN --severity HIGH --limit 5

# Machine-readable: one JSON object per finding, newline-delimited
uv run clawditor inspect $RUN --severity CRITICAL --json | jq .
```

Each rendered finding shows: header (severity / category / title / location), full evidence, source JSON record, syntax-highlighted source-file slice (when `location` is `path:lineN`), `**do**:` hints lifted from `reports/next-steps.md`, and the relevant `clawditor probe-*` invocations.

## Found a payment SDK — what next?

`scan/payment_sdk.json` lists each detected payment SDK (Razorpay, Juspay HyperSDK, PhonePe, Paytm, Stripe, Google Play Billing, Cashfree, PayU, Braintree), any extracted keys / merchant IDs, and severity-tagged notes. Payments are an especially high-value class — misconfigurations can directly enable chargeback fraud, IRSF, or replay attacks.

```bash
RUN=data/<run>

# 1. See which SDK(s) are present + what keys were extracted
jq '.findings[] | {sdk, keys, notes}' $RUN/scan/payment_sdk.json

# 2. For Razorpay / Stripe: verify the extracted key is the PUBLIC (checkout)
# key, not the SECRET (server) key. Stripe sk_live_* in client = CRITICAL.
# Razorpay rzp_live_* is the key_id (public-ish); the secret is rzp_secret_*.
jq '.findings[] | select(.sdk == "Stripe") | .keys[] | select(startswith("sk_"))' \
   $RUN/scan/payment_sdk.json

# 3. Test a live Razorpay key with the provider's restriction-check endpoint.
# A response means the key is active; a 401/403 means it's revoked/scoped.
curl -u rzp_live_xxx: https://api.razorpay.com/v1/payments?count=1

# 4. For Juspay HyperSDK with a bundled WebView: cross-reference the code-pattern
# scan for the unsafe loadDataWithBaseURL("http://juspay.in...) pattern, which
# would let an MITM inject JS into the payment surface.
jq '.webview_load_data_with_base_url, .webview_addjs_interface' \
   $RUN/scan/code_patterns.json

# 5. For Google Play Billing: confirm receipt-validation happens server-side.
# If you see no /verify endpoint in the network strings, the app is trusting
# the BillingClient response — client-side IAP bypass is straightforward.
grep -rE 'verifyPurchase|acknowledgePurchase|developerPayload' \
   $RUN/decompiled/jadx/sources/ 2>/dev/null | head
```

## Reflection & dynamic code loading

A small family of `code_patterns.json` hits flag the building blocks of an
**intent-redirection-to-RCE** chain. Individually each is "interesting"; chained
they're catastrophic. The chain is always the same shape:

1. An **exported** activity / service / receiver (no permission gate) lives in
   the manifest. Anyone on the device can deliver an Intent to it.
2. That component pulls an attacker-supplied string out of the Intent —
   `getStringExtra`, `getBundleExtra`, `getParcelableExtra`.
3. The string is then passed unsanitised into a **code-loading sink** running
   inside the app's own process and UID — `Runtime.exec`, `ProcessBuilder`,
   `DexClassLoader`, `Class.forName(...).getMethod(...).invoke(...)`,
   `System.load`, `WebView.evaluateJavascript`, `ContentResolver.openInputStream`,
   `new FileInputStream / FileOutputStream`.
4. Result: **arbitrary code execution as the victim app** — same UID, same
   permissions, same access to the app's private data dir, signed-in tokens,
   bound Keystore aliases, etc. From an unprivileged installed app this is
   typically the most valuable primitive available to an attacker.

Patterns that fire on step 2→3 (look for these to triage the chain):

| pattern | sink | severity |
| --- | --- | --- |
| `runtime_exec_from_extra` | `Runtime.exec` | CRITICAL |
| `processbuilder_from_extra` | `ProcessBuilder` | CRITICAL |
| `dex_class_loader_from_extra` | `DexClassLoader` | CRITICAL |
| `dex_class_loader_from_url` | `DexClassLoader` from `http(s)://` | CRITICAL |
| `system_loadlibrary_from_extra` | `System.load` / `loadLibrary` | CRITICAL |
| `file_output_stream_from_extra` | overwrite arbitrary file | CRITICAL |
| `class_forname_from_extra` | reflection bootstrap | HIGH |
| `method_invoke_from_extra` | reflection invocation | HIGH |
| `file_input_stream_from_extra` | read arbitrary file | HIGH |
| `content_resolver_from_extra` | content provider with attacker URI | HIGH |
| `webview_evaluate_javascript_from_extra` | JS injection in WebView | HIGH |
| `path_class_loader_external` | load from cache/external dir | HIGH |

Plus three blast-radius helpers (less RCE-y but bad):

- `sharedprefs_world_writeable` — CRITICAL (deprecated since API 17; if present
  the app is shipping with a long-disabled, world-writable preference file that
  any installed app can clobber).
- `sharedprefs_world_readable` / `openfileoutput_world_readable` — HIGH
  (same idea for reads).
- `reflection_field_set_accessible` — LOW (very common noise from
  serialization libraries; only worth pursuing if you find one in app code).

### Triage recipe

```bash
RUN=data/<run>

# 1. List every sink hit, sorted by severity (manually — use the categories above)
jq 'with_entries(select(.value | length > 0)) |
    keys[] | select(test("from_extra|class_loader|world_writeable"))' \
   $RUN/scan/code_patterns.json

# 2. For each hit, get the file:line + match
jq '.runtime_exec_from_extra[], .dex_class_loader_from_extra[],
    .class_forname_from_extra[], .file_output_stream_from_extra[]' \
   $RUN/scan/code_patterns.json

# 3. Cross-reference the file with the manifest's exported_components — if the
#    enclosing class is exported with no permission, that's the full chain.
jq '.exported_components' $RUN/scan/manifest.json

# 4. The `intent_security` cross-reference scanner already does this join for
#    a curated subset of sinks; check it too.
cat $RUN/scan/intent_security.json | jq '.[] | select(.pattern | test("exec|forName|Loader"))'

# 5. Confirm exploitability dynamically (when the dynamic phase exists):
#    `adb shell am start -n <pkg>/<exported_activity> --es <extra_key> "id"`
#    Watch logcat / adb shell ps for the spawned process.
```

A finding from this family that points at app-owned code (not a vendor SDK) is
worth elevating in the report regardless of category — same-UID RCE is one of
the few Android primitives that doesn't need a kernel bug to be useful.

## Diff two runs

When you have two completed runs and want to see how they differ — old vs new build of the same app, two sibling apps from the same publisher, or a tested config vs a baseline — use `clawditor compare`.

```bash
cd ~/Documents/auditor

# Default: side-by-side findings table + Only-in-A / Only-in-B / Severity-changed lists,
# plus SDK, endpoint (hosts), and AIzaSy* key diffs.
uv run clawditor compare data/com.foo_v1 data/com.foo_v2

# Group the findings table by category instead of one flat table.
uv run clawditor compare run_a run_b --by category

# Restrict the rendered table to one segment of the Venn diagram.
uv run clawditor compare run_a run_b --shared    # only present in both
uv run clawditor compare run_a run_b --only-a    # only in A (e.g. regressions fixed in B)
uv run clawditor compare run_a run_b --only-b    # only in B (e.g. new regressions)

# Machine-readable diff document — full structure, easy to feed into jq.
uv run clawditor compare run_a run_b --json | jq '.severity_changed'
uv run clawditor compare run_a run_b --json | jq '.sdk_diff.added_in_b'
uv run clawditor compare run_a run_b --json | jq '.ai_key_diff'
```

Identity: findings are matched by the `(category, title)` tuple — `evidence` strings often vary version-to-version even when the finding is "the same", so they're not part of the key. SDKs are matched by `name` (a version bump doesn't show as add+remove; the spec is asking for set membership). Endpoints come from `scan/secrets.json`'s `firebase_rtdb_url` + `firebase_storage_bucket` entries (the bare host, scheme stripped). API keys come from `scan/secrets.json:google_api_key[].value`.

```bash
# Example: compare two versions of the same app — what got fixed?
uv run clawditor compare data/com.foo_v1 data/com.foo_v2 --json \
  | jq '.only_a | map(select(.severity == "CRITICAL" or .severity == "HIGH"))'

# Example: two sibling apps from the same publisher — do they share keys?
uv run clawditor compare data/pub.app1 data/pub.app2 --json | jq '.ai_key_diff.shared'
```

## Re-running just the probes (no static)

When you've updated probe code or the target's rules have changed but the APK is the same:

```bash
cd ~/Documents/auditor
uv run clawditor run --probe-only --out data/<run>
```

This re-uses the scanned `secrets.json` (which lists the keys / RTDB URLs / buckets to probe) and overwrites `probe/*.json` + `reports/*`.

## DPDP / GDPR compliance audit

`scan/privacy.json` inventories every PII / sensitive-identifier read in the
binary, partitioned by `kind` (`imei_read`, `android_id_read`,
`installed_apps_read`, `call_log_read`, `sms_read`, `contacts_read`,
`clipboard_read`, `wifi_scan_results_read`, `cell_info_read`, …). Useful when
asking: *which data subjects does this app touch, and does each touch have a
documented purpose and a consent flow?*

```bash
RUN=data/<run>

# 1. Birds-eye view: which kinds fire, and how many sites per kind?
jq '.by_kind | to_entries | map({kind: .key, sites: (.value|length)}) | sort_by(-.sites)' \
   $RUN/scan/privacy.json

# 2. Drill into one kind — which files read it?
jq '.by_kind.imei_read' $RUN/scan/privacy.json

# 3. App-owned vs vendor SDK reads (vendor matches are demoted in findings; you may
#    still want to inspect them directly — they imply data shared with third parties).
jq '.by_pattern | to_entries[] | {pattern: .key, files: [.value[].file]}' \
   $RUN/scan/privacy.json | head -60

# 4. Cross-reference with declared permissions — a kind that fires with no
#    matching `uses-permission` is dead code, reflection, or a vendor SDK reading
#    something the app forgot to declare.
jq '.permissions' $RUN/scan/manifest.json

# 5. Check the SDK inventory for the usual identifier-reading SDKs.
jq '.sdks[] | select(.name | test("branch|appsflyer|moengage|clevertap|mixpanel|segment"; "i"))' \
   $RUN/scan/sdk_inventory.json

# 6. Just the HIGH-severity reads — the ones that under DPDP §6 / GDPR Art. 6+7
#    typically require an explicit consent flow.
jq '[.by_pattern | to_entries[] | .value[] | select(.severity == "HIGH")]
    | group_by(.kind) | map({kind: .[0].kind, count: length})' \
   $RUN/scan/privacy.json

# 7. Clipboard reads at launch are a known dark pattern (iOS 14 surfaced it).
#    Android in-foreground reads are still abused — cross-reference Application.onCreate
#    / first-Activity onResume.
jq '.by_kind.clipboard_read' $RUN/scan/privacy.json
grep -rnE 'getPrimaryClip' $RUN/decompiled/jadx/sources/ 2>/dev/null | head

# 8. Installed-apps enumeration on Android 11+ requires QUERY_ALL_PACKAGES
#    (Play-policy-restricted). If `installed_apps_read` fires but the permission
#    isn't declared, the SDK is silently shrinking its result set — still a
#    DPDP "purpose limitation" question.
jq '.permissions[] | select(test("QUERY_ALL_PACKAGES"))' $RUN/scan/manifest.json
```

Severity rubric for a compliance write-up:

- **HIGH** — `imei_read` / `imsi_read` / `phone_number_read` / `sms_read` / `call_log_read` / `accounts_read` in app-owned code without a visible consent flow.
- **MEDIUM** — `mac_read` / `bluetooth_mac_read` / `sim_serial_read` / `device_serial_read` / `clipboard_read` / `contacts_read` / `installed_apps_read` / `wifi_scan_results_read` / `cell_info_read` (usually vendor analytics; flag if the vendor isn't disclosed in the privacy policy).
- **LOW** — `android_id_read` / `calendar_read` (low entropy or narrowly scoped; verify purpose).
- **INFO** — `location_request` / `microphone_access` / `camera_access` (inventory only; legitimate for most apps but should be permission-gated).
