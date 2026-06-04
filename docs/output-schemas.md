# Output schemas

Canonical reference for every JSON / Markdown file the pipeline writes into a run directory. An agent landing in a fresh `data/<package>_<ts>/` can read this once and know how to consume every output.

Run-dir layout (current set of files):

```
data/<package>_<ts>/
├── run.json
├── MANIFEST.md
├── apk/
├── decompiled/
├── scan/
│   ├── stack.json
│   ├── manifest.json
│   ├── secrets.json
│   ├── jwt_analyzer.json
│   ├── code_patterns.json
│   ├── apkleaks.json
│   ├── trufflehog.json
│   ├── sdk_inventory.json
│   ├── network_security.json
│   ├── cert_pinning.json
│   ├── intent_security.json
│   └── flutter.json          # only for Flutter apps
├── probe/
│   ├── google_keys.json
│   ├── firebase_rtdb.json
│   ├── firebase_firestore.json
│   ├── firebase_storage.json
│   └── ai_keys.json          # only if AI/SaaS keys were found
└── reports/
    ├── findings.json
    ├── findings.md
    ├── SUMMARY.md
    ├── deep-dive-guide.md
    └── next-steps.md
```

Conventions:

- All JSON is UTF-8, indent=2.
- "Dict-of-lists keyed by pattern" (e.g. `secrets.json`, `code_patterns.json`) means every regex/pattern key is **always present** — empty list when no hits.
- Probe outputs are dicts **keyed by the probed artifact** (API key, RTDB URL, project id, bucket name) — not arrays.
- A module that finds no input (no `secrets.json` to derive from, tool not installed, etc.) writes nothing and the file is absent. `findings.py` tolerates absence.

---

## `run.json`

**Producer**: `clawditor.config.RunContext.write_meta` — first thing the orchestrator does.
**Always produced**: yes.
**Shape**:

```json
{
  "package": "string | null — Android package (when invoked with positional package arg)",
  "apk_input": "string | null — original --apk path",
  "started_at": "string — local timestamp YYYYMMDD-HHMMSS",
  "flags": {
    "no_probe": false,
    "quick": false,
    "no_jadx": false,
    "probe_only": false
  }
}
```

**Example** (from `data/com.example.app_run2/run.json`):

```json
{
  "package": null,
  "apk_input": "working/com.example.app",
  "started_at": "20260523-164156",
  "flags": {"no_probe": false, "quick": true, "no_jadx": false, "probe_only": false}
}
```

**Consumer notes**:
- `report/markdown.py` reads it to print the run header in `SUMMARY.md`.
- `jq -r '.package // .apk_input' run.json` — display target.

---

## `scan/stack.json`

**Producer**: `clawditor.detect.stack` — runs after decompile, before scan.
**Always produced**: yes.
**Shape**: every key is a boolean; `native_android` is always `true`.

```json
{
  "react_native": false,
  "flutter": false,
  "unity": false,
  "xamarin": false,
  "cordova": false,
  "compose_multiplatform": false,
  "native_android": true
}
```

**Example** (from `data/com.example.app_run2/scan/stack.json`):

```json
{
  "react_native": false,
  "flutter": false,
  "unity": false,
  "xamarin": false,
  "cordova": false,
  "compose_multiplatform": false,
  "native_android": true
}
```

**Consumer notes**:
- `pipeline.py` reads it to decide whether to run `extract/hermes` (RN) and `extract/flutter`.
- `report/markdown.py:_write_summary` reads it to label the "Stack:" line.
- `jq -r 'to_entries | map(select(.value) | .key) | join(", ")' scan/stack.json` — detected stacks.

---

## `scan/manifest.json`

**Producer**: `clawditor.scan.manifest` — parses `decompiled/smali/AndroidManifest.xml`.
**Always produced**: yes when AndroidManifest exists on disk; `{}` (and warning) otherwise.
**Shape**:

```json
{
  "package": "string",
  "version_code": "string | null",
  "version_name": "string | null",
  "min_sdk": "string | null",
  "target_sdk": "string | null",
  "application": {
    "debuggable": false,
    "allow_backup": true,
    "uses_cleartext_traffic": false,
    "network_security_config": "string — e.g. @xml/network_security_config",
    "backup_agent": "string",
    "data_extraction_rules": "string",
    "full_backup_content": "string"
  },
  "permissions_requested": ["android.permission.INTERNET", "…"],
  "exported_components": {
    "activities": [{"name": "…", "exported_attr": "true|null", "permission": "…|null", "has_intent_filter": true}],
    "services": [],
    "receivers": [],
    "providers": []
  },
  "deeplinks": [
    {"activity": "…", "schemes": ["https"], "hosts": ["app.example.com"], "paths": ["/x"]}
  ],
  "providers": [
    {"name": "…", "authorities": "…", "exported": "true|null",
     "grant_uri_permissions": "true|null", "read_permission": "…", "write_permission": "…"}
  ]
}
```

**Example**:

```json
{
  "package": "com.example.app",
  "version_code": "1042",
  "version_name": "10.4.2",
  "min_sdk": "23",
  "target_sdk": "34",
  "application": {
    "debuggable": false,
    "allow_backup": true,
    "uses_cleartext_traffic": false,
    "network_security_config": "@xml/network_security_config",
    "backup_agent": "",
    "data_extraction_rules": "",
    "full_backup_content": ""
  },
  "permissions_requested": ["android.permission.INTERNET", "android.permission.CAMERA"],
  "exported_components": {
    "activities": [
      {"name": ".MainActivity", "exported_attr": "true", "permission": null, "has_intent_filter": true}
    ],
    "services": [], "receivers": [], "providers": []
  },
  "deeplinks": [
    {"activity": ".MainActivity", "schemes": ["https"], "hosts": ["app.example.com"], "paths": ["/share"]}
  ],
  "providers": []
}
```

**Consumer notes**:
- `findings.py:_from_manifest` reads `application.{debuggable,allow_backup,uses_cleartext_traffic,…}`, `exported_components.*`, and `deeplinks`.
- `scan/network_security.py` reads `application.network_security_config` to resolve the NSC XML.
- `scan/cert_pinning.py` reads `permissions_requested` and `package` for the sensitive-app heuristic.
- `scan/intent_security.py` reads `exported_components.*[*].name`.
- `jq '.exported_components | to_entries[] | {kind:.key, count:(.value|length)}' scan/manifest.json` — exported component counts.

---

## `scan/secrets.json`

**Producer**: `clawditor.scan.secrets` — custom regex sweep across `decompiled/{jadx/sources, smali, hermes, native}`.
**Always produced**: yes.
**Shape**: dict-of-lists keyed by pattern name. Every key in `PATTERNS` is present (empty list if no hits). Each hit is `{"value": "<matched string>", "file": "<rel-path-from-decompiled/>"}`. Values are deduped per pattern.

Pattern keys: `google_api_key`, `firebase_rtdb_url`, `firebase_storage_bucket`, `google_oauth_client_id`, `jwt`, `aws_access_key_id`, `slack_token`, `stripe_secret_key`, `branch_key`, `appsflyer_dev_key`, `openai_key`, `anthropic_key`, `xai_grok_key`, `huggingface_token`, `github_token`, `gcp_service_account_json`, `pem_private_key`, `razorpay_key`, `mapbox_token`, `sentry_dsn`, `slack_webhook`, `discord_webhook`, `algolia_app_id_key`, `twilio_account_sid`, `mailgun_key`.

```json
{
  "google_api_key": [{"value": "AIzaSy…", "file": "jadx/sources/com/x/Y.java"}],
  "firebase_rtdb_url": [{"value": "https://example-default-rtdb.firebaseio.com", "file": "…"}],
  "firebase_storage_bucket": [{"value": "example.appspot.com", "file": "…"}],
  "google_oauth_client_id": [],
  "jwt": [],
  "aws_access_key_id": [],
  "...": []
}
```

**Example**:

```json
{
  "google_api_key": [
    {"value": "AIzaSyEXAMPLE_FAKE_KEY_FOR_DOCS_ONLY99",
     "file": "smali/resources/package_1/res/values/strings.xml"}
  ],
  "firebase_rtdb_url": [
    {"value": "https://stoked-virtue-769.firebaseio.com",
     "file": "smali/smali/classes3/com/example/Config.smali"}
  ],
  "firebase_storage_bucket": [
    {"value": "stoked-virtue-769.appspot.com", "file": "…"}
  ],
  "google_oauth_client_id": [],
  "openai_key": [], "anthropic_key": [], "razorpay_key": []
}
```

**Consumer notes**:
- This file is the **input** for every probe. `probe/google_keys.py`, `probe/firebase_*.py`, `probe/ai_keys.py` all read it first; if the corresponding key is empty they skip.
- `findings.py:_from_secrets` reads every key, applies the per-type severity map, and splits each list into app-owned vs vendor via `clawditor.utils.vendor.split_vendor`. Vendor matches get demoted one severity tier.
- `jq '[.google_api_key[].value] | unique' scan/secrets.json` — unique AIzaSy keys to feed into `clawditor probe-key`.
- `jq 'to_entries | map(select(.value|length>0) | {(.key): (.value|length)}) | add' scan/secrets.json` — non-empty pattern hit counts.

---

## `scan/jwt_analyzer.json`

**Producer**: `clawditor.scan.jwt_analyzer` — runs after `secrets.run` in `_scan_phase`. Reads `secrets.json:jwt[]`, base64url-decodes header + payload (no signature verification), and classifies each token.
**Always produced**: yes when `secrets.json` exists (may be `{"tokens": []}` if no JWTs were found).
**Shape**:

```json
{
  "tokens": [
    {
      "file": "smali/.../Config.smali",
      "header": {"alg": "RS256", "typ": "JWT", "kid": "abc"},
      "payload_claims": {"iss": "https://securetoken.google.com/proj", "sub": "uid", "exp": 1700000000, "aud": "proj"},
      "is_expired": true,
      "is_test_fixture": false,
      "issuer_class": "production",
      "findings": ["expired", "production_issuer"]
    }
  ]
}
```

`issuer_class` is one of `production` (real OIDC mints — `securetoken.google.com/*`, `accounts.google.com`, Auth0, Cognito, Okta, ...), `test_fixture` (SDK / docs examples — `https://example.com`, `https://jwt.io`, `urn:example:issuer`, RFC 7519 `joe`, ...), `internal` (hostnames that look like internal/staging/dev/corp/local), or `unknown`. `findings` is a sub-list drawn from `{alg_none, expired, production_issuer, test_fixture_issuer, internal_issuer, hmac_secret_in_payload, malformed}`.

**Consumer notes**:
- `findings.py:_from_jwt_analyzer` maps to severity: `alg_none` → CRITICAL; `production_issuer` + valid `exp` → HIGH; `production_issuer` + expired → MEDIUM; `test_fixture` → INFO; `unknown` issuer + valid `exp` → LOW. Malformed tokens are recorded but produce no finding row.
- `jq '.tokens[] | select(.findings | index("production_issuer"))' scan/jwt_analyzer.json` — every live-issuer JWT shipped.
- `jq '[.tokens[].issuer_class] | group_by(.) | map({(.[0]): length}) | add' scan/jwt_analyzer.json` — issuer-class histogram.

---

## `scan/code_patterns.json`

**Producer**: `clawditor.scan.code_patterns` — `rg`/`grep` for ~50 dangerous code patterns across `decompiled/{jadx/sources, hermes}`.
**Always produced**: yes (even if `rg`/`grep` absent, returns empty lists).
**Shape**: dict-of-lists keyed by pattern name. Every key in `PATTERNS` is present. Each hit is `{"file": "<rel-path>", "line": "<n>", "match": "<first 300 chars>"}` or `{"raw": "<line>"}` when parsing failed. Capped at 200 hits per pattern.

Pattern keys (severity from `findings.py:_from_code_patterns`): `webview_universal_file_access`, `webview_file_url_access`, `webview_js_enabled`, `webview_addjs_interface`, `webview_load_data_with_base_url`, `trust_all_certificates`, `hostname_verifier_accept_all`, `hostname_verifier_lambda`, `rsa_ecb_pkcs1`, `aes_ecb`, `des`, `weak_random`, `zero_iv`, `raw_query_concat`, `exec_sql_concat`, `firestore_instance`, `firestore_collection_literal`, `rtdb_get_reference`, `log_token`, `pending_intent_mutable`, `pending_intent_no_immutable`, `intent_serializable_extra`, `intent_parcelable_extra_no_type`, `implicit_intent_outside_app`, `intent_redirection_pattern`, `file_from_intent_extra_no_canonicalize`, `file_provider_authority_wildcard`, `objectinput_stream_external`, `yaml_load_default`, `missing_filter_touches`, `flag_secure_missing_check`, `clipboard_write_sensitive`, `runtime_exec`, `loadlibrary_dynamic`, `http_url_constant`, `okhttp_no_cert_pinning`, `trust_manager_empty`, `trust_manager_lambda`, `ssl_hostname_verify_all`, `xml_parser_no_disallow_doctype`, `sax_parser_no_secure`, `log_pii_pattern`, `root_check_simple_su`, `frida_check_string`, `accessibility_service_text_changed`, `oauth_redirect_uri_localhost`.

```json
{
  "webview_addjs_interface": [
    {"file": "jadx/sources/com/x/Y.java", "line": "412", "match": "wv.addJavascriptInterface(new Bridge(), \"App\")"}
  ],
  "trust_all_certificates": [],
  "raw_query_concat": [],
  "...": []
}
```

**Example**:

```json
{
  "webview_addjs_interface": [
    {"file": "jadx/sources/com/example/web/MainWebView.java", "line": "212",
     "match": "wv.addJavascriptInterface(new JsBridge(this), \"Native\")"}
  ],
  "rsa_ecb_pkcs1": [
    {"file": "jadx/sources/com/example/crypto/TokenCipher.java", "line": "44",
     "match": "Cipher.getInstance(\"RSA/ECB/PKCS1Padding\")"}
  ],
  "trust_all_certificates": [], "firestore_collection_literal": [],
  "raw_query_concat": [], "http_url_constant": []
}
```

**Consumer notes**:
- `findings.py:_from_code_patterns` applies a per-pattern severity map and splits app vs vendor via `split_vendor(hits, file_key="file")`. Vendor hits get demoted.
- `jq '[.firestore_collection_literal[].match] | map(capture("\"(?<c>[^\"]+)\"").c) | unique' scan/code_patterns.json` — collection names referenced in code (useful to seed `probe/firebase_firestore.py` work).
- `jq 'to_entries[] | select(.value|length>0) | {(.key): (.value|length)}' scan/code_patterns.json` — non-empty pattern counts.

---

## `scan/apkleaks.json`

**Producer**: `clawditor.scan.apkleaks_run` — runs `apkleaks -f universal.apk --json`.
**Always produced**: only when `apkleaks` is on `PATH` and produced output; otherwise file is absent.
**Shape**: pass-through from upstream `apkleaks`. Schema owned by apkleaks, not clawditor.

```json
{
  "package": "string",
  "results": [
    {"name": "<category>", "matches": ["<string>", "…"]}
  ]
}
```

**Example** (from `data/com.example.app_run2/scan/apkleaks.json`):

```json
{
  "package": "com.example.app",
  "results": [
    {"name": "Firebase", "matches": ["stoked-virtue-769.firebaseio.com"]},
    {"name": "Google_API_Key", "matches": ["AIzaSyEXAMPLE_FAKE_KEY_FOR_DOCS_ONLY99"]},
    {"name": "Google_Cloud_Platform_OAuth",
     "matches": ["123456789012-examplefakeoauthclient0000000000.apps.googleusercontent.com"]},
    {"name": "JSON_Web_Token", "matches": ["eyJ…", "eyJ…"]},
    {"name": "IP_Address", "matches": ["0.0.0.0", "8.8.8.8"]},
    {"name": "LinkFinder", "matches": ["/api/v1/…"]}
  ]
}
```

**Consumer notes**:
- `findings.py:_from_apkleaks` iterates `.results[]`, maps `name` to severity (LOW default; `AWS_Access_Key_ID`/`Slack_Webhook`=HIGH; `Google_API_Key`/`Firebase`/`IP_Address`/`LinkFinder`=INFO).
- `jq '.results[] | select(.name=="LinkFinder") | .matches[]' scan/apkleaks.json | awk -F/ '{print $3}' | sort -u` — unique hosts referenced.

---

## `scan/trufflehog.json`

**Producer**: `clawditor.scan.trufflehog_run` — runs `trufflehog filesystem decompiled/ --json --no-update`, collects each JSONL line into an array.
**Always produced**: only when `trufflehog` is on `PATH`.
**Shape**: JSON **array** of trufflehog detector hits. Schema owned by trufflehog.

```json
[
  {
    "SourceMetadata": {"Data": {"Filesystem": {"file": "/abs/path/to/file", "line": 123}}},
    "SourceID": 1, "SourceType": 15, "SourceName": "trufflehog - filesystem",
    "DetectorType": 414, "DetectorName": "TomorrowIO",
    "DetectorDescription": "…",
    "DecoderName": "PLAIN",
    "Verified": false,
    "VerificationFromCache": false,
    "Raw": "<raw match>",
    "RawV2": "<optional secondary>",
    "Redacted": "<masked>",
    "ExtraData": null,
    "StructuredData": null
  }
]
```

**Example** (from `data/com.example.app_run2/scan/trufflehog.json`):

```json
[
  {
    "SourceMetadata": {"Data": {"Filesystem": {
      "file": "~/Documents/auditor/data/com.example.app_run2/decompiled/smali/resources/package_1/res/values/strings.xml",
      "line": 1131}}},
    "SourceID": 1, "SourceType": 15, "SourceName": "trufflehog - filesystem",
    "DetectorName": "FacebookOAuth", "DetectorType": 40,
    "DecoderName": "PLAIN", "Verified": false,
    "Raw": "FAKEFBAPPSECRETFORDOCSONLY0000000",
    "Redacted": "000000000000000"
  }
]
```

**Consumer notes**:
- `findings.py:_from_trufflehog` reads `DetectorName`, `Verified`, `SourceMetadata.Data.Filesystem.file`, `Redacted`. `Verified=true` → CRITICAL; otherwise MEDIUM.
- `jq '[.[] | select(.Verified)] | length' scan/trufflehog.json` — live-verified hit count.
- `jq -r 'group_by(.DetectorName)[] | "\(length)\t\(.[0].DetectorName)"' scan/trufflehog.json | sort -rn` — detector hit histogram.

---

## `scan/sdk_inventory.json`

**Producer**: `clawditor.scan.sdk_inventory` — parses `decompiled/smali/root/META-INF/**.properties` and `decompiled/smali/root/*-version.txt`.
**Always produced**: yes (empty `sdks` if nothing found).
**Shape**:

```json
{
  "sdks": [
    {"name": "string", "version": "string", "source": "<rel path from smali/root>"}
  ],
  "by_category": {
    "firebase": [{"name": "…", "version": "…", "source": "…"}],
    "google_play_services": [],
    "androidx": [],
    "third_party": []
  }
}
```

**Example**:

```json
{
  "sdks": [
    {"name": "firebase-analytics", "version": "21.6.1", "source": "META-INF/firebase-analytics.properties"},
    {"name": "play-services-base", "version": "18.5.0", "source": "META-INF/play-services-base.properties"},
    {"name": "androidx-core", "version": "1.13.1", "source": "androidx-core-version.txt"}
  ],
  "by_category": {
    "firebase": [{"name": "firebase-analytics", "version": "21.6.1", "source": "META-INF/firebase-analytics.properties"}],
    "google_play_services": [{"name": "play-services-base", "version": "18.5.0", "source": "META-INF/play-services-base.properties"}],
    "androidx": [{"name": "androidx-core", "version": "1.13.1", "source": "androidx-core-version.txt"}],
    "third_party": []
  }
}
```

**Consumer notes**:
- `findings.py:_from_sdk_inventory` emits ONE summary INFO finding listing category counts; no per-SDK finding (yet).
- `jq -r '.sdks[] | "\(.name)\t\(.version)"' scan/sdk_inventory.json | sort` — flat SDK list for CVE lookup.
- `jq '.by_category.third_party' scan/sdk_inventory.json` — non-Google/non-AndroidX SDKs (the interesting ones).

---

## `scan/network_security.json`

**Producer**: `clawditor.scan.network_security` — resolves the NSC XML referenced from `manifest.json` and parses it.
**Always produced**: yes. If no NSC: `summary="no NSC configured"` and most fields stay null/empty.
**Shape**:

```json
{
  "nsc_path": "string | null — rel path from decompiled/",
  "base_config": {"cleartext_permitted_raw": "string|null", "cleartext_permitted": "bool|null"} ,
  "domain_configs": [
    {"cleartext_permitted_raw": "…", "cleartext_permitted": false,
     "domains": ["app.example.com"]}
  ],
  "pin_sets": [
    {"domains": ["…"], "expiration": "string|null",
     "pins": [{"digest": "SHA-256", "value": "<base64>"}]}
  ],
  "user_trust_anchor": false,
  "gradle_placeholders": [
    {"where": "base-config | domain-config", "attr": "<attribute>",
     "value": "<raw attr value>", "placeholder": "${…}"}
  ],
  "cleartext_domains": ["app.example.com"],
  "summary": "string — short human summary"
}
```

**Example**:

```json
{
  "nsc_path": "smali/resources/package_1/res/xml/network_security_config.xml",
  "base_config": {"cleartext_permitted_raw": "false", "cleartext_permitted": false},
  "domain_configs": [
    {"cleartext_permitted_raw": "true", "cleartext_permitted": true,
     "domains": ["staging.example.com"]}
  ],
  "pin_sets": [
    {"domains": ["api.example.com"], "expiration": "2026-12-31",
     "pins": [{"digest": "SHA-256", "value": "AAAA…="}]}
  ],
  "user_trust_anchor": false,
  "gradle_placeholders": [],
  "cleartext_domains": ["staging.example.com"],
  "summary": "1 cleartext domain(s); 1 pin-set(s)"
}
```

**Consumer notes**:
- `findings.py:_from_network_security` emits HIGH for each `gradle_placeholders[]` entry, HIGH if `user_trust_anchor`, MEDIUM per `cleartext_domains[]`, INFO when `pin_sets` is non-empty. NOTE: there is no `findings[]` key in this file — the older stub `_from_network_security` reading `.findings` is dead code.
- `jq '.cleartext_domains, .gradle_placeholders, .user_trust_anchor' scan/network_security.json` — quick rule-posture check.

---

## `scan/cert_pinning.json`

**Producer**: `clawditor.scan.cert_pinning` — greps source tree (`jadx/sources` preferred, else `smali`) for OkHttp / TrustKit / Conscrypt usage.
**Always produced**: yes (`summary="no source"` if no decompiled tree).
**Shape**:

```json
{
  "pinners_found": [
    {"file": "<rel path>", "line": 123,
     "type": "OkHttpCertificatePinner | OkHttpCertificatePinnerApply | TrustKit | CustomSslSocketFactory | Conscrypt"}
  ],
  "okhttp_without_pinning": [
    {"file": "<rel path>", "line": 123}
  ],
  "trust_kit_used": false,
  "sensitive_app": false,
  "summary": "string"
}
```

**Example**:

```json
{
  "pinners_found": [
    {"file": "jadx/sources/com/example/net/HttpClient.java", "line": 88,
     "type": "OkHttpCertificatePinnerApply"}
  ],
  "okhttp_without_pinning": [
    {"file": "jadx/sources/com/example/upload/Uploader.java", "line": 42}
  ],
  "trust_kit_used": false,
  "sensitive_app": false,
  "summary": "1 pinner hit(s); 1 OkHttpClient without pinning"
}
```

**Consumer notes**:
- `findings.py:_from_cert_pinning` reads `pinners_found`, `okhttp_without_pinning`, `sensitive_app`, `trust_kit_used`. When `okhttp_without_pinning` is non-empty AND `pinners_found` is empty: HIGH if `sensitive_app` else INFO. NOTE: no `findings[]` key — the older stub reading `.findings` is dead code.
- `jq -r '.pinners_found[] | "\(.file):\(.line)\t\(.type)"' scan/cert_pinning.json` — list pin call sites.

---

## `scan/intent_security.json`

**Producer**: `clawditor.scan.intent_security` — cross-references `manifest.json` exported components with unsafe-extra-consumption regex patterns in their source.
**Always produced**: yes (empty array if no manifest or no jadx sources).
**Shape**: bare JSON **array** (the module returns `{"findings": [...]}` but writes the bare list to disk). Each entry:

```json
[
  {
    "exported_class": "com.example.deeplink.DeeplinkActivity",
    "pattern": "WebView loadUrl from extra | Uri.parse from extra | Intent forwarding | URL scheme prepend | File path from extra",
    "file": "jadx/sources/com/example/deeplink/DeeplinkActivity.java",
    "snippet": "… code window around the match (up to 200 chars) …"
  }
]
```

**Example**:

```json
[
  {
    "exported_class": "com.example.deeplink.DeeplinkActivity",
    "pattern": "WebView loadUrl from extra",
    "file": "jadx/sources/com/example/deeplink/DeeplinkActivity.java",
    "snippet": "String u = getIntent().getStringExtra(\"url\"); webView.loadUrl(u);"
  }
]
```

**Consumer notes**:
- `findings.py:_from_intent_security` iterates the array directly and emits each as HIGH-severity `intent_security`. (An earlier stub in the file expects a `{"findings": [...]}` wrapper and is shadowed/dead.)
- `jq 'group_by(.exported_class) | map({class:.[0].exported_class, patterns:map(.pattern)})' scan/intent_security.json` — group hits by component.

---

## `scan/flutter.json`

**Producer**: `clawditor.extract.flutter` — runs only when `stack.json:flutter == true` AND a `libapp.so` is found under `decompiled/native/`.
**Always produced**: no.
**Shape**:

```json
{
  "libapp_path": "string — rel path from decompiled/",
  "libapp_size": 12345,
  "notes": ["string", "…"],
  "url_count": 0,
  "unique_hosts": ["api.example.com"],
  "google_api_keys_in_dart": ["AIzaSy…"],
  "jwt_candidates": ["eyJ…"],
  "dart_packages": ["package:flutter/material.dart"]
}
```

If the `strings` dump fails, only `libapp_path`, `libapp_size`, `notes` are present.

**Example** (from `data/com.example.flutter_run2/scan/flutter.json`):

```json
{
  "libapp_path": "native/arm64-v8a/libapp.so",
  "libapp_size": 62695112,
  "notes": [
    "Dart AOT snapshot detected; full decompilation requires Blutter / reFlutter.",
    "What follows is a strings-only triage. Anything sensitive in the Dart code will need dynamic analysis (mitmproxy + Frida) or a manual Blutter pass."
  ],
  "url_count": 0,
  "unique_hosts": [],
  "google_api_keys_in_dart": [],
  "jwt_candidates": [],
  "dart_packages": []
}
```

**Consumer notes**:
- Not currently joined into `findings.json` (informational triage file).
- `jq '.unique_hosts' scan/flutter.json` — endpoint inventory for Dart-side traffic.
- `jq '.google_api_keys_in_dart' scan/flutter.json` — keys that bypassed the main secrets sweep (they live in compressed Dart constants).

---

## `probe/google_keys.json`

**Producer**: `clawditor.probe.google_keys` — iterates every `AIzaSy*` key from `secrets.json` × ~36 Google services.
**Always produced**: only when `secrets.json` exists and contains `google_api_key` hits.
**Shape**: dict keyed by raw API key.

```json
{
  "<AIzaSy…>": {
    "services": [
      {"service": "Maps Geocoding",
       "verdict": "LEAKED | SUCCESS | REACHED_ERR(<gcp-status>) | BLOCKED_ANDROID | BLOCKED_IP | BLOCKED_REFERRER | BLOCKED_API_RESTR | BLOCKED_METHOD | API_DISABLED | KEY_INVALID | QUOTA | MAPS_<status> | HTTP<n>",
       "detail": "string — truncated upstream error msg"}
    ],
    "summary": {"BLOCKED_ANDROID": 30, "REACHED_ERR": 4, "SUCCESS": 2}
  }
}
```

**Example**:

```json
{
  "AIzaSyEXAMPLE_FAKE_KEY_FOR_DOCS_ONLY99": {
    "services": [
      {"service": "Maps Geocoding", "verdict": "BLOCKED_ANDROID",
       "detail": "Requests from this Android client application are blocked"},
      {"service": "IT signUp (anon)", "verdict": "SUCCESS",
       "detail": "{\"kind\":\"identitytoolkit#SignupNewUserResponse\",…}"},
      {"service": "IT sendVerifyCode SMS", "verdict": "REACHED_ERR(INVALID_ARGUMENT)",
       "detail": "TOO_LONG"}
    ],
    "summary": {"BLOCKED_ANDROID": 30, "SUCCESS": 1, "REACHED_ERR": 1}
  }
}
```

**Consumer notes**:
- `findings.py:_from_google_keys` iterates each key, partitions services by verdict, emits CRITICAL on `LEAKED`, HIGH on `SUCCESS`, MEDIUM if no `BLOCKED_ANDROID` found (= key lacks Android restriction), HIGH on `sendVerifyCode` reach (SMS pumping), MEDIUM on `sendOobCode` (reset spam) and `createAuthUri` (user enumeration).
- `jq 'to_entries[] | {key:(.key|.[0:10]+"…"), summary:.value.summary}' probe/google_keys.json` — per-key verdict histogram.
- `jq -r 'to_entries[] | .key as $k | .value.services[] | select(.verdict=="SUCCESS") | "\($k|.[0:10]+"…")\t\(.service)"' probe/google_keys.json` — every fully-open service per key.

---

## `probe/firebase_rtdb.json`

**Producer**: `clawditor.probe.firebase_rtdb` — per RTDB URL, unauth + (when possible) anon-authed reads on common paths.
**Always produced**: only when at least one RTDB URL is derivable from `secrets.json`.
**Shape**: dict keyed by RTDB URL.

```json
{
  "<https://project-default-rtdb.firebaseio.com>": {
    "project": "project",
    "unauth": {
      "/": {"http": 401, "snippet": "Permission denied"},
      "users": {"http": 200, "snippet": "{\"u1\":{…}}"},
      "config": {"http": 401, "snippet": "…"}
    },
    "auth": {
      "/": {"http": 401, "snippet": "…"},
      "users": {"http": 200, "snippet": "…"}
    },
    "auth_used": true
  }
}
```

Paths probed: `""` (root), `users`, `config`, `app_config`, `settings`, `remote_config`, `app`, `catalog`, `stories`, `episodes`, `shows`, `channels`, `messages`, `chats`, `leaderboard`. Root key is `"/"`.

**Example**:

```json
{
  "https://stoked-virtue-769.firebaseio.com": {
    "project": "stoked-virtue-769",
    "unauth": {
      "/": {"http": 401, "snippet": "{ \"error\" : \"Permission denied\" }"},
      "config": {"http": 200, "snippet": "{\"feature_x\":true}"}
    },
    "auth": {
      "/": {"http": 401, "snippet": "…"},
      "users": {"http": 200, "snippet": "{\"uid1\":true}"}
    },
    "auth_used": true
  }
}
```

**Consumer notes**:
- `findings.py:_from_firebase_rtdb` flags CRITICAL when any `unauth[*].http == 200`, HIGH when any `auth[*].http == 200`.
- `jq -r 'to_entries[] | .key as $u | .value.unauth | to_entries[] | select(.value.http==200) | "\($u)\t\(.key)"' probe/firebase_rtdb.json` — open unauth paths.

---

## `probe/firebase_firestore.json`

**Producer**: `clawditor.probe.firebase_firestore` — per project derived from storage buckets / RTDB URLs, mints an anon identity and probes Firestore rule boundary.
**Always produced**: only when at least one Firebase project is derivable AND at least one AIzaSy key exists.
**Shape**: dict keyed by project id.

```json
{
  "<project-id>": {
    "auth_used": true,
    "uid": "<localId of minted anon>",
    "status": "string — only present when auth could not be minted",
    "db_existence_check": {"http": 200, "snippet": "…"},
    "collection_list": {
      "users":   {"http": 403, "snippet": "Missing or insufficient permissions"},
      "config":  {"http": 200, "snippet": "{}"},
      "...":     {"http": 0, "snippet": "…"}
    },
    "own_uid_read": {"http": 404, "snippet": "…"},
    "structured_query_users": {"http": 403, "snippet": "…"}
  }
}
```

Collections probed: `users`, `config`, `app_config`, `remote_config`, `catalog`, `episodes`, `stories`, `shows`, `settings`, `public`, `products`, `orders`, `messages`, `chats`.

**Example**:

```json
{
  "stoked-virtue-769": {
    "auth_used": true,
    "uid": "abcDEF1234",
    "db_existence_check": {"http": 200, "snippet": "{\"documents\":[]}"},
    "collection_list": {
      "users": {"http": 403, "snippet": "Missing or insufficient permissions."},
      "config": {"http": 200, "snippet": "{\"documents\":[{\"name\":\"…/config/global\",…}]}"}
    },
    "own_uid_read": {"http": 404, "snippet": "Not found"},
    "structured_query_users": {"http": 403, "snippet": "Missing or insufficient permissions."}
  }
}
```

**Consumer notes**:
- `findings.py:_from_firebase_firestore` flags HIGH on `structured_query_users.http==200 && "readTime" in snippet` (unfiltered list allowed), and HIGH per collection with `http==200` and a non-empty body.
- `jq -r 'to_entries[] | .key as $p | .value.collection_list | to_entries[] | select(.value.http==200 and (.value.snippet|test("documents"))) | "\($p)\t\(.key)"' probe/firebase_firestore.json` — readable collections.

---

## `probe/firebase_storage.json`

**Producer**: `clawditor.probe.firebase_storage` — per Firebase storage bucket: try listing (Firebase + GCS endpoints) + 31 common path enumeration.
**Always produced**: only when at least one storage bucket is in `secrets.json` (after filtering example/myservice/r.appspot domains).
**Shape**: dict keyed by bucket.

```json
{
  "<bucket.appspot.com | bucket.firebasestorage.app>": {
    "listing":      {"http": 403, "snippet": "Permission denied"},
    "gcs_listing":  {"http": 401, "snippet": "Anonymous caller does not have storage.objects.list…"},
    "path_probe": {
      "robots.txt":  {"http": 404, "snippet": "…"},
      "config/app.json": {"http": 200, "snippet": "{\"feature\":true}"},
      "...":         {"http": 404, "snippet": "…"}
    },
    "publicly_readable_paths": ["config/app.json"]
  }
}
```

**Example**:

```json
{
  "stoked-virtue-769.appspot.com": {
    "listing": {"http": 403, "snippet": "Permission denied. Could not access bucket"},
    "gcs_listing": {"http": 401, "snippet": "Anonymous caller does not have storage.objects.list"},
    "path_probe": {
      "robots.txt": {"http": 404, "snippet": "Not Found"},
      "config/app.json": {"http": 200, "snippet": "{\"min_version\":42}"}
    },
    "publicly_readable_paths": ["config/app.json"]
  }
}
```

**Consumer notes**:
- `findings.py:_from_firebase_storage` flags CRITICAL when `listing.http==200` (unauth listing allowed), HIGH when `publicly_readable_paths` non-empty.
- `jq -r 'to_entries[] | .key as $b | .value.publicly_readable_paths[]? | "\($b)\t\(.)"' probe/firebase_storage.json` — accessible files per bucket.

---

## `probe/ai_keys.json`

**Producer**: `clawditor.probe.ai_keys` — read-only `GET` against each provider's `/models` or `/user` endpoint for AI / SaaS keys found by `secrets.json`.
**Always produced**: only when at least one matching key was scanned AND a probe ran (file is skipped when `results` is empty).
**Shape**: dict keyed by raw key.

```json
{
  "<api-key>": {
    "provider": "openai | anthropic | xai | github | razorpay | mapbox | sentry",
    "verdict": "VALID | INVALID | RATE_LIMITED | ERROR",
    "detail": "string — truncated provider response (first 140 chars)"
  }
}
```

Verdict map: HTTP 200 → VALID; 401/403 → INVALID; 429 → RATE_LIMITED; 0 / other → ERROR. Sentry is special-cased: any HTTP response counts as VALID (DSN reachability check).

**Example**:

```json
{
  "sk-proj-AbCdEf...XYZ": {
    "provider": "openai", "verdict": "INVALID",
    "detail": "{\"error\":{\"message\":\"Incorrect API key provided…\"}}"
  },
  "https://abcdef…@o12345.ingest.sentry.io/42": {
    "provider": "sentry", "verdict": "VALID",
    "detail": "reachable HTTP401; host=o12345.ingest.sentry.io project=42"
  }
}
```

**Consumer notes**:
- `findings.py:_from_ai_keys`: VALID → CRITICAL, RATE_LIMITED → MEDIUM, INVALID → LOW. `ERROR`/unset → skipped.
- `jq -r 'to_entries[] | select(.value.verdict=="VALID") | "\(.value.provider)\t\(.key)"' probe/ai_keys.json` — live keys to rotate first.

---

## `reports/findings.json`

**Producer**: `clawditor.report.findings.collect` + `clawditor.report.markdown.run` — joins every scan/probe JSON into a uniform list.
**Always produced**: yes (empty array if nothing was found).
**Shape**: bare JSON **array** of finding objects, sorted ascending by `SEVERITY_ORDER` (`CRITICAL` first → `INFO` last).

```json
[
  {
    "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
    "category": "manifest | secrets | code | apkleaks | trufflehog | google_key | firebase_rtdb | firebase_firestore | firebase_storage | ai_keys | intent_security | sdk_inventory | network_security | cert_pinning",
    "title": "string — one-line description",
    "location": "string — file:line, URL, GCP, bucket name, etc.",
    "evidence": "string — short snippet / values / detail (truncated to ~200 chars by mdwriter)"
  }
]
```

**Example**:

```json
[
  {
    "severity": "CRITICAL",
    "category": "google_key",
    "title": "key flagged as LEAKED by Google: AIzaSyEXAM…99Y99",
    "location": "GCP",
    "evidence": "detector fired on: IT signUp (anon), IT sendOobCode reset"
  },
  {
    "severity": "HIGH",
    "category": "firebase_storage",
    "title": "bucket stoked-virtue-769.appspot.com serves these guessed paths to unauth: ['config/app.json']",
    "location": "stoked-virtue-769.appspot.com",
    "evidence": "config/app.json"
  },
  {
    "severity": "INFO",
    "category": "sdk_inventory",
    "title": "47 third-party SDK(s) catalogued",
    "location": "scan/sdk_inventory.json",
    "evidence": "categories: firebase=8, google_play_services=14, androidx=22, third_party=3; grep this file for CVE candidates"
  }
]
```

**Consumer notes**:
- This is the **canonical agent contract**. Every category emits at least one finding when applicable. Severity values are exactly the five constants above.
- `jq '[.[] | select(.severity=="CRITICAL" or .severity=="HIGH")]' reports/findings.json` — actionable subset.
- `jq -r 'group_by(.category)[] | "\(length)\t\(.[0].category)"' reports/findings.json | sort -rn` — findings histogram by category.
- `jq -r '.[] | "[\(.severity)] [\(.category)] \(.title)"' reports/findings.json` — flat printable list.

---

## `reports/findings.md`

**Producer**: `clawditor.report.markdown._write_findings_md`.
**Always produced**: yes.
**Shape**: a single markdown table mirror of `findings.json` with columns `Sev | Category | Title | Location | Evidence`. Severity wrapped in bold; pipes in any field escaped. Use `findings.json` for any programmatic consumption; this file is for humans.

---

## `reports/SUMMARY.md`

**Producer**: `clawditor.report.markdown._write_summary`.
**Always produced**: yes.
**Shape** (sections): `# Audit summary — <package>`, then bullet list (started, stack, severity counts), then `## Top findings` (first 15 findings as bullets with `**SEVERITY** [category] title` and a sub-bullet `\`location\` — evidence`), then `## Artifacts` (relative paths to `decompiled/`, `scan/`, `probe/`, findings), then `## Notes` (caveats about probe semantics and verified flags).

---

## `reports/deep-dive-guide.md`

**Producer**: `clawditor.report.deep_dive_guide.run` — agent-facing guidance, conditioned on which categories appeared.
**Always produced**: yes.
**Shape** (sections): top intro paragraph; then one section per finding category present in this run (`## \`<cat>\` — N finding(s)`) with "Structured output" → JSON path, "Source artifact" → decompiled file, and a "Next steps" bullet list. If `google_key` appeared, an additional "## Re-running just the probes" code-block section is appended.

---

## `reports/next-steps.md`

**Producer**: `clawditor.report.next_steps.run` — prioritized checklist.
**Always produced**: yes.
**Shape**: `# Next steps` header, then a `## CRITICAL` / `## HIGH` / `## MEDIUM` / `## LOW` section (only those with findings). Each finding becomes a `- [ ] **[category]** title` with sub-bullets `location:`, `evidence:`, and zero-or-more `**do**:` action hints from `_action_hints()` (e.g. "rotate the key today in GCP Console").

---

## `MANIFEST.md`

**Producer**: `clawditor.report.manifest.run` — per-run entry point.
**Always produced**: yes.
**Shape** (sections): `# Run manifest — <target>` header; "What this run found" (started timestamp, flags, severity + category counts); "File layout" (annotated tree); "Deep-dive entry points" (a quick-reference table per category and a pointer to `deep-dive-guide.md`); "Re-running probes"; "Notes".

This is the suggested first file to open when landing in a run dir cold.
