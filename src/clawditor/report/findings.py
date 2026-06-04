"""Convert scan + probe JSON into a uniform findings list with severity tags."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from clawditor.config import RunContext


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def collect(ctx: RunContext) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_from_manifest(ctx))
    findings.extend(_from_secrets(ctx))
    findings.extend(_from_code_patterns(ctx))
    findings.extend(_from_apkleaks(ctx))
    findings.extend(_from_trufflehog(ctx))
    findings.extend(_from_google_keys(ctx))
    findings.extend(_from_firebase_rtdb(ctx))
    findings.extend(_from_firebase_firestore(ctx))
    findings.extend(_from_firebase_storage(ctx))
    findings.extend(_from_ai_keys(ctx))
    findings.extend(_from_intent_security(ctx))
    findings.extend(_from_sdk_inventory(ctx))
    findings.extend(_from_network_security(ctx))
    findings.extend(_from_cert_pinning(ctx))
    findings.extend(_from_payment_sdk(ctx))
    findings.extend(_from_s3_buckets(ctx))
    findings.extend(_from_asset_inspector(ctx))
    findings.extend(_from_applinks(ctx))
    findings.extend(_from_build_leaks(ctx))
    findings.extend(_from_privacy(ctx))
    findings.extend(_from_jwt_analyzer(ctx))
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return findings


def _read_json(p: Path) -> dict | list | None:
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _from_manifest(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "manifest.json")
    if not d:
        return
    app = d.get("application", {})
    if app.get("debuggable"):
        yield _f("HIGH", "manifest", "android:debuggable=true in production",
                 "AndroidManifest.xml", "debuggable flag enables runtime debugger attach + JS console in WebView")
    if app.get("uses_cleartext_traffic") and not app.get("network_security_config"):
        yield _f("MEDIUM", "manifest", "usesCleartextTraffic=true and no networkSecurityConfig",
                 "AndroidManifest.xml", "permits HTTP downgrade for all destinations")
    if app.get("allow_backup", True) and not app.get("data_extraction_rules") and not app.get("full_backup_content"):
        yield _f("MEDIUM", "manifest", "allowBackup=true with no extraction/backup rules",
                 "AndroidManifest.xml", "all SharedPreferences/DataStore eligible for adb backup + Google Drive Auto Backup")
    # Exported components without permissions
    for kind, items in d.get("exported_components", {}).items():
        for it in items:
            if not it.get("permission"):
                yield _f("LOW", "manifest", f"exported {kind[:-1]} without permission: {it.get('name')}",
                         "AndroidManifest.xml", "any other app can interact with this component")
    # Deeplinks
    for link in d.get("deeplinks", []):
        if any(s in ("http", "https") for s in link.get("schemes", [])) and not link.get("hosts"):
            yield _f("LOW", "manifest", f"deeplink with http(s) scheme and no host restriction in {link.get('activity')}",
                     "AndroidManifest.xml", "overly broad deeplink filter; can be triggered by any site")


def _from_secrets(ctx: RunContext) -> Iterator[dict]:
    from clawditor.utils.vendor import split_vendor
    d = _read_json(ctx.scan_dir / "secrets.json")
    if not d:
        return
    for typ, items in d.items():
        if not items:
            continue
        # Separate app-owned vs vendor matches. Vendor hits are usually false
        # positives (regex matched string literal inside an SDK), so they get
        # demoted by one severity and tagged as such.
        app_items, vendor_items = split_vendor(items)
        # JWTs and bearer tokens are HIGH-confidence noise — but worth listing as INFO
        sev = {
            "google_api_key": "INFO",
            "firebase_rtdb_url": "INFO",
            "firebase_storage_bucket": "INFO",
            "google_oauth_client_id": "INFO",
            "aws_access_key_id": "HIGH",
            "stripe_secret_key": "HIGH",
            "slack_token": "HIGH",
            "branch_key": "INFO",
            "jwt": "LOW",
            "appsflyer_dev_key": "INFO",
            # AI provider keys
            "openai_key": "HIGH",
            "anthropic_key": "HIGH",
            "xai_grok_key": "HIGH",
            "huggingface_token": "HIGH",
            # Source / infra / crypto
            "github_token": "HIGH",
            "gcp_service_account_json": "CRITICAL",
            "pem_private_key": "CRITICAL",
            # Payments
            "razorpay_key": "HIGH",
            # Geo / observability
            "mapbox_token": "MEDIUM",
            "sentry_dsn": "MEDIUM",
            # Chat ops
            "slack_webhook": "HIGH",
            "discord_webhook": "HIGH",
            # Lower-confidence / heavily-restricted
            "twilio_account_sid": "MEDIUM",
            "mailgun_key": "MEDIUM",
            "algolia_app_id_key": "MEDIUM",
            # AWS / S3 — bucket-URL findings are INFO; the active S3 probe upgrades
            # severity if a bucket is publicly listable or readable.
            "s3_bucket_url": "INFO",
            "s3_virtual_path_url": "INFO",
            "cloudfront_url": "INFO",
            "aws_secret_access_key_context": "CRITICAL",
            "gcs_bucket_url": "INFO",
            "azure_blob_url": "INFO",
            "do_spaces_url": "INFO",
        }.get(typ, "INFO")
        if app_items:
            yield _f(sev, "secrets",
                     f"{typ}: {len(app_items)} unique app-owned value(s) in binary",
                     app_items[0].get("file", "?"),
                     ", ".join(it["value"][:10] + "…" for it in app_items[:5]))
        if vendor_items:
            yield _f(_demote(sev), "secrets",
                     f"{typ}: {len(vendor_items)} match(es) inside vendor SDK code (likely FP)",
                     vendor_items[0].get("file", "?"),
                     ", ".join(it["value"][:10] + "…" for it in vendor_items[:5]))


_DEMOTE = {"CRITICAL": "MEDIUM", "HIGH": "LOW", "MEDIUM": "LOW", "LOW": "INFO", "INFO": "INFO"}


def _demote(sev: str) -> str:
    return _DEMOTE.get(sev, "INFO")


def _from_code_patterns(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "code_patterns.json")
    if not d:
        return
    sev_map = {
        "webview_universal_file_access": "HIGH",
        "webview_file_url_access": "HIGH",
        "webview_addjs_interface": "MEDIUM",
        "webview_js_enabled": "INFO",
        "webview_load_data_with_base_url": "MEDIUM",
        "webview_mixed_content_always_allow": "HIGH",
        "webview_mixed_content_compatibility": "MEDIUM",
        "webview_safe_browsing_disabled": "MEDIUM",
        "webview_safe_browsing_manifest_disabled": "MEDIUM",
        "webview_save_password": "MEDIUM",
        "webview_save_form_data": "LOW",
        "webview_geolocation_enabled": "INFO",
        "webview_geolocation_always_allow": "HIGH",
        "webview_database_enabled": "INFO",
        "webview_content_access": "MEDIUM",
        "webview_plugin_enabled": "MEDIUM",
        "webview_user_agent_set": "INFO",
        "webview_debugging_enabled": "HIGH",  # CRITICAL if also debuggable=true at manifest
        "webview_third_party_cookies": "LOW",
        "trust_all_certificates": "CRITICAL",
        "hostname_verifier_accept_all": "CRITICAL",
        "hostname_verifier_lambda": "HIGH",
        "rsa_ecb_pkcs1": "MEDIUM",
        "aes_ecb": "MEDIUM",
        "des": "MEDIUM",
        "weak_random": "LOW",
        "zero_iv": "MEDIUM",
        "raw_query_concat": "HIGH",
        "exec_sql_concat": "HIGH",
        "firestore_instance": "INFO",
        "firestore_collection_literal": "INFO",
        "rtdb_get_reference": "INFO",
        "log_token": "MEDIUM",
        "pending_intent_mutable": "HIGH",
        "pending_intent_no_immutable": "MEDIUM",
        "intent_serializable_extra": "MEDIUM",
        "intent_parcelable_extra_no_type": "LOW",
        "implicit_intent_outside_app": "LOW",
        "intent_redirection_pattern": "HIGH",
        "file_from_intent_extra_no_canonicalize": "HIGH",
        "file_provider_authority_wildcard": "MEDIUM",
        "objectinput_stream_external": "CRITICAL",
        "yaml_load_default": "HIGH",
        "missing_filter_touches": "MEDIUM",
        "flag_secure_missing_check": "INFO",
        "clipboard_write_sensitive": "MEDIUM",
        "runtime_exec": "MEDIUM",
        "loadlibrary_dynamic": "HIGH",
        "http_url_constant": "LOW",
        "okhttp_no_cert_pinning": "INFO",
        "trust_manager_empty": "CRITICAL",
        "trust_manager_lambda": "CRITICAL",
        "ssl_hostname_verify_all": "CRITICAL",
        "xml_parser_no_disallow_doctype": "MEDIUM",
        "sax_parser_no_secure": "MEDIUM",
        "log_pii_pattern": "MEDIUM",
        "root_check_simple_su": "INFO",
        "frida_check_string": "INFO",
        "accessibility_service_text_changed": "HIGH",
        "oauth_redirect_uri_localhost": "MEDIUM",
        "dex_class_loader": "MEDIUM",
        "path_class_loader_external": "HIGH",
        "dex_class_loader_from_extra": "CRITICAL",  # RCE
        "dex_class_loader_from_url": "CRITICAL",
        "class_forname_from_extra": "HIGH",
        "method_invoke_from_extra": "HIGH",
        "method_getmethod_from_extra": "MEDIUM",
        "runtime_exec_from_extra": "CRITICAL",
        "processbuilder_from_extra": "CRITICAL",
        "reflection_field_set_accessible": "LOW",  # very common in serialization libs; mostly noise
        "system_loadlibrary_from_extra": "CRITICAL",
        "webview_evaluate_javascript_from_extra": "HIGH",
        "file_input_stream_from_extra": "HIGH",   # path traversal / read of arbitrary files
        "file_output_stream_from_extra": "CRITICAL",  # overwrite arbitrary files
        "content_resolver_from_extra": "HIGH",
        "sharedprefs_world_readable": "HIGH",     # deprecated since API 17
        "sharedprefs_world_writeable": "CRITICAL",
        "openfileoutput_world_readable": "HIGH",
        "sendbroadcast_no_permission": "LOW",     # high false-positive rate
        "register_receiver_no_permission": "LOW",
    }
    from clawditor.utils.vendor import split_vendor
    for pat, hits in d.items():
        if not hits:
            continue
        sev = sev_map.get(pat, "LOW")
        app_hits, vendor_hits = split_vendor(hits, file_key="file")
        if app_hits:
            evidence = app_hits[0].get("match", app_hits[0].get("raw", ""))[:140]
            loc = app_hits[0].get("file", "?") + (":" + app_hits[0]["line"] if "line" in app_hits[0] else "")
            yield _f(sev, "code", f"{pat} ({len(app_hits)} app-owned hit(s))", loc, evidence)
        if vendor_hits:
            evidence = vendor_hits[0].get("match", vendor_hits[0].get("raw", ""))[:140]
            loc = vendor_hits[0].get("file", "?") + (":" + vendor_hits[0]["line"] if "line" in vendor_hits[0] else "")
            yield _f(_demote(sev), "code",
                     f"{pat} ({len(vendor_hits)} vendor SDK hit(s); usually FP)",
                     loc, evidence)


def _from_apkleaks(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "apkleaks.json")
    if not d:
        return
    for r in d.get("results", []):
        name = r.get("name", "?")
        matches = r.get("matches", [])
        if not matches:
            continue
        sev = {
            "JSON_Web_Token": "LOW",
            "Google_API_Key": "INFO",
            "Firebase": "INFO",
            "Facebook_Secret_Key": "INFO",
            "Artifactory_Password": "LOW",
            "Slack_Webhook": "HIGH",
            "AWS_Access_Key_ID": "HIGH",
            "Authorization_Basic": "INFO",
            "Authorization_Bearer": "MEDIUM",
            "HackerOne_CTF_Flag": "INFO",
            "IP_Address": "INFO",
            "LinkFinder": "INFO",
        }.get(name, "LOW")
        yield _f(sev, "apkleaks", f"{name} ({len(matches)} match(es))", "apkleaks",
                 str(matches[0])[:140])


# Trufflehog detectors with notoriously loose regex (32-char base64-like) that
# match Java DEX bytecode identifiers, signing manifests, ad SDK obfuscation
# strings, etc. Demote unverified hits from these to INFO.
LOOSE_TRUFFLEHOG_DETECTORS = {"Box", "Generic_API_Key", "Generic", "GoogleGeminiAPIKey",
                              "UnifyID", "RapidAPI"}


def _from_trufflehog(ctx: RunContext) -> Iterator[dict]:
    from clawditor.utils.vendor import is_vendor
    d = _read_json(ctx.scan_dir / "trufflehog.json")
    if not d:
        return
    for hit in d:
        verified = hit.get("Verified", False)
        det = hit.get("DetectorName", "?")
        meta = hit.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        file = meta.get("file", "?")
        # Verified = real live secret, regardless of detector or location.
        if verified:
            yield _f("CRITICAL", "trufflehog", f"{det} (VERIFIED LIVE SECRET)",
                     file, hit.get("Redacted", "")[:100])
            continue
        # Unverified: weight by detector quality + file location.
        in_vendor = is_vendor(file) or any(p in file for p in (".dex", "META-INF/", ".SF", ".RSA", ".DSA"))
        is_loose = det in LOOSE_TRUFFLEHOG_DETECTORS
        if is_loose and in_vendor:
            sev = "INFO"     # near-certain false positive
        elif is_loose:
            sev = "LOW"
        elif in_vendor:
            sev = "LOW"      # detector is decent but inside vendor code → likely sample/example
        else:
            sev = "MEDIUM"   # high-confidence detector in app-owned code
        suffix = " in vendor/bytecode (likely FP)" if in_vendor else ""
        yield _f(sev, "trufflehog", f"{det} (unverified{suffix})", file,
                 hit.get("Redacted", "")[:100])


def _from_google_keys(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.probe_dir / "google_keys.json")
    if not d:
        return
    for key, info in d.items():
        services = info.get("services", [])
        leaked = [s for s in services if s["verdict"] == "LEAKED"]
        success = [s for s in services if s["verdict"] == "SUCCESS"]
        reached = [s for s in services if s["verdict"].startswith("REACHED_ERR")]
        android_blocked = [s for s in services if s["verdict"] == "BLOCKED_ANDROID"]
        if leaked:
            yield _f("CRITICAL", "google_key",
                     f"key flagged as LEAKED by Google: {key[:10]}…{key[-4:]}",
                     "GCP", f"detector fired on: {', '.join(s['service'] for s in leaked)}")
        if success:
            yield _f("HIGH", "google_key",
                     f"key has {len(success)} fully-open service(s): {key[:10]}…{key[-4:]}",
                     "GCP", f"SUCCESS on: {', '.join(s['service'] for s in success[:6])}")
        if not android_blocked and (success or reached):
            yield _f("MEDIUM", "google_key",
                     f"key has NO Android package restriction: {key[:10]}…{key[-4:]}",
                     "GCP",
                     "any restriction is API-level only; consider adding package + SHA-1 restriction")
        # SMS pumping / OOB email specifically
        for s in reached:
            if "sendVerifyCode" in s["service"]:
                yield _f("HIGH", "google_key",
                         f"Identity Toolkit sendVerificationCode reachable: SMS pumping risk on {key[:10]}…{key[-4:]}",
                         "GCP",
                         "attacker can trigger billed SMS to attacker-controlled numbers in expensive countries")
            elif "sendOobCode" in s["service"]:
                yield _f("MEDIUM", "google_key",
                         f"Identity Toolkit sendOobCode reachable: password-reset spam risk on {key[:10]}…{key[-4:]}",
                         "GCP",
                         "attacker can trigger reset emails to arbitrary addresses")
            elif "createAuthUri" in s["service"]:
                yield _f("MEDIUM", "google_key",
                         f"Identity Toolkit createAuthUri reachable: user enumeration risk on {key[:10]}…{key[-4:]}",
                         "GCP",
                         "registered:true/false field reveals account existence for any email")


def _from_firebase_rtdb(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.probe_dir / "firebase_rtdb.json")
    if not d:
        return
    for url, info in d.items():
        # Look for HTTP 200 on unauth (open rule) or non-401 on auth path that's not 404
        opens = [p for p, r in info.get("unauth", {}).items() if r.get("http") == 200]
        if opens:
            yield _f("CRITICAL", "firebase_rtdb",
                     f"RTDB allows unauthenticated read on: {opens}",
                     url, "anyone on the internet can dump these paths")
        auth_opens = [p for p, r in info.get("auth", {}).items() if r.get("http") == 200]
        if auth_opens:
            yield _f("HIGH", "firebase_rtdb",
                     f"RTDB allows ANY authenticated user to read: {auth_opens}",
                     url, "rules are 'auth != null' or weaker; any anon user can dump these paths")


def _from_firebase_firestore(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.probe_dir / "firebase_firestore.json")
    if not d:
        return
    for proj, info in d.items():
        # structured_query_users returned 200 with [{readTime}] = rules allow LIST
        sq = info.get("structured_query_users", {})
        if sq.get("http") == 200 and "readTime" in sq.get("snippet", ""):
            yield _f("HIGH", "firebase_firestore",
                     f"Firestore /users LIST allowed to anon-auth user in project {proj}",
                     proj, "rules permit unfiltered list; existing docs would be exposed")
        # public-style collections returning 200
        for c, r in info.get("collection_list", {}).items():
            if r.get("http") == 200 and r.get("snippet", "").strip() not in ("{}", ""):
                yield _f("HIGH", "firebase_firestore",
                         f"collection /{c} returned non-empty body to anon auth in {proj}",
                         proj, r.get("snippet", "")[:120])


def _from_firebase_storage(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.probe_dir / "firebase_storage.json")
    if not d:
        return
    for bucket, info in d.items():
        listing = info.get("listing", {})
        if listing.get("http") == 200:
            yield _f("CRITICAL", "firebase_storage",
                     f"bucket {bucket} allows UNAUTHENTICATED listing",
                     bucket, "rules_version=2 with allow list to all; attacker can enumerate all files")
        public_paths = info.get("publicly_readable_paths", [])
        if public_paths:
            yield _f("HIGH", "firebase_storage",
                     f"bucket {bucket} serves these guessed paths to unauth: {public_paths}",
                     bucket, ", ".join(public_paths))


def _from_ai_keys(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.probe_dir / "ai_keys.json")
    if not d:
        return
    sev_for_verdict = {"VALID": "CRITICAL", "RATE_LIMITED": "MEDIUM", "INVALID": "LOW"}
    for key, info in d.items():
        verdict = info.get("verdict", "ERROR")
        provider = info.get("provider", "?")
        sev = sev_for_verdict.get(verdict)
        if not sev:
            continue  # ERROR / UNAUTHORIZED with no clear signal — skip
        title = {
            "CRITICAL": f"LIVE {provider} key confirmed by provider API",
            "MEDIUM": f"{provider} key probe rate-limited (cannot confirm)",
            "LOW": f"{provider} key rejected by provider (likely revoked or invalid)",
        }[sev]
        yield _f(sev, "ai_keys", title,
                 f"{provider}:{key[:10]}…{key[-4:]}",
                 info.get("detail", "")[:140])


def _from_intent_security(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "intent_security.json")
    if not d:
        return
    # The intent_security module writes a flat list of findings (one per match).
    # Each is a cross-reference of an exported component AND an unsafe extra-consumption
    # pattern — high confidence, so always HIGH.
    for entry in d:
        cls = entry.get("exported_class", "?")
        pattern = entry.get("pattern", "?")
        yield _f("HIGH", "intent_security",
                 f"exported {cls} consumes intent extra unsafely: {pattern}",
                 entry.get("file", "?"),
                 entry.get("snippet", "")[:140])


def _from_sdk_inventory(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "sdk_inventory.json")
    if not d:
        return
    sdks = d.get("sdks", [])
    if not sdks:
        return
    cats = d.get("by_category", {})
    cat_summary = ", ".join(f"{k}={len(v)}" for k, v in cats.items() if v)
    yield _f("INFO", "sdk_inventory",
             f"{len(sdks)} third-party SDK(s) catalogued",
             "scan/sdk_inventory.json",
             f"categories: {cat_summary}; grep this file for CVE candidates")


def _from_network_security(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "network_security.json")
    if not d:
        return
    loc = d.get("nsc_path") or "network_security_config.xml"
    for ph in d.get("gradle_placeholders", []):
        yield _f("HIGH", "network_security",
                 f"unresolved Gradle placeholder {ph.get('placeholder')} in NSC "
                 f"({ph.get('where')}@{ph.get('attr')})",
                 loc,
                 f"value={ph.get('value', '')[:120]}; build leaked an unresolved template into production")
    if d.get("user_trust_anchor"):
        yield _f("HIGH", "network_security",
                 "NSC trusts user-installed CAs (certificates src=\"user\")",
                 loc,
                 "any sideloaded CA can MITM TLS — defeats the point of pinning")
    for dom in d.get("cleartext_domains", []):
        yield _f("MEDIUM", "network_security",
                 f"NSC permits cleartext to non-IP domain: {dom}",
                 loc,
                 "explicit cleartextTrafficPermitted=true on a real domain; HTTP downgrade possible")
    if d.get("pin_sets"):
        n = len(d["pin_sets"])
        yield _f("INFO", "network_security",
                 f"NSC declares {n} pin-set(s)",
                 loc,
                 "cert pinning configured at platform level — good practice")


def _from_cert_pinning(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "cert_pinning.json")
    if not d:
        return
    pinners = d.get("pinners_found", [])
    no_pin = d.get("okhttp_without_pinning", [])
    sensitive = d.get("sensitive_app", False)
    if d.get("trust_kit_used"):
        yield _f("INFO", "cert_pinning",
                 "TrustKit-Android referenced for pinning",
                 "cert_pinning.json",
                 "third-party pinning library detected; review configured domains")
    if pinners:
        yield _f("INFO", "cert_pinning",
                 f"{len(pinners)} certificate-pinning hint(s) found",
                 pinners[0].get("file", "?") + f":{pinners[0].get('line', '?')}",
                 f"types: {sorted({p['type'] for p in pinners})}")
    if no_pin and not pinners:
        sev = "HIGH" if sensitive else "INFO"
        loc = no_pin[0].get("file", "?") + f":{no_pin[0].get('line', '?')}"
        yield _f(sev, "cert_pinning",
                 f"OkHttpClient.Builder used in {len(no_pin)} file(s) with no certificatePinner",
                 loc,
                 "no certificate pinning detected anywhere in the app "
                 + ("(sensitive-app heuristic matched — banking/auth/payment context)"
                    if sensitive else "(non-sensitive app context)"))


def _from_payment_sdk(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "payment_sdk.json")
    if not d:
        return
    for entry in d.get("findings", []) or []:
        sdk = entry.get("sdk", "?")
        keys = entry.get("keys", []) or []
        # One INFO row per detected SDK (location: scan/payment_sdk.json).
        ev_bits = []
        if keys:
            ev_bits.append(f"{len(keys)} key(s): " + ", ".join(k[:14] + "..." for k in keys[:3]))
        evidence_files = entry.get("evidence", []) or []
        if evidence_files:
            ev_bits.append(f"first hit: {str(evidence_files[0])[:80]}")
        yield _f("INFO", "payment_sdk",
                 f"{sdk} payment SDK detected",
                 "scan/payment_sdk.json",
                 "; ".join(ev_bits) or "namespace match")

        # Per-key severity calls.
        for k in keys:
            if "sk_live_" in k:
                yield _f("HIGH", "payment_sdk",
                         f"{sdk}: server key sk_live_... shipped in client binary",
                         "scan/payment_sdk.json",
                         f"{k[:14]}... — Stripe secret keys must never reach a mobile client; "
                         "rotate immediately and move to server-side")
            elif "_test_" in k:
                yield _f("HIGH", "payment_sdk",
                         f"{sdk}: TEST key shipped in production build",
                         "scan/payment_sdk.json",
                         f"{k[:14]}... — test-mode credentials cannot process real payments; "
                         "ship looks like a build-config bug")
            elif "_live_" in k:
                yield _f("MEDIUM", "payment_sdk",
                         f"{sdk}: production key in client",
                         "scan/payment_sdk.json",
                         f"{k[:14]}... — usually intentional for public-checkout keys; "
                         "verify it isn't a server-only credential")


def _from_s3_buckets(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.probe_dir / "s3_buckets.json")
    if not d:
        return
    for bucket, info in d.items():
        guessed = info.get("guessed", False)
        if info.get("listable"):
            yield _f("CRITICAL", "s3_buckets",
                     f"S3 bucket {bucket} allows UNAUTHENTICATED listing",
                     bucket,
                     "bucket policy / ACL grants list to public; attacker can enumerate every object")
        public_paths = info.get("publicly_readable_paths", []) or []
        if public_paths:
            yield _f("HIGH", "s3_buckets",
                     f"S3 bucket {bucket} serves common paths to unauth: {public_paths}",
                     bucket, ", ".join(public_paths))
        if guessed and info.get("exists") is False:
            yield _f("INFO", "s3_buckets",
                     f"brute-suffix S3 bucket {bucket} does not exist",
                     bucket,
                     "sibling-name guess (-staging/-backup/-uploads/-dev/-prod) — no bucket; "
                     "consider registering the name to prevent squatting")


def _from_asset_inspector(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "asset_inspector.json")
    if not d:
        return
    for entry in d.get("findings", []) or []:
        kind = entry.get("kind", "?")
        sev = entry.get("severity", "INFO")
        desc = entry.get("description", "")
        matches = entry.get("matches", []) or []
        count = entry.get("count", len(matches))
        loc = matches[0] if matches else "scan/asset_inspector.json"
        evidence = f"{count} match(es); first: {', '.join(matches[:3])}"
        yield _f(sev, "asset_inspector",
                 f"{kind}: {desc}",
                 loc, evidence[:200])


def _from_applinks(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "applinks.json")
    if not d:
        return
    findings = d.get("findings", []) or [] if isinstance(d, dict) else []
    for entry in findings:
        msg = entry.get("finding", "")
        if not msg:
            continue
        typ = entry.get("type")
        activity = entry.get("activity") or "?"
        if typ == "applink_assetlinks":
            host = entry.get("domain", "?")
            present = entry.get("assetlinks_present")
            pkg_declared = entry.get("package_declared")
            if present and pkg_declared is False:
                sev = "HIGH"
            elif not present:
                sev = "HIGH"
            elif present and pkg_declared is None and "malformed" in msg:
                sev = "HIGH"
            else:
                sev = "INFO"
            yield _f(sev, "applinks",
                     f"App Link verification issue on {host}",
                     f"AndroidManifest.xml::{activity}",
                     msg[:200])
        elif typ == "no_path_restriction":
            hosts = entry.get("hosts", []) or []
            schemes = entry.get("schemes", []) or []
            yield _f("MEDIUM", "applinks",
                     f"deeplink with no path restriction in {activity}",
                     "AndroidManifest.xml",
                     f"schemes={schemes} hosts={hosts}; entire host space is reachable")
        elif typ == "high_priority_intent_filter":
            p = entry.get("priority")
            yield _f("LOW", "applinks",
                     f"intent-filter priority={p} in {activity}",
                     "AndroidManifest.xml",
                     msg[:200])


def _from_build_leaks(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "build_leaks.json")
    if not d:
        return
    # CRITICAL: debug-signed APK
    ds = d.get("debug_signed")
    if ds:
        yield _f("CRITICAL", "build_leaks",
                 "APK signed by Android debug keystore (or with CN=Android Debug)",
                 ds.get("file", "scan/build_leaks.json"),
                 f"indicator={ds.get('indicator')}; this build was produced by the IDE 'Run' button, "
                 "not the release pipeline — it should never have shipped to users")

    # Placeholders: HIGH if in NSC/manifest (already covered by network_security for NSC,
    # so we filter to avoid double-counting), MEDIUM otherwise.
    nsc_emitted = False
    nsc_d = _read_json(ctx.scan_dir / "network_security.json") or {}
    nsc_path = (nsc_d.get("nsc_path") or "").replace("\\", "/") if isinstance(nsc_d, dict) else ""
    nsc_placeholder_count = len(nsc_d.get("gradle_placeholders", []) if isinstance(nsc_d, dict) else [])

    hi_phs: list[dict] = []
    med_phs: list[dict] = []
    for ph in d.get("unresolved_placeholders", []):
        f = (ph.get("file") or "").replace("\\", "/")
        # Dedupe vs network_security: skip the NSC file entirely if NSC scan already
        # reported placeholders for it.
        if nsc_path and f == nsc_path and nsc_placeholder_count > 0:
            continue
        if "network_security" in f or f.endswith("AndroidManifest.xml"):
            hi_phs.append(ph)
        else:
            med_phs.append(ph)
    if hi_phs:
        first = hi_phs[0]
        yield _f("HIGH", "build_leaks",
                 f"unresolved Gradle placeholder in security-critical config "
                 f"({len(hi_phs)} hit(s))",
                 first.get("file", "?"),
                 f"first: {first.get('value', '')}; build leaked a template token "
                 "into NSC / manifest")
    if med_phs:
        first = med_phs[0]
        uniq_files = sorted({p.get("file", "?") for p in med_phs})
        yield _f("MEDIUM", "build_leaks",
                 f"unresolved Gradle placeholder(s) in resources "
                 f"({len(med_phs)} hit(s) across {len(uniq_files)} file(s))",
                 first.get("file", "?"),
                 f"first: {first.get('value', '')} — Gradle templating "
                 "didn't substitute at build time (likely a feature-flag or env switch)")

    # Staging URLs: one MEDIUM per unique host (cap the rendered list at 10).
    urls = d.get("staging_urls", []) or []
    by_host: dict[str, list[dict]] = {}
    for u in urls:
        by_host.setdefault(u.get("host") or u.get("value", ""), []).append(u)
    if by_host:
        hosts = sorted(by_host.keys())
        first_host = hosts[0]
        first_hit = by_host[first_host][0]
        yield _f("MEDIUM", "build_leaks",
                 f"staging/dev/preprod URL leakage: {len(hosts)} unique host(s)",
                 first_hit.get("file", "?"),
                 f"hosts: {', '.join(hosts[:10])}"
                 + (" …" if len(hosts) > 10 else ""))

    # Debug flags
    flags = d.get("debug_flags", []) or []
    if flags:
        first = flags[0]
        names = sorted({f.get("constant", "?") for f in flags})
        yield _f("MEDIUM", "build_leaks",
                 f"hardcoded debug/logging flag(s) set to true ({len(flags)} hit(s))",
                 first.get("file", "?"),
                 f"constants: {', '.join(names[:6])}; first: {first.get('match', '')[:140]}")

    # test/dev/staging meta-data in manifest
    for entry in d.get("test_metadata", []) or []:
        yield _f("MEDIUM", "build_leaks",
                 f"test/dev meta-data in manifest: {entry.get('name', '?')}",
                 "AndroidManifest.xml",
                 f"value={entry.get('value', '')[:160]}")


def _from_privacy(ctx: RunContext) -> Iterator[dict]:
    """One finding per `kind` of PII / identifier read; demotes vendor SDK matches."""
    from clawditor.utils.vendor import split_vendor
    d = _read_json(ctx.scan_dir / "privacy.json")
    if not d:
        return
    by_kind = d.get("by_kind") or {}
    by_pattern = d.get("by_pattern") or {}
    # Each kind's severity comes from the first pattern that produced it
    # (all patterns mapped to a given kind share severity by construction).
    kind_sev: dict[str, str] = {}
    kind_desc: dict[str, str] = {}
    for items in by_pattern.values():
        for it in items:
            k = it.get("kind")
            if k and k not in kind_sev:
                kind_sev[k] = it.get("severity", "LOW")
                kind_desc[k] = it.get("description", k)
    for kind, items in sorted(by_kind.items()):
        if not items:
            continue
        sev = kind_sev.get(kind, "LOW")
        desc = kind_desc.get(kind, kind)
        app_items, vendor_items = split_vendor(items, file_key="file")
        if app_items:
            loc = app_items[0].get("file", "?")
            patterns = sorted({it.get("pattern", "?") for it in app_items})
            yield _f(sev, "privacy",
                     f"{kind}: {len(app_items)} app-owned read(s)",
                     loc,
                     f"{desc}; patterns: {', '.join(patterns[:4])}")
        if vendor_items:
            loc = vendor_items[0].get("file", "?")
            patterns = sorted({it.get("pattern", "?") for it in vendor_items})
            yield _f(_demote(sev), "privacy",
                     f"{kind}: {len(vendor_items)} vendor SDK read(s) (usually FP)",
                     loc,
                     f"{desc}; patterns: {', '.join(patterns[:4])}")


def _from_jwt_analyzer(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "jwt_analyzer.json")
    if not d:
        return
    for tok in d.get("tokens", []) or []:
        findings = tok.get("findings", []) or []
        file = tok.get("file", "?")
        iss = (tok.get("payload_claims") or {}).get("iss", "?")
        alg = (tok.get("header") or {}).get("alg", "?")
        issuer_class = tok.get("issuer_class", "unknown")
        is_expired = bool(tok.get("is_expired"))
        is_fixture = bool(tok.get("is_test_fixture"))

        if "alg_none" in findings:
            yield _f("CRITICAL", "jwt_analyzer",
                     "JWT with alg:none in binary (auth-bypass vector)",
                     file,
                     f"iss={iss} — signature verification disabled; an attacker can mint arbitrary tokens")
            continue  # alg:none subsumes everything else for this token

        if issuer_class == "production" and not is_expired:
            yield _f("HIGH", "jwt_analyzer",
                     f"live {iss} JWT shipped in binary (alg={alg})",
                     file,
                     f"production issuer with valid exp; treat as a leaked session token and revoke")
            continue

        if issuer_class == "production" and is_expired:
            yield _f("MEDIUM", "jwt_analyzer",
                     f"expired {iss} JWT shipped in binary (alg={alg})",
                     file,
                     "was a real session token at build time; concerning that it leaked into the APK")
            continue

        if is_fixture:
            yield _f("INFO", "jwt_analyzer",
                     f"test-fixture JWT (iss={iss})",
                     file,
                     "well-known SDK example / docs token; not exploitable")
            continue

        if issuer_class == "unknown" and not is_expired and "malformed" not in findings:
            yield _f("LOW", "jwt_analyzer",
                     f"unknown-issuer JWT with valid expiry (iss={iss}, alg={alg})",
                     file,
                     "non-standard issuer; worth a manual look")


def _f(severity: str, category: str, title: str, location: str, evidence: str) -> dict:
    return {"severity": severity, "category": category, "title": title,
            "location": location, "evidence": evidence}
