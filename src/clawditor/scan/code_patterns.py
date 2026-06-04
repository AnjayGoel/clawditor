"""Grep-based scan for known-dangerous code patterns."""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log
from clawditor.utils.shell import run as sh, which


PATTERNS = {
    # WebView misconfig
    "webview_universal_file_access": r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
    "webview_file_url_access": r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)",
    "webview_js_enabled": r"setJavaScriptEnabled\s*\(\s*true\s*\)",
    "webview_addjs_interface": r"addJavascriptInterface\s*\(",
    "webview_load_data_with_base_url": r'loadDataWithBaseURL\(\s*"http://',
    # WebView misconfig — deeper coverage
    # Mixed content — HTTPS page allowed to load HTTP subresources (cookie theft via MITM)
    "webview_mixed_content_always_allow": r"setMixedContentMode\s*\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)",
    "webview_mixed_content_compatibility": r"setMixedContentMode\s*\(\s*(?:WebSettings\.)?MIXED_CONTENT_COMPATIBILITY_MODE\s*\)",
    # Safe Browsing — protects from malicious URLs; if explicitly disabled, that's a finding
    "webview_safe_browsing_disabled": r"setSafeBrowsingEnabled\s*\(\s*false\s*\)",
    "webview_safe_browsing_manifest_disabled": r'<meta-data[^>]*android:name=["\']android\.webkit\.WebView\.EnableSafeBrowsing["\'][^>]*android:value=["\']false["\']',
    # Save password — autofill credentials leak (deprecated but still seen)
    "webview_save_password": r"setSavePassword\s*\(\s*true\s*\)",
    # Save form data — autofill leak
    "webview_save_form_data": r"setSaveFormData\s*\(\s*true\s*\)",
    # Geolocation enabled without permission flow
    "webview_geolocation_enabled": r"setGeolocationEnabled\s*\(\s*true\s*\)",
    # Pair with: onGeolocationPermissionsShowPrompt that always allows
    "webview_geolocation_always_allow": r"onGeolocationPermissionsShowPrompt[\s\S]{0,300}invoke\s*\([^)]*true\s*,\s*false",
    # Database storage — local SQL state for the WebView's origin (sensitive if loaded URL is attacker-controlled)
    "webview_database_enabled": r"setDatabaseEnabled\s*\(\s*true\s*\)",
    # Allow content access — content:// URIs accessible to WebView
    "webview_content_access": r"setAllowContentAccess\s*\(\s*true\s*\)",
    # Plugin enabled (deprecated; was used for Flash)
    "webview_plugin_enabled": r"setPluginState\s*\(\s*(?:WebSettings\.)?(?:PluginState\.)?ON\b",
    # User-agent override to a non-app-identifiable string (could be used to fingerprint-evade or impersonate)
    "webview_user_agent_set": r"setUserAgentString\s*\(",  # informational
    # WebView debugging enabled in production (allows attached Chrome dev tools)
    "webview_debugging_enabled": r"WebView\.setWebContentsDebuggingEnabled\s*\(\s*true\s*\)",
    # Cookie acceptance for third-party — privacy risk
    "webview_third_party_cookies": r"setAcceptThirdPartyCookies\s*\([^,]+,\s*true\s*\)",
    # TLS
    "trust_all_certificates": r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}",
    "hostname_verifier_accept_all": r"return\s+true;\s*\}\s*\}\s*//\s*HostnameVerifier",
    "hostname_verifier_lambda": r"HostnameVerifier[^{]*\{[^}]*return\s+true",
    # Crypto
    "rsa_ecb_pkcs1": r'"RSA/ECB/PKCS1Padding"',
    "aes_ecb": r'"AES/ECB/',
    "des": r'"DES"',
    "weak_random": r"\bnew\s+Random\s*\(\)",
    "zero_iv": r"\bnew\s+byte\[\s*16\s*\]\s*[;,)]",
    # SQL
    "raw_query_concat": r"rawQuery\s*\([^,]*\+",
    "exec_sql_concat": r"execSQL\s*\([^,]*\+",
    # Firebase usage signals
    "firestore_instance": r"FirebaseFirestore\.getInstance\(\)",
    "firestore_collection_literal": r'\.collection\s*\(\s*"([^"]+)"',
    "rtdb_get_reference": r'\.getReference\s*\(\s*"([^"]+)"',
    # Logging of sensitive
    "log_token": r'Log\.[a-z]\s*\([^,]+,\s*"[^"]*[Tt]oken',
    # IPC / Intent security
    "pending_intent_mutable": r"PendingIntent\.FLAG_MUTABLE",
    "pending_intent_no_immutable": r"PendingIntent\.getActivity\([^)]*\)(?![^;]*FLAG_IMMUTABLE)",
    "intent_serializable_extra": r"getSerializableExtra\(",
    "intent_parcelable_extra_no_type": r"getParcelableExtra\(\s*\"[^\"]+\"\s*\)",
    "implicit_intent_outside_app": r"setAction\s*\(\s*[\"']android\.intent\.action\.",
    "intent_redirection_pattern": r"startActivity\s*\(\s*\(Intent\)\s*get(?:Serializable|Parcelable)Extra",
    # Path traversal
    "file_from_intent_extra_no_canonicalize": r"new\s+File\([^)]*get(?:String|Extra)\(",
    "file_provider_authority_wildcard": r'<provider[^>]*authorities="[^"]*\*',
    # Insecure deserialization
    "objectinput_stream_external": r"new\s+ObjectInputStream\s*\([^)]*get(?:String|Extra|Bytes|Input)",
    "yaml_load_default": r"\bYaml\(\)\.load\(",
    # Tapjacking / overlay
    "missing_filter_touches": r"setFilterTouchesWhenObscured\s*\(\s*false\s*\)",
    # Screen capture / sensitive UI (presence is GOOD; report as INFO so absence is noticed)
    "flag_secure_missing_check": r"WindowManager\.LayoutParams\.FLAG_SECURE",
    # Clipboard
    "clipboard_write_sensitive": r"setPrimaryClip\s*\([^)]*(?:[Tt]oken|[Pp]assword|[Oo]tp|[Pp]in|[Cc]ard)",
    # Dangerous runtime
    "runtime_exec": r"Runtime\.getRuntime\(\)\.exec\(",
    "loadlibrary_dynamic": r"System\.loadLibrary\(\s*(?!\")",
    # Network
    "http_url_constant": r'"http://[^"]+"',
    "okhttp_no_cert_pinning": r"new\s+OkHttpClient(?:\.Builder)?\s*\(\)(?![^;]*certificatePinner)",
    "trust_manager_empty": r"public\s+void\s+checkServerTrusted\([^)]*\)\s*(?:throws\s+[A-Za-z.]+\s*)?\{\s*\}",
    "trust_manager_lambda": r"X509TrustManager\s*[^{]*\{\s*(?:[^}]*return\s+null|[^}]*return\s+new\s+X509Certificate\[\s*0\s*\])",
    "ssl_hostname_verify_all": r"ALLOW_ALL_HOSTNAME_VERIFIER|return\s+true;\s*\}\s*}\s*\)?;?(?:\s*//\s*[Hh]ostname)?",
    # XML / XXE
    "xml_parser_no_disallow_doctype": r"DocumentBuilderFactory\.newInstance\(\)(?![^;]*setFeature\([\"']http://apache\.org/xml/features/disallow-doctype-decl)",
    "sax_parser_no_secure": r"SAXParserFactory\.newInstance\(\)(?![^;]*setFeature\([\"']http://javax\.xml\.XMLConstants/feature/secure-processing)",
    # Logging
    "log_pii_pattern": r"Log\.[a-z]\s*\([^,]+,[^)]*(?:phone|email|otp|aadhaar|pan|password|token)",
    # Root detection bypass surface
    "root_check_simple_su": r'"/system/(?:bin|xbin)/su"',
    "frida_check_string": r'"frida-server"|"gum-js-loop"|"gmain"',
    # Accessibility abuse (could be keylogger)
    "accessibility_service_text_changed": r"TYPE_VIEW_TEXT_CHANGED",
    # Custom URL scheme handler (oauth callback hijack)
    "oauth_redirect_uri_localhost": r'redirect_uri=https?://(?:localhost|127\.0\.0\.1)',
    # Dynamic code loading
    "dex_class_loader": r"\bnew\s+DexClassLoader\s*\(",
    "path_class_loader_external": r"\bnew\s+PathClassLoader\s*\([^)]*get(?:Cache|External|Files)Dir",
    "dex_class_loader_from_extra": r"\bnew\s+DexClassLoader\s*\([^)]*getStringExtra",
    "dex_class_loader_from_url": r"\bnew\s+DexClassLoader\s*\([^)]*http",
    # Reflection from intent input — classic intent-redirection-to-RCE
    "class_forname_from_extra": r"\bClass\.forName\s*\([^)]*get(?:String|Char|Bundle)Extra",
    "method_invoke_from_extra": r"\.invoke\s*\([^)]*get(?:String|Bundle)Extra",
    "method_getmethod_from_extra": r"\.getMethod\s*\([^)]*get(?:String|Bundle)Extra",
    # Runtime.exec from intent input — direct RCE
    "runtime_exec_from_extra": r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*get(?:String|Bundle)Extra",
    "processbuilder_from_extra": r"\bnew\s+ProcessBuilder\s*\([^)]*get(?:String|Bundle)Extra",
    # Reflection generally (already partially covered, but specifically dangerous patterns)
    "reflection_field_set_accessible": r"\.setAccessible\s*\(\s*true\s*\)",
    "system_loadlibrary_from_extra": r"System\.load(?:Library)?\s*\([^)]*get(?:String|Bundle)Extra",
    # Eval-style — Mozilla rhino / JS in WebView from extras
    "webview_evaluate_javascript_from_extra": r"evaluateJavascript\s*\([^)]*get(?:String|Bundle)Extra",
    # Insecure file operations from intent
    "file_input_stream_from_extra": r"\bnew\s+FileInputStream\s*\([^)]*get(?:String|Bundle)Extra",
    "file_output_stream_from_extra": r"\bnew\s+FileOutputStream\s*\([^)]*get(?:String|Bundle)Extra",
    # Content resolver with attacker-controlled URI
    "content_resolver_from_extra": r"getContentResolver\(\)\.(?:openInputStream|openOutputStream|query|insert|update|delete)\s*\([^)]*get(?:Parcelable|String)Extra",
    # Insecure pref / MODE_WORLD_*
    "sharedprefs_world_readable": r"MODE_WORLD_READABLE\b",
    "sharedprefs_world_writeable": r"MODE_WORLD_WRITEABLE\b",
    "openfileoutput_world_readable": r"openFileOutput\s*\([^,]+,\s*[^,]*MODE_WORLD_READABLE",
    # Broadcast intent without permission (any app receives)
    "sendbroadcast_no_permission": r"sendBroadcast\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",  # one-arg form — no permission
    "register_receiver_no_permission": r"registerReceiver\s*\([^,]+,\s*[^,]+\)(?!\s*,)",  # two-arg form
}


SEARCH_DIRS = ("jadx/sources", "hermes")


def run(ctx: RunContext) -> dict:
    hits: dict[str, list[dict]] = {k: [] for k in PATTERNS}
    rg = which("rg")
    for sub in SEARCH_DIRS:
        base = ctx.decompiled_dir / sub
        if not base.exists():
            continue
        for name, pattern in PATTERNS.items():
            results = _grep(base, pattern, rg=rg)
            for line in results:
                hits[name].append(_parse_grep_line(line, base))
    out = ctx.scan_dir / "code_patterns.json"
    out.write_text(json.dumps(hits, indent=2))
    nonempty = {k: len(v) for k, v in hits.items() if v}
    if nonempty:
        log.ok(f"code patterns: {sum(nonempty.values())} hits across {len(nonempty)} pattern(s)")
        for k, n in sorted(nonempty.items(), key=lambda x: -x[1]):
            log.info(f"  {k}: {n}")
    return hits


def _grep(base: Path, pattern: str, rg: str | None) -> list[str]:
    """Search `base` for `pattern`; return up to 200 matching `file:line:content` lines."""
    try:
        if rg:
            res = sh([rg, "-Pn", "--no-heading", pattern, str(base)],
                     timeout=120, check=False)
        else:
            res = sh(["grep", "-rPnH", "--include=*.java", "--include=*.js",
                      pattern, str(base)],
                     timeout=180, check=False)
        if res.returncode > 1:  # grep/rg returns 1 for no matches
            return []
        return [l for l in res.stdout.splitlines() if l.strip()][:200]
    except Exception:
        # ShellError shouldn't fire with check=False, but guard against TimeoutExpired etc.
        return []


def _parse_grep_line(line: str, base: Path) -> dict:
    # rg / grep output: path:line:content
    parts = line.split(":", 2)
    if len(parts) == 3:
        return {"file": parts[0], "line": parts[1], "match": parts[2][:300]}
    return {"raw": line[:300]}
