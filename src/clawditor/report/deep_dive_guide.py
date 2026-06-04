"""Generate reports/deep-dive-guide.md.

For each finding category in this run, lay out: what the finding means, which
JSON to read, which CLI subcommand to drill into, which decompiled file to grep,
and what the typical next step is. Designed for an agent landing in a run dir
cold; nothing should require prior context.
"""
from __future__ import annotations

from collections import defaultdict

from clawditor.config import RunContext


GUIDE: dict[str, dict] = {
    "manifest": {
        "what": "AndroidManifest.xml issues — exported components, cleartext traffic, backup rules, debug flags, broad deeplinks.",
        "json": "scan/manifest.json",
        "file": "decompiled/smali/AndroidManifest.xml",
        "next": [
            "Read the manifest directly to confirm context (decorators, sibling components).",
            "For exported components, grep the component class name in `decompiled/jadx/sources/` to find what intents it accepts.",
            "For deeplink filters, check whether the handler activity validates extras before using them.",
        ],
    },
    "secrets": {
        "what": "Custom regex hits for API keys, JWTs, OAuth client IDs, AWS/Stripe/Slack secrets, Firebase URLs.",
        "json": "scan/secrets.json",
        "next": [
            "Run `clawditor probe-key <key>` for each AIzaSy* value — confirms restrictions.",
            "Run `clawditor probe-firebase <project>` for each Firebase project derived from the buckets / RTDB URLs.",
            "For JWTs, decode header+payload with `cut -d. -f2 | base64 -d` to see whether they're test fixtures (typical) or real session tokens.",
        ],
    },
    "code": {
        "what": "Pattern-grep hits for dangerous WebView config, crypto misuse, SQL string concat, certificate validation bypasses.",
        "json": "scan/code_patterns.json",
        "next": [
            "Open the file:line in the hit — confirm the pattern is in app code (not vendor SDK).",
            "For WebView findings, trace where the activity loads URLs from (intent extras, server config) — that determines exploitability.",
            "For crypto findings (RSA/ECB/PKCS1, AES/ECB, weak Random), check what is being encrypted; symmetric crypto on session tokens is high-severity.",
        ],
    },
    "apkleaks": {
        "what": "apkleaks regex sweep — high volume, mixed signal. Useful for endpoint inventory and the few categories that are truly high-confidence.",
        "json": "scan/apkleaks.json",
        "next": [
            "Filter to `Google_API_Key`, `Firebase`, `AWS_Access_Key_ID`, `Slack_Webhook`, `JSON_Web_Token` — these are the high-signal categories.",
            "Ignore `Authorization_Basic` and `HackerOne_CTF_Flag` — almost always false positive.",
            "`LinkFinder` is endpoint inventory; pipe through `awk -F/ '{print $3}' | sort -u` for unique hosts.",
        ],
    },
    "trufflehog": {
        "what": "Trufflehog secrets — with provider verification. VERIFIED hits = live secrets.",
        "json": "scan/trufflehog.json",
        "next": [
            "VERIFIED hits (CRITICAL) need immediate rotation. Confirm by reading the file at the line, then notify the secret owner.",
            "Unverified hits may still be real; the provider just couldn't be reached (rate limit) or the detector lacks a verifier. Manually verify if the type is high-confidence (AWS, Stripe, etc.).",
        ],
    },
    "google_key": {
        "what": "Restriction matrix per AIzaSy* key — which services accept it, whether Android-package restriction is present.",
        "json": "probe/google_keys.json",
        "next": [
            "Re-probe a single key in detail: `uv run clawditor probe-key <AIzaSy...>` (prints the full matrix).",
            "If `LEAKED` or any `SUCCESS`: rotate the key, add Android package + SHA-1 restriction, add API restriction list.",
            "If `sendVerifyCode SMS REACHED_ERR` → SMS pumping vector; disable phone auth OR enforce App Check immediately.",
            "If `createAuthUri SUCCESS` → user enumeration via `registered: true/false`; same fix.",
        ],
    },
    "firebase_rtdb": {
        "what": "Realtime DB rule probe — unauthenticated and authenticated (anonymous) reads on common paths.",
        "json": "probe/firebase_rtdb.json",
        "next": [
            "If any path returned HTTP 200 unauthenticated → CRITICAL. Open the project's `database.rules.json` and tighten.",
            "If only the authenticated reads succeeded → rules are `auth != null`; tighten to per-doc owner checks.",
            "If everything returned 401/404 → rules are locked (or DB not provisioned). No action.",
        ],
    },
    "firebase_firestore": {
        "what": "Firestore rule probe — collection list, own-UID doc read, unfiltered structured query — with an anon-auth identity.",
        "json": "probe/firebase_firestore.json",
        "next": [
            "If `structured_query_users` returned `[{readTime}]` → rules permit unfiltered LIST. Tighten.",
            "If any collection returned a non-empty body → data is exposed to any anonymous user.",
            "If DB doesn't exist → safe by absence.",
        ],
    },
    "firebase_storage": {
        "what": "Storage bucket probe — listing API + 31 common file paths, unauthenticated.",
        "json": "probe/firebase_storage.json",
        "next": [
            "If `listing.http == 200` → bucket allows unauth listing. CRITICAL.",
            "If `publicly_readable_paths` is non-empty → those specific files are exposed.",
            "Mostly 404? → bucket exists but our path guesses missed; capture a real filename via dynamic analysis to confirm rule posture.",
        ],
    },
}


def run(ctx: RunContext, findings: list[dict]) -> None:
    cats = sorted(set(f["category"] for f in findings))
    body = [
        "# Deep-dive guide",
        "",
        "For each finding category that appeared in this run, here's how to investigate further.",
        "",
        "If you're an agent: start with the JSON file listed under each category. Then run the suggested CLI subcommand, or grep the suggested decompiled file.",
        "",
    ]
    for c in cats:
        info = GUIDE.get(c)
        if not info:
            continue
        n = sum(1 for f in findings if f["category"] == c)
        body += [f"## `{c}` — {n} finding(s)", "", info["what"], ""]
        body += [f"**Structured output**: `{info['json']}`", ""]
        if "file" in info:
            body += [f"**Source artifact**: `{info['file']}`", ""]
        body += ["**Next steps**:"]
        for step in info["next"]:
            body += [f"- {step}"]
        body += [""]
    if "google_key" in cats:
        body += [
            "## Re-running just the probes",
            "",
            "Probes are deterministic given the same scanned secrets. Re-run any single probe standalone:",
            "",
            "```bash",
            "uv run clawditor probe-key AIzaSy...        # full 36-service matrix for one key",
            "uv run clawditor probe-firebase <project>   # RTDB + Firestore + Storage for one project",
            "uv run clawditor probe-storage <bucket>     # 31-path enumeration for one bucket",
            "```",
            "",
        ]
    (ctx.reports_dir / "deep-dive-guide.md").write_text("\n".join(body))
