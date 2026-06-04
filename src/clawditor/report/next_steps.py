"""Generate reports/next-steps.md — prioritized action checklist."""
from __future__ import annotations

from clawditor.config import RunContext


SEVERITY_PRI = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def run(ctx: RunContext, findings: list[dict]) -> None:
    items = sorted(findings, key=lambda f: SEVERITY_PRI[f["severity"]])
    body = ["# Next steps", "", "Prioritized action checklist for this audit. Tick off as you go.", ""]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        fs = [f for f in items if f["severity"] == sev]
        if not fs:
            continue
        body += [f"## {sev}", ""]
        for f in fs:
            body += [f"- [ ] **[{f['category']}]** {f['title']}"]
            body += [f"  - location: `{f['location']}`"]
            body += [f"  - evidence: `{f['evidence'][:200]}`"]
            for hint in _action_hints(f):
                body += [f"  - **do**: {hint}"]
        body += [""]
    if not [f for f in items if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]:
        body += ["No CRITICAL/HIGH/MEDIUM findings — but verify the active probes ran (check `probe/` directory exists)."]
    (ctx.reports_dir / "next-steps.md").write_text("\n".join(body) + "\n")


def _action_hints(f: dict) -> list[str]:
    t = f["title"].lower()
    cat = f["category"]
    hints = []
    if "leaked" in t and cat == "google_key":
        hints += [
            "rotate the key today in GCP Console",
            "add Android package + SHA-1 restriction to the replacement key",
            "add API restriction list (only the APIs the app actually needs)",
            "audit GCP billing for the affected project over the last 90 days",
        ]
    elif "sendverif" in t.lower() or "sms pumping" in t.lower():
        hints += [
            "disable Firebase Phone Auth in the project if not used",
            "if used, restrict allowed countries to your real user geo",
            "set up billing alerts on Firebase Auth SMS spend",
            "enable Firebase App Check with Play Integrity",
        ]
    elif "createauthuri" in t.lower() or "user enumeration" in t.lower():
        hints += [
            "enable Firebase App Check; that endpoint stops working from non-app contexts",
            "consider rate-limiting createAuthUri at the application layer (Cloud Functions wrapper)",
        ]
    elif "android package restriction" in t.lower():
        hints += [
            "add the production package name + SHA-1 to the key in GCP Console",
            "for the staging build, use a different key with the staging SHA-1",
        ]
    elif "rtdb allows unauthenticated" in t.lower():
        hints += [
            "edit database.rules.json in Firebase Console — change to `auth.uid != null` or stricter",
            "deploy with `firebase deploy --only database`",
        ]
    elif "firestore" in t.lower() and "list" in t.lower():
        hints += [
            "edit firestore.rules — require an authenticated user AND a filter (e.g. `where uid == request.auth.uid`)",
            "deploy with `firebase deploy --only firestore:rules`",
        ]
    elif "unauthenticated listing" in t.lower():
        hints += [
            "edit storage.rules — remove `allow list` from the root match",
            "rules_version=\"2\" is required to grant list; downgrade or scope to specific authenticated paths",
        ]
    elif "cleartexttraffic" in t.lower():
        hints += [
            "add a network_security_config.xml that sets `cleartextTrafficPermitted=\"false\"` by default",
            "if specific endpoints need cleartext (rare), allowlist them by domain in the NSC",
        ]
    elif "allowbackup" in t.lower():
        hints += [
            "set android:allowBackup=\"false\" in <application>",
            "or add data_extraction_rules.xml + full_backup_content.xml excluding every store with sensitive data",
        ]
    elif "debuggable" in t.lower():
        hints += [
            "set android:debuggable=\"false\" (or remove the attr — defaults to false from manifest merger)",
            "verify CI doesn't override this for release builds",
        ]
    elif "webview" in t.lower() and "universal" in t.lower():
        hints += [
            "remove setAllowUniversalAccessFromFileURLs(true); rare app actually needs it",
            "audit every code path that builds the URL passed to this WebView — if any of them come from intent extras or server config, raise severity to CRITICAL",
        ]
    elif "exported" in t.lower():
        hints += [
            "set android:exported=\"false\" unless the component is intentionally public",
            "if it must be exported, add a signature-level permission",
        ]
    elif "rsa/ecb/pkcs1" in t.lower() or "pkcs1" in t.lower():
        hints += [
            "migrate to RSA-OAEP (RSA/ECB/OAEPWithSHA-256AndMGF1Padding)",
            "PKCS#1 v1.5 is vulnerable to Bleichenbacher-style padding oracle attacks",
        ]
    elif "verified live secret" in t.lower():
        hints += [
            "rotate the secret immediately",
            "audit logs for the credential's recent use",
            "investigate how it landed in the binary (CI leak, build config, etc.)",
        ]
    return hints
