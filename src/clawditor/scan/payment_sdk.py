"""Payment SDK detection and configuration audit.

Payment SDKs are an especially high-value class because misconfigurations
directly expose money (chargeback fraud, replay attacks, IRSF via
Auth-as-payment apps). For each known SDK we detect presence (namespace OR
runtime marker), extract any keys/merchant IDs we can pull out of the
decompiled source, and record severity-relevant notes (sk_live_ shipped in
client, test key in prod build, etc.).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log


SDKS = [
    {"name": "Razorpay",
     "markers": ["com/razorpay/", "RazorpayCheckout"],
     "key_pattern": r"rzp_(?:live|test)_[A-Za-z0-9]{14,20}"},
    {"name": "Juspay HyperSDK",
     "markers": ["in/juspay/", "juspay.in"],
     "key_pattern": r'"clientId"\s*:\s*"([A-Za-z0-9_-]+)"'},
    {"name": "PhonePe",
     "markers": ["com/phonepe/intent/", "com.phonepe.app"],
     "key_pattern": None},
    {"name": "Paytm",
     "markers": ["com/paytm/pgsdk/"],
     "key_pattern": r'MID["\s:=]+"?([A-Za-z0-9]{10,30})"?'},
    {"name": "Stripe",
     "markers": ["com/stripe/android/", "pk_live_", "sk_live_"],
     "key_pattern": r"(?:pk|sk)_(?:live|test)_[A-Za-z0-9]{24,}"},
    {"name": "GooglePlayBilling",
     "markers": ["com/android/billingclient/", "com.android.vending.BILLING"],
     "key_pattern": None},
    {"name": "Cashfree",
     "markers": ["com/cashfree/pg/"],
     "key_pattern": None},
    {"name": "PayU",
     "markers": ["com/payumoney/", "com/payu/"],
     "key_pattern": None},
    {"name": "Braintree",
     "markers": ["com/braintreepayments/api/"],
     "key_pattern": None},
]


# File extensions we sweep for text markers / key patterns. Smali + jadx-sources
# + xml (manifest, strings.xml, network_security_config) + json (resources).
TEXT_EXTS = (".smali", ".java", ".kt", ".xml", ".json", ".js", ".properties")


def run(ctx: RunContext) -> dict:
    if not ctx.decompiled_dir.exists():
        result = {"findings": []}
        (ctx.scan_dir / "payment_sdk.json").write_text(json.dumps(result, indent=2))
        log.ok("payment_sdk: 0 SDK(s) detected (no decompiled dir)")
        return result

    # Build a single in-memory index of (path_str, lazy text) for the dirs we
    # care about. The naive approach in the spec rglobs *.smali for every
    # marker per SDK -> O(N_files * N_markers * 2). We instead enumerate once
    # and reuse: O(N_files) walk + O(N_files * N_markers) substring tests.
    path_index = _build_path_index(ctx.decompiled_dir)

    findings: list[dict] = []
    for sdk in SDKS:
        present, where = _detect_presence(sdk["markers"], path_index)
        if not present:
            continue

        entry: dict = {"sdk": sdk["name"], "detected": True,
                       "evidence": where[:3], "notes": []}

        if sdk["key_pattern"]:
            keys, key_locations = _extract_keys(sdk["key_pattern"], path_index)
            if keys:
                entry["keys"] = sorted(keys)
                entry["key_locations"] = key_locations[:5]
                for k in keys:
                    note = _key_note(sdk["name"], k)
                    if note:
                        entry["notes"].append(note)

        findings.append(entry)

    result = {"findings": findings}
    (ctx.scan_dir / "payment_sdk.json").write_text(json.dumps(result, indent=2))
    log.ok(f"payment_sdk: {len(findings)} SDK(s) detected")
    for f in findings:
        keys_n = len(f.get("keys", []))
        log.info(f"  {f['sdk']}: {keys_n} key(s) extracted")
    return result


def _build_path_index(root: Path) -> list[Path]:
    """One walk; return all text-y files under decompiled/.

    The decompiled tree typically contains jadx/sources/, smali/smali/,
    smali/root/ (resources), hermes/, native/. We restrict to text-ish
    extensions to avoid reading binary blobs.
    """
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in TEXT_EXTS:
            files.append(p)
    return files


def _detect_presence(markers: list[str], files: list[Path]) -> tuple[bool, list[str]]:
    """Return (present, list_of_evidence_paths_or_snippets).

    A marker ending in "/" is a namespace path fragment — matched against the
    file path (covers jadx Java + smali layouts). A marker without trailing
    slash is matched against either the path (cheap) or file contents.
    """
    evidence: list[str] = []
    namespace_markers = [m for m in markers if m.endswith("/")]
    literal_markers = [m for m in markers if not m.endswith("/")]

    # 1. Fast path: namespace check via path substring.
    for f in files:
        # normalize separators so on Windows-style paths "\" we still match.
        path_str = str(f).replace("\\", "/")
        for m in namespace_markers:
            if m in path_str:
                evidence.append(path_str)
                break
        if evidence:
            break

    # 2. Cheap second pass: literal markers in path (catches "RazorpayCheckout"
    # as a filename, "com.phonepe.app" appearing as a deeplink in
    # AndroidManifest.xml path, etc.) -- usually still requires file read but
    # path-match is a free win when applicable.
    if literal_markers:
        for f in files:
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for m in literal_markers:
                if m in text:
                    evidence.append(f"{f}:{m}")
                    break
            if len(evidence) >= 3:
                break

    return (len(evidence) > 0, evidence)


def _extract_keys(pattern: str, files: list[Path]) -> tuple[set[str], list[dict]]:
    rx = re.compile(pattern)
    keys: set[str] = set()
    locations: list[dict] = []
    for f in files:
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if val and val not in keys:
                keys.add(val)
                locations.append({"file": str(f), "value": val})
            if len(keys) >= 50:  # cap; an APK with 50+ distinct keys is broken
                return keys, locations
    return keys, locations


def _key_note(sdk_name: str, k: str) -> str | None:
    """Return a severity-tagged human-readable note for a key, or None."""
    if "sk_live_" in k:
        return (f"CRITICAL: Stripe SECRET key {k[:10]}... in client binary "
                "(should be server-side only)")
    if "sk_test_" in k:
        return (f"HIGH: Stripe test SECRET key {k[:10]}... in client binary "
                "(server-side credential shipped to clients)")
    if "_live_" in k:
        return (f"{sdk_name} production key {k[:10]}... in client "
                "(verify intentional / public-checkout key)")
    if "_test_" in k:
        return (f"TEST key {k[:10]}... shipping in production build "
                f"({sdk_name})")
    return None


if __name__ == "__main__":  # pragma: no cover
    import sys
    out = Path(sys.argv[1])
    ctx = RunContext(package=None, apk_input=None, out_dir=out)
    ctx.ensure_dirs()
    run(ctx)
