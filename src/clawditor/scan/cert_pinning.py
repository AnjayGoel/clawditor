"""Detect certificate pinning (or its conspicuous absence) in decompiled code."""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log


# Each (label, regex) yields a "pinners_found" entry for every match.
PINNER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OkHttpCertificatePinner", re.compile(r"CertificatePinner\.Builder\s*\(")),
    ("OkHttpCertificatePinnerApply", re.compile(r"\.certificatePinner\s*\(")),
    ("TrustKit", re.compile(r"\b(?:com\.datatheorem\.android\.trustkit|TrustKit)\b")),
    ("CustomSslSocketFactory", re.compile(r"OkHttpClient\.Builder\(\)\s*\.\s*sslSocketFactory\s*\(")),
    ("Conscrypt", re.compile(r"Conscrypt\.newProvider\s*\(")),
]

OKHTTP_BUILDER_RX = re.compile(r"new\s+OkHttpClient\.Builder\s*\(\s*\)")
CERT_PINNER_APPLY_RX = re.compile(r"\.certificatePinner\s*\(")
TRUSTKIT_RX = re.compile(r"\b(?:com\.datatheorem\.android\.trustkit|TrustKit)\b")

# Sensitive package keyword markers
SENSITIVE_KEYWORDS = ("pay", "bank", "wallet", "auth")
BILLING_PERMS = ("com.android.vending.BILLING",)


def run(ctx: RunContext) -> dict:
    base = _pick_source_root(ctx)
    pinners_found: list[dict] = []
    okhttp_without_pinning: list[dict] = []
    trust_kit_used = False

    if base is None or not base.exists():
        log.warn("cert_pinning: no decompiled source tree available; skipping")
        out = {
            "pinners_found": [],
            "okhttp_without_pinning": [],
            "trust_kit_used": False,
            "summary": "no source",
        }
        (ctx.scan_dir / "cert_pinning.json").write_text(json.dumps(out, indent=2))
        return out

    src_exts = {".java", ".kt", ".smali"}
    for p in base.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in src_exts:
            continue
        try:
            txt = p.read_text(errors="ignore")
        except Exception:
            continue
        if len(txt) > 4 * 1024 * 1024:
            continue
        rel = _rel(p, ctx)

        # Per-file pinning state
        file_has_pinner = bool(CERT_PINNER_APPLY_RX.search(txt))
        if TRUSTKIT_RX.search(txt):
            trust_kit_used = True

        # Catalog all pinner-hint patterns with line numbers
        for label, rx in PINNER_PATTERNS:
            for m in rx.finditer(txt):
                line = txt.count("\n", 0, m.start()) + 1
                pinners_found.append({"file": rel, "line": line, "type": label})

        # Flag OkHttp builders that aren't paired with a pinner in the same file
        if not file_has_pinner:
            for m in OKHTTP_BUILDER_RX.finditer(txt):
                line = txt.count("\n", 0, m.start()) + 1
                okhttp_without_pinning.append({"file": rel, "line": line})

    sensitive = _is_sensitive(ctx)
    summary_bits = [
        f"{len(pinners_found)} pinner hit(s)",
        f"{len(okhttp_without_pinning)} OkHttpClient without pinning",
    ]
    if trust_kit_used:
        summary_bits.append("TrustKit referenced")
    if sensitive:
        summary_bits.append("sensitive-app heuristic matched")
    summary = "; ".join(summary_bits)

    out = {
        "pinners_found": pinners_found,
        "okhttp_without_pinning": okhttp_without_pinning,
        "trust_kit_used": trust_kit_used,
        "sensitive_app": sensitive,
        "summary": summary,
    }
    (ctx.scan_dir / "cert_pinning.json").write_text(json.dumps(out, indent=2))
    log.ok(f"cert_pinning: {summary}")
    return out


def _pick_source_root(ctx: RunContext) -> Path | None:
    jadx_sources = ctx.jadx_dir / "sources"
    if jadx_sources.exists():
        return jadx_sources
    if ctx.smali_dir.exists():
        return ctx.smali_dir
    return None


def _rel(p: Path, ctx: RunContext) -> str:
    try:
        return str(p.relative_to(ctx.decompiled_dir))
    except ValueError:
        return str(p)


def _is_sensitive(ctx: RunContext) -> bool:
    pkg = (ctx.package or "").lower()
    if any(k in pkg for k in SENSITIVE_KEYWORDS):
        return True
    mf_path = ctx.scan_dir / "manifest.json"
    if mf_path.exists():
        try:
            mf = json.loads(mf_path.read_text())
        except Exception:
            return False
        perms = mf.get("permissions_requested") or []
        if any(bp in perms for bp in BILLING_PERMS):
            return True
        mpkg = (mf.get("package") or "").lower()
        if any(k in mpkg for k in SENSITIVE_KEYWORDS):
            return True
    return False


if __name__ == "__main__":  # pragma: no cover
    import sys
    out = Path(sys.argv[1])
    ctx = RunContext(package=None, apk_input=None, out_dir=out)
    run(ctx)
