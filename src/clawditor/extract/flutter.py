"""Flutter (Dart AOT) extraction.

Flutter compiles Dart to a native AOT snapshot in `lib/<abi>/libapp.so`.
Full decompilation requires Blutter or reFlutter (out of scope for the
static pipeline). What we do here:

1. Confirm libapp.so is present.
2. Dump strings (already done by `extract/native.py`, but we re-run with a
   tighter min-length to surface API endpoints and embedded constants).
3. Detect interesting strings (URLs, AIzaSy keys that bypassed the secrets
   scanner because they're in compressed Dart constants, package identifiers).
4. Write a `flutter.json` advisory file noting what was found and what is
   still out of reach.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log
from clawditor.utils.shell import which, run as sh


def run(ctx: RunContext) -> dict:
    libapp = _find_libapp(ctx)
    if not libapp:
        log.warn("flutter: libapp.so not found; skipping")
        return {}

    result: dict = {
        "libapp_path": str(libapp.relative_to(ctx.decompiled_dir)),
        "libapp_size": libapp.stat().st_size,
        "notes": [
            "Dart AOT snapshot detected; full decompilation requires Blutter / reFlutter.",
            "What follows is a strings-only triage. Anything sensitive in the Dart code "
            "will need dynamic analysis (mitmproxy + Frida) or a manual Blutter pass.",
        ],
    }

    # Re-dump strings with min length 8 to surface more URLs/keys
    text = _strings_dump(libapp)
    if not text:
        log.warn("flutter: strings dump failed; saving libapp.so for manual inspection")
        (ctx.scan_dir / "flutter.json").write_text(json.dumps(result, indent=2))
        return result

    # Endpoint extraction
    urls = sorted(set(re.findall(r"https?://[A-Za-z0-9.\-_/:?=&%~+#@!,]{6,256}", text)))
    api_hosts = sorted({_host(u) for u in urls if _host(u)})

    # AIzaSy keys hiding in compressed Dart constants
    aiza = sorted(set(re.findall(r"AIzaSy[A-Za-z0-9_-]{33}", text)))

    # JWT-shape strings (the regex is loose; just an inventory)
    jwts = sorted(set(re.findall(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", text)))

    # Package: prefixes (Dart) — useful for identifying which Dart packages are bundled
    packages = sorted(set(re.findall(r"\bpackage:[A-Za-z0-9_/]+\b", text)))[:200]

    result.update({
        "url_count": len(urls),
        "unique_hosts": api_hosts,
        "google_api_keys_in_dart": aiza,
        "jwt_candidates": jwts,
        "dart_packages": packages,
    })

    (ctx.scan_dir / "flutter.json").write_text(json.dumps(result, indent=2))
    log.ok(f"flutter: libapp.so ({result['libapp_size']//1024} KiB), "
           f"{len(api_hosts)} unique hosts, {len(aiza)} AIzaSy keys")
    return result


def _find_libapp(ctx: RunContext) -> Path | None:
    for so in ctx.native_dir.rglob("libapp.so"):
        return so
    return None


def _strings_dump(so: Path) -> str | None:
    # Prefer strings with -n 8 for noise reduction
    if which("strings"):
        res = sh(["strings", "-n", "8", str(so)], check=False, timeout=180)
        if res.ok:
            return res.stdout
    # Python fallback
    try:
        data = so.read_bytes()
    except Exception:
        return None
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= 8:
                out.append(cur.decode("ascii", errors="replace"))
            cur = bytearray()
    return "\n".join(out)


def _host(url: str) -> str:
    m = re.match(r"https?://([A-Za-z0-9.\-_]+)", url)
    return m.group(1) if m else ""
