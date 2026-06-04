"""Run apkleaks against the universal APK."""
from __future__ import annotations

import json
import shutil

from clawditor.config import RunContext
from clawditor.utils import logging as log
from clawditor.utils.shell import which, run as sh


def run(ctx: RunContext) -> dict:
    if not which("apkleaks"):
        log.warn("apkleaks not on PATH; skipping")
        return {}
    out_json = ctx.scan_dir / "apkleaks.json"
    log.info("apkleaks scanning (re-runs jadx internally, can be slow)…")
    res = sh(
        ["apkleaks", "-f", str(ctx.universal_apk), "-o", str(out_json), "--json"],
        timeout=900,
        check=False,
    )
    if not out_json.exists():
        log.warn(f"apkleaks did not produce output:\n{res.stderr[-400:]}")
        return {}
    data = json.loads(out_json.read_text())
    n = sum(len(r.get("matches", [])) for r in data.get("results", []))
    log.ok(f"apkleaks: {n} total matches across {len(data.get('results',[]))} categories")
    return data
