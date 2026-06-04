"""Run trufflehog filesystem mode across decompiled trees."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log
from clawditor.utils.shell import which, run as sh


def run(ctx: RunContext) -> dict:
    if not which("trufflehog"):
        log.warn("trufflehog not on PATH; skipping")
        return {}
    findings: list[dict] = []
    log.info("trufflehog: filesystem scan (verified + high-confidence unverified)")
    res = sh(
        ["trufflehog", "filesystem", str(ctx.decompiled_dir), "--json", "--no-update"],
        timeout=1800,
        check=False,
    )
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    out = ctx.scan_dir / "trufflehog.json"
    out.write_text(json.dumps(findings, indent=2))
    verified = sum(1 for f in findings if f.get("Verified"))
    log.ok(f"trufflehog: {len(findings)} hits ({verified} verified)")
    return {"count": len(findings), "verified": verified}
