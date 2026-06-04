"""Cross-reference manifest exported components with unsafe extra-consumption patterns in their source."""
from __future__ import annotations

import json
import re

from clawditor.config import RunContext
from clawditor.utils import logging as log


UNSAFE_EXTRA_PATTERNS = [
    (r"getStringExtra\([^)]+\)[^;]*\.startsWith\(\"http\"\)\s*\?", "URL scheme prepend"),
    (r"loadUrl\s*\([^)]*getStringExtra", "WebView loadUrl from extra"),
    (r"Uri\.parse\([^)]*getStringExtra", "Uri.parse from extra"),
    (r"startActivity\([^)]*\(Intent\)\s*get(?:Serializable|Parcelable)Extra", "Intent forwarding"),
    (r"new\s+File\s*\([^)]*getStringExtra", "File path from extra"),
]


def run(ctx: RunContext) -> dict:
    manifest_path = ctx.scan_dir / "manifest.json"
    if not manifest_path.exists():
        log.warn("intent_security: manifest.json not present; skipping")
        return {"findings": []}

    manifest_data = json.loads(manifest_path.read_text())
    exported: list[str] = []
    for _kind, items in manifest_data.get("exported_components", {}).items():
        for it in items:
            name = it.get("name")
            if name:
                exported.append(name)

    findings: list[dict] = []
    for cls in exported:
        # find the file — handle both fully-qualified ("com.x.Y") and dot-prefixed (".Y") names
        rel_path = cls.lstrip(".").replace(".", "/") + ".java"
        candidate = ctx.jadx_dir / "sources" / rel_path
        if not candidate.exists():
            continue
        try:
            text = candidate.read_text(errors="ignore")
        except Exception:
            continue
        for pattern, label in UNSAFE_EXTRA_PATTERNS:
            for m in re.finditer(pattern, text):
                findings.append({
                    "exported_class": cls,
                    "pattern": label,
                    "file": str(candidate.relative_to(ctx.decompiled_dir)),
                    "snippet": text[max(0, m.start() - 40):m.end() + 60][:200],
                })

    out = ctx.scan_dir / "intent_security.json"
    out.write_text(json.dumps(findings, indent=2))
    log.ok(f"intent_security: {len(findings)} suspicious extra consumption(s)")
    return {"findings": findings}
