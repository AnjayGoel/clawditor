"""Write the executive markdown summary + findings.{md,json}."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from clawditor.config import RunContext
from clawditor.report.findings import SEVERITY_ORDER, collect
from clawditor.utils import logging as log


def run(ctx: RunContext) -> None:
    findings = collect(ctx)
    (ctx.reports_dir / "findings.json").write_text(json.dumps(findings, indent=2))
    _write_findings_md(ctx, findings)
    _write_summary(ctx, findings)
    # Additional consumer-facing artifacts
    from clawditor.report import manifest as mfst, deep_dive_guide, next_steps
    mfst.run(ctx, findings)
    deep_dive_guide.run(ctx, findings)
    next_steps.run(ctx, findings)
    sev_counts = Counter(f["severity"] for f in findings)
    log.ok("findings: " + " ".join(f"{s}:{sev_counts[s]}" for s in SEVERITY_ORDER if sev_counts[s]))


def _write_findings_md(ctx: RunContext, findings: list[dict]) -> None:
    p = ctx.reports_dir / "findings.md"
    rows = ["| Sev | Category | Title | Location | Evidence |", "|---|---|---|---|---|"]
    for f in findings:
        rows.append(
            f"| **{f['severity']}** | {f['category']} | {_esc(f['title'])} | "
            f"{_esc(f['location'])} | {_esc(f['evidence'][:200])} |"
        )
    p.write_text("# Findings\n\n" + "\n".join(rows) + "\n")


def _esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _write_summary(ctx: RunContext, findings: list[dict]) -> None:
    counts = Counter(f["severity"] for f in findings)
    meta = json.loads((ctx.out_dir / "run.json").read_text())
    stack = {}
    p = ctx.scan_dir / "stack.json"
    if p.exists():
        stack = json.loads(p.read_text())

    detected_stack = [k for k, v in stack.items() if v and k != "native_android"]
    stack_str = "native Android"
    if detected_stack:
        stack_str += " + " + ", ".join(detected_stack)

    findings_inline = " ".join(f"**{s}**: {counts[s]}" for s in SEVERITY_ORDER if counts[s]) or "none"
    body = [f"# Audit summary — {meta.get('package') or Path(meta.get('apk_input') or '?').name}",
            "",
            f"- Started: {meta['started_at']}",
            f"- Stack: {stack_str}",
            f"- Findings: {findings_inline}",
            "",
            "## Top findings",
            ""]
    for f in findings[:15]:
        body.append(f"- **{f['severity']}** [{f['category']}] {f['title']}")
        body.append(f"  - `{f['location']}` — {f['evidence'][:200]}")
    body += [
        "",
        "## Artifacts",
        "",
        f"- decompiled: `{ctx.decompiled_dir.relative_to(ctx.out_dir)}/`",
        f"- scan jsons: `{ctx.scan_dir.relative_to(ctx.out_dir)}/`",
        f"- probe jsons: `{ctx.probe_dir.relative_to(ctx.out_dir)}/`",
        f"- findings: `reports/findings.md` + `reports/findings.json`",
        "",
        "## Notes",
        "",
        "- Active probes run with deliberately invalid params to avoid real side effects.",
        "- A `BLOCKED_METHOD` / `API_DISABLED` verdict means the key was rejected at a layer LATER than Android-package check, i.e. the key still has no Android restriction.",
        "- Trufflehog `VERIFIED` findings (CRITICAL) confirmed the secret against the provider's API.",
    ]
    (ctx.reports_dir / "SUMMARY.md").write_text("\n".join(body) + "\n")
