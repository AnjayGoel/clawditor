"""Per-run MANIFEST.md — the entry point for any consumer (human or agent).

Lists every artifact, what it is for, and which CLI / grep / read commands are
useful for digging into specific finding categories. The goal is that a fresh
agent dropped into a run directory can navigate without prior knowledge.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from clawditor.config import RunContext
from clawditor.report.findings import SEVERITY_ORDER


def run(ctx: RunContext, findings: list[dict]) -> None:
    counts = Counter(f["severity"] for f in findings)
    categories = Counter(f["category"] for f in findings)
    meta = json.loads((ctx.out_dir / "run.json").read_text())
    target = meta.get("package") or Path(meta.get("apk_input") or "?").name

    text = f"""# Run manifest — {target}

This directory contains the full output of one `clawditor` pipeline run. Start here.

## What this run found

- Started: `{meta['started_at']}`
- Flags: `{meta['flags']}`
- Findings by severity: {_dict_inline(counts, SEVERITY_ORDER)}
- Findings by category: {_dict_inline(categories)}

**Primary report** → `reports/SUMMARY.md`
**Ranked findings table** → `reports/findings.md`
**Structured findings** → `reports/findings.json`
**Next-action checklist** → `reports/next-steps.md`

## File layout

```
{target}/
├── run.json                   # this run's input flags + metadata
├── MANIFEST.md                # ← you are here
├── apk/                       # raw + universal APKs
│   └── universal.apk
├── decompiled/
│   ├── jadx/sources/          # Java source (only without --quick/--no-jadx)
│   ├── smali/                 # APKEditor smali + decoded AndroidManifest + resources
│   ├── hermes/                # decompiled.js + disasm.hasm (RN apps only)
│   └── native/                # .so files + their strings dump
├── scan/                      # passive scan outputs (no network)
│   ├── stack.json             # detected cross-platform framework signals
│   ├── manifest.json          # parsed AndroidManifest analysis
│   ├── secrets.json           # custom regex sweep
│   ├── apkleaks.json          # apkleaks results
│   ├── trufflehog.json        # trufflehog results
│   └── code_patterns.json     # WebView misconfig, crypto, Firestore use
├── probe/                     # active-probe outputs (network out)
│   ├── google_keys.json       # restriction matrix per AIzaSy key
│   ├── firebase_rtdb.json
│   ├── firebase_firestore.json
│   └── firebase_storage.json
└── reports/
    ├── SUMMARY.md             # executive summary (start here for humans)
    ├── findings.md            # ranked findings table
    ├── findings.json          # structured findings (start here for agents)
    ├── next-steps.md          # actionable, prioritized
    └── deep-dive-guide.md     # how to investigate each finding further
```

## Deep-dive entry points

If you're a human or an agent investigating a specific finding, **read `reports/deep-dive-guide.md`** — it maps each finding category to: which JSON to look at, which CLI subcommand to run, and which decompiled file to read.

Quick reference (most common):

| Question | Look at | Or run |
|---|---|---|
| Which Google keys are open? | `probe/google_keys.json` | `clawditor show {ctx.out_dir.name} --keys` |
| Are Firebase RTDB rules locked? | `probe/firebase_rtdb.json` | `clawditor probe-firebase <project>` |
| Any public storage paths? | `probe/firebase_storage.json` | `clawditor probe-storage <bucket>` |
| What's in the manifest? | `scan/manifest.json` | `cat decompiled/smali/AndroidManifest.xml` |
| Find a specific secret | `scan/secrets.json` | `grep -r <value> decompiled/` |
| Which WebView calls are dangerous? | `scan/code_patterns.json` | `grep -rn 'webview' decompiled/jadx/sources/` |

## Re-running probes

The active-probe phase can be re-run without redoing static analysis:

```bash
cd ~/Documents/auditor
uv run clawditor run --probe-only --out {ctx.out_dir}
```

## Notes

- All active probes use deliberately invalid params (no real SMS sent, no email delivered).
- A `VERIFIED` trufflehog finding (CRITICAL severity) was confirmed against the provider's API — those are real live secrets.
- The pipeline is deterministic given the same inputs; re-running on the same APK should produce the same scan results.
"""
    (ctx.out_dir / "MANIFEST.md").write_text(text)


def _dict_inline(d: dict, order=None) -> str:
    items = []
    if order:
        for k in order:
            if d.get(k):
                items.append(f"`{k}`={d[k]}")
    else:
        for k, v in sorted(d.items(), key=lambda x: -x[1]):
            items.append(f"`{k}`={v}")
    return " ".join(items) or "_none_"
