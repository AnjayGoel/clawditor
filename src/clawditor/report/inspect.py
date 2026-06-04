"""Per-finding deep-inspection renderer (used by `clawditor inspect`)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax


CATEGORY_TO_JSON: dict[str, str] = {
    "secrets": "scan/secrets.json",
    "code": "scan/code_patterns.json",
    "manifest": "scan/manifest.json",
    "apkleaks": "scan/apkleaks.json",
    "trufflehog": "scan/trufflehog.json",
    "google_key": "probe/google_keys.json",
    "firebase_rtdb": "probe/firebase_rtdb.json",
    "firebase_firestore": "probe/firebase_firestore.json",
    "firebase_storage": "probe/firebase_storage.json",
    "ai_keys": "probe/ai_keys.json",
    "sdk_inventory": "scan/sdk_inventory.json",
    "network_security": "scan/network_security.json",
    "cert_pinning": "scan/cert_pinning.json",
    "intent_security": "scan/intent_security.json",
}

SEVERITY_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                  "LOW": "cyan", "INFO": "dim"}

_LOC_RE = re.compile(r"^(.+?):(\d+)$")
_AIZA_RE = re.compile(r"AIzaSy[A-Za-z0-9_-]{33}")
_RTDB_RE = re.compile(r"https://([a-z0-9-]+?)(?:-default-rtdb)?\.firebaseio\.com")
_LANG_BY_EXT = {".java": "java", ".kt": "kotlin", ".xml": "xml",
                ".js": "javascript", ".jsx": "javascript", ".json": "json"}


# ─────────────── selection ───────────────

def select(findings: list[dict], *, finding: int | None, severity: str | None,
           category: str | None, grep: str | None, limit: int) -> list[dict]:
    """`--finding` short-circuits; otherwise AND-able filters with --limit cap."""
    if finding is not None:
        return [findings[finding]] if 0 <= finding < len(findings) else []
    needle = grep.lower() if grep else None
    sev = severity.upper() if severity else None
    out: list[dict] = []
    for f in findings:
        if sev and f.get("severity") != sev:
            continue
        if category and f.get("category") != category:
            continue
        if needle and needle not in (f.get("title", "") + " " + f.get("evidence", "")).lower():
            continue
        out.append(f)
        if len(out) >= limit:
            break
    return out


# ─────────────── source JSON record + file context + hints ───────────────

def find_source_record(run_dir: Path, finding: dict) -> tuple[str | None, Any]:
    """(relative path, matched dict-keyed sub-record OR full doc OR None)."""
    rel = CATEGORY_TO_JSON.get(finding.get("category", ""))
    if not rel:
        return None, None
    p = run_dir / rel
    if not p.exists():
        return rel, None
    try:
        data = json.loads(p.read_text())
    except Exception:
        return rel, None
    title, ev, loc = (finding.get("title", ""), finding.get("evidence", ""),
                      finding.get("location", ""))
    if isinstance(data, dict):
        for k, v in data.items():
            if k and (k in loc or k in title or k in ev):
                return rel, {k: v}
    return rel, data


def source_context(run_dir: Path, location: str, window: int = 10) -> dict | None:
    """If location is `path:lineN`, return ±window line slice. Else None."""
    m = _LOC_RE.match(location.strip())
    if not m:
        return None
    rel_path = m.group(1)
    try:
        line = int(m.group(2))
    except ValueError:
        return None
    fp = run_dir / "decompiled" / rel_path
    if not fp.is_file():
        return None
    try:
        text = fp.read_text(errors="ignore")
    except Exception:
        return None
    lines = text.splitlines()
    start = max(0, line - 1 - window)
    end = min(len(lines), line - 1 + window + 1)
    return {
        "path": str(fp), "rel_path": rel_path, "line": line,
        "start_line": start + 1,
        "snippet": "\n".join(lines[start:end]),
        "lines": [{"n": start + 1 + i, "code": l} for i, l in enumerate(lines[start:end])],
    }


def next_steps_for(run_dir: Path, finding: dict) -> list[str]:
    """Pull `**do**:` lines under the matching `- [ ]` block in next-steps.md."""
    p = run_dir / "reports" / "next-steps.md"
    title = finding.get("title", "")
    if not p.exists() or not title:
        return []
    try:
        raw = p.read_text()
    except Exception:
        return []
    hints, inside = [], False
    for ln in raw.splitlines():
        if ln.startswith("- [ ]"):
            inside = title in ln
            continue
        if not inside:
            continue
        s = ln.strip()
        if not s:
            inside = False
            continue
        if s.startswith("- **do**:"):
            hints.append(s[len("- **do**:"):].strip())
    return hints


def related_commands(finding: dict, source_record: Any) -> list[str]:
    cat = finding.get("category", "")
    cmds: list[str] = []
    if cat == "google_key":
        # Truncated title can't be used to rebuild the key; prefer the JSON record key.
        key = None
        if isinstance(source_record, dict):
            for k in source_record:
                if _AIZA_RE.fullmatch(k):
                    key = k
                    break
        if not key:
            m = _AIZA_RE.search(finding.get("evidence", "") + " " + finding.get("title", ""))
            key = m.group(0) if m else None
        if key:
            cmds.append(f"clawditor probe-key {key}")
    elif cat.startswith("firebase_"):
        loc = finding.get("location", "")
        if cat == "firebase_firestore":
            cmds.append(f"clawditor probe-firebase {loc}")
        elif cat == "firebase_rtdb":
            m = _RTDB_RE.search(loc)
            if m:
                cmds.append(f"clawditor probe-firebase {m.group(1)}")
        elif cat == "firebase_storage":
            cmds.append(f"clawditor probe-storage {loc}")
    elif cat == "secrets":
        t = finding.get("title", "").lower()
        if "openai" in t or "anthropic" in t:
            cmds.append("# verify manually: curl https://api.openai.com/v1/models "
                        "-H 'Authorization: Bearer <key>'")
    return cmds


# ─────────────── rendering ───────────────

def render_rich(console: Console, run_dir: Path, finding: dict) -> None:
    sev = finding.get("severity", "INFO")
    color = SEVERITY_COLOR.get(sev, "white")
    console.print(Panel(
        f"[{color}]{sev}[/]  [bold]{finding.get('category', '?')}[/]  "
        f"{finding.get('title', '?')}\n[dim]location:[/] {finding.get('location', '?')}",
        border_style=color,
    ))
    console.print("\n[bold]Evidence[/]")
    console.print(Panel(finding.get("evidence", "") or "_no evidence_", border_style="white"))

    rel, record = find_source_record(run_dir, finding)
    if rel:
        console.print(f"\n[bold]Source record[/] [dim]({rel})[/]")
        if record is None:
            console.print(Panel(f"[dim]file missing or unreadable: {rel}[/]"))
        else:
            console.print(Syntax(json.dumps(record, indent=2)[:4000],
                                 "json", theme="monokai", word_wrap=True))

    cb = source_context(run_dir, finding.get("location", ""))
    if cb:
        console.print(f"\n[bold]Source context[/] [dim]{cb['rel_path']}:{cb['line']}[/]")
        ext = "." + cb["rel_path"].rsplit(".", 1)[-1] if "." in cb["rel_path"] else ""
        console.print(Syntax(cb["snippet"], _LANG_BY_EXT.get(ext, "text"),
                             theme="monokai", line_numbers=True,
                             start_line=cb["start_line"], highlight_lines={cb["line"]}))

    hints = next_steps_for(run_dir, finding)
    if hints:
        console.print("\n[bold]Suggested next steps[/]")
        for h in hints:
            console.print(f"  - {h}")
    else:
        skill = _skill_for(finding)
        if skill:
            console.print(f"\n[bold]Suggested next steps[/]\n  - see Claude skill: [cyan]{skill}[/]")

    cmds = related_commands(finding, record)
    if cmds:
        console.print("\n[bold]Related commands[/]")
        for c in cmds:
            console.print(f"  $ {c}")


def render_json(run_dir: Path, finding: dict) -> dict:
    rel, record = find_source_record(run_dir, finding)
    cb = source_context(run_dir, finding.get("location", ""))
    return {
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "title": finding.get("title"),
        "location": finding.get("location"),
        "evidence": finding.get("evidence"),
        "source_record_path": rel,
        "source_record": record,
        "source_context": ({"path": cb["path"], "line": cb["line"], "lines": cb["lines"]}
                           if cb else None),
        "next_steps": next_steps_for(run_dir, finding),
        "related_commands": related_commands(finding, record),
    }


def _skill_for(finding: dict) -> str | None:
    cat = finding.get("category", "")
    if cat == "secrets":
        return "deep-dive-secrets"
    if cat in ("google_key", "ai_keys"):
        return "deep-dive-api-keys"
    if cat.startswith("firebase_"):
        return "deep-dive-firebase"
    if cat == "code" and "webview" in finding.get("title", "").lower():
        return "deep-dive-webview"
    if finding.get("severity") in ("CRITICAL", "HIGH"):
        return "understand-findings"
    return None
