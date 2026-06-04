"""Diff two completed pipeline runs.

Comparison axes:
  - Findings: keyed by (category, title); reports shared / only-A / only-B / severity-changed.
  - SDK inventory: keyed by SDK name from scan/sdk_inventory.json:sdks[].name.
  - Endpoint hosts: harvested from scan/secrets.json (firebase_rtdb_url + firebase_storage_bucket).
    (No LinkFinder scanner exists in this pipeline yet; secrets.json is the closest
    structured source of "URLs / hosts the binary referenced".)
  - Google API keys: scan/secrets.json:google_api_key[].value (AIzaSy* strings).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.table import Table

# CRITICAL > HIGH > MEDIUM > LOW > INFO (higher rank == more severe).
SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


# ─────────────────── load helpers ───────────────────

def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _load_run(run_dir: Path) -> dict:
    """Slurp the per-run JSON we need (no decompiled tree access)."""
    meta = _read_json(run_dir / "run.json", {})
    target = meta.get("package") or (
        Path(meta.get("apk_input") or run_dir.name).name
    )
    findings = _read_json(run_dir / "reports" / "findings.json", [])
    sdk = _read_json(run_dir / "scan" / "sdk_inventory.json", {})
    secrets = _read_json(run_dir / "scan" / "secrets.json", {})
    return {
        "path": str(run_dir),
        "target": target,
        "findings": findings,
        "sdks": [s.get("name", "") for s in sdk.get("sdks", []) if s.get("name")],
        "endpoints": _harvest_endpoints(secrets),
        "ai_keys": _harvest_ai_keys(secrets),
    }


def _harvest_endpoints(secrets: dict) -> list[str]:
    """Pull hosts from secrets.json categories that look like URLs/buckets."""
    hosts: set[str] = set()
    for key in ("firebase_rtdb_url", "firebase_storage_bucket"):
        for entry in secrets.get(key, []) or []:
            v = (entry.get("value") or "").strip()
            if not v:
                continue
            # strip scheme to compare as bare host.
            for prefix in ("https://", "http://"):
                if v.startswith(prefix):
                    v = v[len(prefix):]
            v = v.split("/", 1)[0].rstrip("/")
            if v:
                hosts.add(v)
    return sorted(hosts)


def _harvest_ai_keys(secrets: dict) -> list[str]:
    """AIzaSy* keys from scan/secrets.json:google_api_key."""
    keys: set[str] = set()
    for entry in secrets.get("google_api_key", []) or []:
        v = (entry.get("value") or "").strip()
        if v:
            keys.add(v)
    return sorted(keys)


def _counts(findings: Iterable[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "INFO")
        out[s] = out.get(s, 0) + 1
    return out


# ─────────────────── core diff ───────────────────

def compute(run_a: Path, run_b: Path) -> dict:
    a = _load_run(run_a)
    b = _load_run(run_b)

    # Findings keyed by (category, title).
    a_map = {(f.get("category", ""), f.get("title", "")): f for f in a["findings"]}
    b_map = {(f.get("category", ""), f.get("title", "")): f for f in b["findings"]}

    shared, only_a, only_b, severity_changed = [], [], [], []
    for key, fa in a_map.items():
        if key in b_map:
            fb = b_map[key]
            row = {
                "category": key[0],
                "title": key[1],
                "severity_a": fa.get("severity"),
                "severity_b": fb.get("severity"),
            }
            shared.append(row)
            if fa.get("severity") != fb.get("severity"):
                severity_changed.append(row)
        else:
            only_a.append({
                "category": key[0], "title": key[1],
                "severity": fa.get("severity"),
            })
    for key, fb in b_map.items():
        if key not in a_map:
            only_b.append({
                "category": key[0], "title": key[1],
                "severity": fb.get("severity"),
            })

    def _sort_sev(rows, sev_field="severity"):
        rows.sort(key=lambda r: (-SEV_RANK.get(r.get(sev_field, "INFO"), 0),
                                 r.get("category", ""), r.get("title", "")))

    def _sort_shared(rows):
        rows.sort(key=lambda r: (
            -max(SEV_RANK.get(r["severity_a"], 0), SEV_RANK.get(r["severity_b"], 0)),
            r["category"], r["title"],
        ))

    _sort_shared(shared)
    _sort_shared(severity_changed)
    _sort_sev(only_a)
    _sort_sev(only_b)

    sa, sb = set(a["sdks"]), set(b["sdks"])
    ea, eb = set(a["endpoints"]), set(b["endpoints"])
    ka, kb = set(a["ai_keys"]), set(b["ai_keys"])

    return {
        "a": {"path": a["path"], "target": a["target"], "counts": _counts(a["findings"])},
        "b": {"path": b["path"], "target": b["target"], "counts": _counts(b["findings"])},
        "shared": shared,
        "only_a": only_a,
        "only_b": only_b,
        "severity_changed": severity_changed,
        "sdk_diff": {
            "added_in_b": sorted(sb - sa),
            "removed_from_a": sorted(sa - sb),
            "shared": sorted(sa & sb),
        },
        "endpoint_diff": {
            "added_in_b": sorted(eb - ea),
            "removed_from_a": sorted(ea - eb),
            "shared": sorted(ea & eb),
        },
        "ai_key_diff": {
            "added_in_b": sorted(kb - ka),
            "removed_from_a": sorted(ka - kb),
            "shared": sorted(ka & kb),
        },
    }


# ─────────────────── rich rendering ───────────────────

_SEV_STYLE = {
    "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
    "LOW": "cyan", "INFO": "dim",
}


def _sev_cell(sev: str | None) -> str:
    if not sev:
        return "[dim]—[/]"
    return f"[{_SEV_STYLE.get(sev, 'white')}]{sev}[/]"


def _counts_str(counts: dict[str, int]) -> str:
    if not counts:
        return "no findings"
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    return " ".join(
        f"[{_SEV_STYLE.get(s, 'white')}]{s[0]}:{counts[s]}[/]"
        for s in order if counts.get(s)
    )


def render_rich(
    console: Console,
    result: dict,
    *,
    only_shared: bool = False,
    only_a: bool = False,
    only_b: bool = False,
    by_category: bool = False,
) -> None:
    a, b = result["a"], result["b"]
    console.print(f"[bold]A[/] {a['target']}  ({a['path']})  {_counts_str(a['counts'])}")
    console.print(f"[bold]B[/] {b['target']}  ({b['path']})  {_counts_str(b['counts'])}")
    console.print()

    rows_shared = result["shared"]
    rows_only_a = result["only_a"]
    rows_only_b = result["only_b"]

    # Build the side-by-side table from the filter selection.
    if only_shared:
        table_rows = [(r["category"], r["title"], r["severity_a"], r["severity_b"]) for r in rows_shared]
    elif only_a:
        table_rows = [(r["category"], r["title"], r["severity"], None) for r in rows_only_a]
    elif only_b:
        table_rows = [(r["category"], r["title"], None, r["severity"]) for r in rows_only_b]
    else:
        table_rows = (
            [(r["category"], r["title"], r["severity_a"], r["severity_b"]) for r in rows_shared]
            + [(r["category"], r["title"], r["severity"], None) for r in rows_only_a]
            + [(r["category"], r["title"], None, r["severity"]) for r in rows_only_b]
        )
        table_rows.sort(key=lambda r: (
            -max(SEV_RANK.get(r[2], 0), SEV_RANK.get(r[3], 0)),
            r[0], r[1],
        ))

    if by_category:
        from collections import defaultdict
        groups: dict[str, list] = defaultdict(list)
        for cat, title, sa, sb in table_rows:
            groups[cat].append((title, sa, sb))
        for cat in sorted(groups):
            t = Table(title=f"[cyan]{cat}[/]", show_header=True, header_style="bold")
            t.add_column("Title"); t.add_column("A"); t.add_column("B")
            for title, sa, sb in groups[cat]:
                t.add_row(title, _sev_cell(sa), _sev_cell(sb))
            console.print(t)
    else:
        t = Table(title="Findings (A vs B)", show_header=True, header_style="bold")
        t.add_column("Category"); t.add_column("Title")
        t.add_column("A"); t.add_column("B")
        for cat, title, sa, sb in table_rows:
            t.add_row(cat, title, _sev_cell(sa), _sev_cell(sb))
        console.print(t)

    # Skip the lists if a single-segment filter is active (already shown above).
    if not (only_shared or only_a or only_b):
        if rows_only_a:
            console.print("\n[bold yellow]Only in A:[/]")
            for r in rows_only_a:
                console.print(f"  {_sev_cell(r['severity'])}  [{r['category']}] {r['title']}")
        if rows_only_b:
            console.print("\n[bold yellow]Only in B:[/]")
            for r in rows_only_b:
                console.print(f"  {_sev_cell(r['severity'])}  [{r['category']}] {r['title']}")
        if result["severity_changed"]:
            console.print("\n[bold magenta]Severity changed:[/]")
            for r in result["severity_changed"]:
                console.print(
                    f"  [{r['category']}] {r['title']}  "
                    f"{_sev_cell(r['severity_a'])} → {_sev_cell(r['severity_b'])}"
                )

    # SDK / endpoint / key diffs.
    _render_set_diff(console, "SDKs", result["sdk_diff"])
    _render_set_diff(console, "Endpoints / hosts", result["endpoint_diff"])
    _render_set_diff(console, "Google API keys (AIzaSy)", result["ai_key_diff"])


def _render_set_diff(console: Console, title: str, diff: dict) -> None:
    added = diff.get("added_in_b", [])
    removed = diff.get("removed_from_a", [])
    if not added and not removed:
        console.print(f"\n[dim]{title}: no change[/]")
        return
    console.print(f"\n[bold]{title}:[/]")
    if added:
        console.print("  [green]added in B:[/]")
        for x in added:
            console.print(f"    + {x}")
    if removed:
        console.print("  [red]removed from A (not in B):[/]")
        for x in removed:
            console.print(f"    - {x}")
