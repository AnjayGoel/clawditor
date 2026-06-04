"""Unit tests for `clawditor inspect`."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from clawditor.cli import app
from clawditor.report import inspect as ins


runner = CliRunner()


def _build_run(tmp: Path) -> Path:
    """Minimal run dir with two findings, a source file, and a next-steps.md."""
    (tmp / "scan").mkdir(parents=True)
    (tmp / "probe").mkdir()
    (tmp / "reports").mkdir()
    (tmp / "decompiled" / "jadx" / "sources" / "com" / "ex").mkdir(parents=True)

    # Source file the second finding will point at.
    src = tmp / "decompiled" / "jadx" / "sources" / "com" / "ex" / "Foo.java"
    src.write_text("\n".join(f"// line {i}" for i in range(1, 41)))

    # scan/secrets.json (source record for finding 0).
    (tmp / "scan" / "secrets.json").write_text(json.dumps({
        "openai_key": [
            {"file": "jadx/sources/com/ex/Foo.java", "line": "20",
             "value": "sk-abcdef1234567890XYZ"},
        ],
    }))

    # probe/google_keys.json (source record for finding 2 — google_key category).
    full_key = "AIzaSy" + "X" * 33
    (tmp / "probe" / "google_keys.json").write_text(json.dumps({
        full_key: {
            "services": [
                {"service": "Gemini", "verdict": "LEAKED", "detail": "leaked detector"},
            ],
            "summary": {"LEAKED": 1},
        }
    }))

    findings = [
        {"severity": "HIGH", "category": "secrets",
         "title": "openai_key: 1 unique app-owned value(s) in binary",
         "location": "jadx/sources/com/ex/Foo.java:20",
         "evidence": "sk-abcdef…"},
        {"severity": "LOW", "category": "manifest",
         "title": "deeplink with http(s) scheme",
         "location": "AndroidManifest.xml",
         "evidence": "overly broad deeplink"},
        {"severity": "CRITICAL", "category": "google_key",
         "title": f"key flagged as LEAKED by Google: {full_key[:10]}…{full_key[-4:]}",
         "location": "GCP",
         "evidence": f"detector fired on: Gemini"},
    ]
    (tmp / "reports" / "findings.json").write_text(json.dumps(findings))

    # next-steps.md with hints for finding 0.
    (tmp / "reports" / "next-steps.md").write_text(
        "# Next steps\n\n"
        "## HIGH\n\n"
        "- [ ] **[secrets]** openai_key: 1 unique app-owned value(s) in binary\n"
        "  - location: `jadx/sources/com/ex/Foo.java:20`\n"
        "  - evidence: `sk-abc…`\n"
        "  - **do**: rotate the key now\n"
        "  - **do**: audit usage for the last 90 days\n"
        "\n"
        "## LOW\n\n"
        "- [ ] **[manifest]** deeplink with http(s) scheme\n"
        "  - **do**: restrict the host\n"
    )
    return tmp


# ─────── selection helpers (unit) ───────


def test_select_by_index(tmp_path: Path):
    run = _build_run(tmp_path)
    findings = json.loads((run / "reports" / "findings.json").read_text())
    out = ins.select(findings, finding=1, severity=None, category=None, grep=None, limit=20)
    assert len(out) == 1 and out[0]["category"] == "manifest"


def test_select_by_severity_and_grep(tmp_path: Path):
    run = _build_run(tmp_path)
    findings = json.loads((run / "reports" / "findings.json").read_text())
    out = ins.select(findings, finding=None, severity="HIGH", category=None,
                     grep="openai", limit=20)
    assert len(out) == 1 and out[0]["category"] == "secrets"


def test_select_respects_limit(tmp_path: Path):
    run = _build_run(tmp_path)
    findings = json.loads((run / "reports" / "findings.json").read_text())
    out = ins.select(findings, finding=None, severity=None, category=None,
                     grep=None, limit=2)
    assert len(out) == 2


# ─────── helper unit tests ───────


def test_source_context_window(tmp_path: Path):
    run = _build_run(tmp_path)
    ctx = ins.source_context(run, "jadx/sources/com/ex/Foo.java:20", window=5)
    assert ctx is not None
    assert ctx["line"] == 20
    assert ctx["start_line"] == 15
    assert "// line 20" in ctx["snippet"]


def test_source_context_returns_none_for_non_path_location(tmp_path: Path):
    run = _build_run(tmp_path)
    assert ins.source_context(run, "GCP") is None
    assert ins.source_context(run, "AndroidManifest.xml") is None


def test_next_steps_extraction(tmp_path: Path):
    run = _build_run(tmp_path)
    findings = json.loads((run / "reports" / "findings.json").read_text())
    hints = ins.next_steps_for(run, findings[0])
    assert hints == ["rotate the key now", "audit usage for the last 90 days"]


def test_related_commands_for_google_key(tmp_path: Path):
    run = _build_run(tmp_path)
    findings = json.loads((run / "reports" / "findings.json").read_text())
    _, rec = ins.find_source_record(run, findings[2])
    cmds = ins.related_commands(findings[2], rec)
    assert any(c.startswith("clawditor probe-key AIzaSy") for c in cmds)
    # full key was reconstructed from source_record, not the truncated title
    assert all("…" not in c for c in cmds)


# ─────── CLI integration ───────


def test_cli_inspect_rich_mode(tmp_path: Path):
    run = _build_run(tmp_path)
    result = runner.invoke(app, ["inspect", str(run), "--finding", "0"])
    assert result.exit_code == 0, result.output
    assert "openai_key" in result.output
    assert "HIGH" in result.output
    assert "rotate the key now" in result.output


def test_cli_inspect_json_mode_is_parseable(tmp_path: Path):
    run = _build_run(tmp_path)
    result = runner.invoke(app, ["inspect", str(run), "--finding", "0", "--json"])
    assert result.exit_code == 0, result.output
    # rich.Console can wrap long JSON across lines for display, so reassemble.
    # Single finding → exactly one JSON object on stdout.
    obj = json.loads(result.output.strip())
    assert obj["category"] == "secrets"
    assert obj["next_steps"] == ["rotate the key now", "audit usage for the last 90 days"]
    assert obj["source_context"]["line"] == 20


def test_cli_inspect_severity_filter_multiple(tmp_path: Path):
    run = _build_run(tmp_path)
    result = runner.invoke(app, ["inspect", str(run), "--severity", "HIGH"])
    assert result.exit_code == 0, result.output
    assert "openai_key" in result.output


def test_cli_inspect_no_match(tmp_path: Path):
    run = _build_run(tmp_path)
    result = runner.invoke(app, ["inspect", str(run), "--category", "nonexistent"])
    assert result.exit_code == 0
    assert "no findings matched" in result.output
