"""Unit tests for `clawditor compare`."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from clawditor.cli import app
from clawditor.report import compare as cmp


runner = CliRunner()


def _build_run(
    base: Path,
    *,
    target: str,
    findings: list[dict],
    sdks: list[dict] | None = None,
    secrets: dict | None = None,
) -> Path:
    base.mkdir(parents=True)
    (base / "scan").mkdir()
    (base / "reports").mkdir()
    (base / "run.json").write_text(json.dumps({
        "package": target, "apk_input": None, "started_at": "t",
    }))
    (base / "reports" / "findings.json").write_text(json.dumps(findings))
    (base / "scan" / "sdk_inventory.json").write_text(json.dumps({"sdks": sdks or []}))
    (base / "scan" / "secrets.json").write_text(json.dumps(secrets or {}))
    return base


def _two_runs(tmp_path: Path) -> tuple[Path, Path]:
    """Two runs that diverge in every dimension the compare command checks."""
    a = _build_run(
        tmp_path / "run_a",
        target="com.foo",
        findings=[
            # Shared, same severity.
            {"severity": "HIGH", "category": "secrets",
             "title": "openai_key: leaked",
             "location": "Foo.java:1", "evidence": "sk-..."},
            # Shared, severity bumped in B.
            {"severity": "MEDIUM", "category": "manifest",
             "title": "deeplink with http(s) scheme",
             "location": "AndroidManifest.xml", "evidence": "..."},
            # Only in A.
            {"severity": "LOW", "category": "code_patterns",
             "title": "raw SQL via RawQuery",
             "location": "Foo.java:9", "evidence": "..."},
        ],
        sdks=[
            {"name": "okhttp", "version": "4.9.0"},
            {"name": "firebase-analytics", "version": "22.4.0"},
        ],
        secrets={
            "google_api_key": [
                {"value": "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "file": "x"},
                {"value": "AIzaSyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "file": "y"},
            ],
            "firebase_rtdb_url": [
                {"value": "https://shared.firebaseio.com", "file": "x"},
                {"value": "https://only-a.firebaseio.com", "file": "y"},
            ],
            "firebase_storage_bucket": [],
        },
    )
    b = _build_run(
        tmp_path / "run_b",
        target="com.foo",
        findings=[
            {"severity": "HIGH", "category": "secrets",
             "title": "openai_key: leaked",
             "location": "Foo.java:1", "evidence": "sk-..."},
            {"severity": "HIGH", "category": "manifest",
             "title": "deeplink with http(s) scheme",
             "location": "AndroidManifest.xml", "evidence": "..."},
            # Only in B.
            {"severity": "CRITICAL", "category": "google_key",
             "title": "key flagged as LEAKED by Google: AIzaSy...",
             "location": "GCP", "evidence": "leaked"},
        ],
        sdks=[
            {"name": "okhttp", "version": "4.12.0"},
            {"name": "play-services-ads", "version": "23.0.0"},
        ],
        secrets={
            "google_api_key": [
                {"value": "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "file": "x"},
                {"value": "AIzaSyCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "file": "y"},
            ],
            "firebase_rtdb_url": [
                {"value": "https://shared.firebaseio.com", "file": "x"},
                {"value": "https://only-b.firebaseio.com", "file": "y"},
            ],
        },
    )
    return a, b


# ─────── compute() unit tests ───────


def test_compute_classifies_findings(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    r = cmp.compute(a, b)
    titles_shared = {(x["category"], x["title"]) for x in r["shared"]}
    assert ("secrets", "openai_key: leaked") in titles_shared
    assert ("manifest", "deeplink with http(s) scheme") in titles_shared

    only_a = {(x["category"], x["title"]) for x in r["only_a"]}
    assert ("code_patterns", "raw SQL via RawQuery") in only_a
    assert ("secrets", "openai_key: leaked") not in only_a

    only_b = {(x["category"], x["title"]) for x in r["only_b"]}
    assert ("google_key", "key flagged as LEAKED by Google: AIzaSy...") in only_b

    changed = {(x["category"], x["title"]) for x in r["severity_changed"]}
    assert ("manifest", "deeplink with http(s) scheme") in changed
    # Same-severity shared should NOT appear in severity_changed.
    assert ("secrets", "openai_key: leaked") not in changed


def test_compute_sdk_diff(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    r = cmp.compute(a, b)
    assert "play-services-ads" in r["sdk_diff"]["added_in_b"]
    assert "firebase-analytics" in r["sdk_diff"]["removed_from_a"]
    assert "okhttp" in r["sdk_diff"]["shared"]


def test_compute_endpoint_and_key_diff(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    r = cmp.compute(a, b)
    assert "only-b.firebaseio.com" in r["endpoint_diff"]["added_in_b"]
    assert "only-a.firebaseio.com" in r["endpoint_diff"]["removed_from_a"]
    assert "shared.firebaseio.com" in r["endpoint_diff"]["shared"]

    assert "AIzaSyCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" in r["ai_key_diff"]["added_in_b"]
    assert "AIzaSyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" in r["ai_key_diff"]["removed_from_a"]


def test_compute_handles_missing_files(tmp_path: Path):
    a = tmp_path / "empty_a"
    b = tmp_path / "empty_b"
    a.mkdir(); b.mkdir()
    r = cmp.compute(a, b)
    assert r["shared"] == [] and r["only_a"] == [] and r["only_b"] == []
    assert r["sdk_diff"]["added_in_b"] == []


# ─────── CLI integration ───────


def test_cli_default_output_mentions_each_section(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    result = runner.invoke(app, ["compare", str(a), str(b)])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Only in A" in out
    assert "Only in B" in out
    assert "Severity changed" in out
    assert "raw SQL via RawQuery" in out
    assert "play-services-ads" in out
    assert "firebase-analytics" in out


def test_cli_shared_filter(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    result = runner.invoke(app, ["compare", str(a), str(b), "--shared"])
    assert result.exit_code == 0, result.output
    # Shared finding is rendered; only-a finding is NOT in the table view.
    assert "openai_key: leaked" in result.output
    # "Only in A:" section header is suppressed when --shared is set.
    assert "Only in A:" not in result.output


def test_cli_only_a_filter(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    result = runner.invoke(app, ["compare", str(a), str(b), "--only-a"])
    assert result.exit_code == 0, result.output
    assert "raw SQL via RawQuery" in result.output
    # The B-only finding's title shouldn't be in the rendered table.
    assert "key flagged as LEAKED by Google" not in result.output


def test_cli_mutually_exclusive_filters(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    result = runner.invoke(app, ["compare", str(a), str(b), "--shared", "--only-a"])
    assert result.exit_code != 0


def test_cli_json_mode_is_parseable(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    result = runner.invoke(app, ["compare", str(a), str(b), "--json"])
    assert result.exit_code == 0, result.output
    obj = json.loads(result.output)
    assert obj["a"]["target"] == "com.foo"
    assert obj["b"]["target"] == "com.foo"
    assert any(r["title"] == "raw SQL via RawQuery" for r in obj["only_a"])
    assert any(r["title"].startswith("key flagged as LEAKED") for r in obj["only_b"])
    assert "play-services-ads" in obj["sdk_diff"]["added_in_b"]


def test_cli_by_category_groups_findings(tmp_path: Path):
    a, b = _two_runs(tmp_path)
    result = runner.invoke(app, ["compare", str(a), str(b), "--by", "category"])
    assert result.exit_code == 0, result.output
    # Category names appear as section titles when grouped.
    assert "secrets" in result.output
    assert "manifest" in result.output
