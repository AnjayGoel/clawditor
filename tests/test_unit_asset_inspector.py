"""Unit tests for the asset_inspector scanner."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from clawditor.scan.asset_inspector import run as run_asset_inspector


def _build_apk(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)


def test_flags_known_suspicious_files(tmp_run):
    apk_path = tmp_run.universal_apk
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    _build_apk(apk_path, {
        ".env": b"SECRET=1",
        ".git/HEAD": b"ref: refs/heads/main",
        "id_rsa": b"-----BEGIN OPENSSH PRIVATE KEY-----",
        "src/main.js.map": b"{}",
        "assets/clean.json": b"{\"ok\": true}",
    })

    result = run_asset_inspector(tmp_run)
    kinds = {f["kind"] for f in result["findings"]}

    # All four suspicious classes flagged.
    assert "env_file" in kinds
    assert "git_directory" in kinds
    assert "ssh_private_key" in kinds
    assert "js_source_map" in kinds

    # Clean file isn't reported as a finding (no kind for assets/clean.json).
    all_matches: list[str] = []
    for f in result["findings"]:
        all_matches.extend(f["matches"])
    assert "assets/clean.json" not in all_matches

    # JSON sidecar written.
    out = json.loads((tmp_run.scan_dir / "asset_inspector.json").read_text())
    assert "findings" in out
    assert len(out["findings"]) == len(result["findings"])


def test_empty_apk_yields_no_findings(tmp_run):
    apk_path = tmp_run.universal_apk
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    _build_apk(apk_path, {})

    result = run_asset_inspector(tmp_run)
    assert result["findings"] == []

    out = json.loads((tmp_run.scan_dir / "asset_inspector.json").read_text())
    assert out["findings"] == []


def test_missing_apk_is_safe(tmp_run):
    # No APK file at all; should warn and return {} without raising.
    result = run_asset_inspector(tmp_run)
    assert result == {}
