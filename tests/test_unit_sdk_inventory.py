"""Unit tests for the SDK inventory scanner."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.config import RunContext
from clawditor.scan.sdk_inventory import run as run_sdk


def _write(p: Path, txt: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt)


def test_extracts_properties_and_version_txt(tmp_run: RunContext):
    root = tmp_run.smali_dir / "root"
    # META-INF style properties (Firebase, Play Services, AndroidX, plus a third-party)
    _write(root / "META-INF" / "firebase-analytics.properties", "client=21.5.0\nversion=21.5.0\n")
    _write(root / "META-INF" / "play-services-ads.properties", "version=22.6.0\n")
    _write(root / "META-INF" / "androidx-core.properties", "version=1.12.0\n")
    _write(root / "META-INF" / "kotlin-stdlib.properties", "version=1.9.0\n")
    # Root-level version txt file
    _write(root / "amplitude-version.txt", "8.6.0\n")
    # An empty / bogus properties file should be ignored, not crash
    _write(root / "META-INF" / "empty.properties", "")

    d = run_sdk(tmp_run)
    names = {s["name"]: s for s in d["sdks"]}
    assert "firebase-analytics" in names
    assert names["firebase-analytics"]["version"] == "21.5.0"
    assert "play-services-ads" in names
    assert names["play-services-ads"]["version"] == "22.6.0"
    assert "androidx-core" in names
    assert "kotlin-stdlib" in names
    assert "amplitude" in names
    assert names["amplitude"]["version"] == "8.6.0"

    cats = d["by_category"]
    assert any(s["name"] == "firebase-analytics" for s in cats["firebase"])
    assert any(s["name"] == "play-services-ads" for s in cats["google_play_services"])
    assert any(s["name"] == "androidx-core" for s in cats["androidx"])
    assert any(s["name"] in ("kotlin-stdlib", "amplitude") for s in cats["third_party"])

    # File on disk parses back
    out = json.loads((tmp_run.scan_dir / "sdk_inventory.json").read_text())
    assert out["sdks"] == d["sdks"]


def test_no_smali_dir_does_not_crash(tmp_run: RunContext):
    d = run_sdk(tmp_run)
    assert d["sdks"] == []
    assert (tmp_run.scan_dir / "sdk_inventory.json").exists()
