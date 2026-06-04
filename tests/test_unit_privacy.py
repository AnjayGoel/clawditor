"""Unit tests for the privacy / PII identifier scanner."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.config import RunContext
from clawditor.report.findings import _from_privacy
from clawditor.scan import privacy


def _ctx(tmp_path: Path) -> RunContext:
    ctx = RunContext("p", None, tmp_path)
    ctx.ensure_dirs()
    return ctx


def _src(ctx: RunContext, rel: str, body: str) -> None:
    p = ctx.jadx_dir / "sources" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)


# ----- detection -----

def test_detects_imei_android_id_installed_apps_call_log(tmp_path: Path):
    ctx = _ctx(tmp_path)
    _src(ctx, "com/app/Tel.java",
         "public class Tel { String x = tm.getDeviceId(); }")
    _src(ctx, "com/app/Aid.java",
         "public class Aid { String x = Settings.Secure.ANDROID_ID; }")
    _src(ctx, "com/app/Pkg.java",
         "public class Pkg { void a() { pm.getInstalledApplications(0); } }")
    _src(ctx, "com/app/Cl.java",
         "public class Cl { Uri u = CallLog.Calls.CONTENT_URI; }")

    result = privacy.run(ctx)
    by_pattern = result["by_pattern"]
    by_kind = result["by_kind"]

    # Each pattern fired
    assert len(by_pattern["telephony_get_device_id"]) == 1
    assert len(by_pattern["android_id_read"]) == 1
    assert len(by_pattern["installed_apps_list"]) == 1
    assert len(by_pattern["call_log_read"]) == 1

    # Severities preserved
    assert by_pattern["telephony_get_device_id"][0]["severity"] == "HIGH"
    assert by_pattern["android_id_read"][0]["severity"] == "LOW"
    assert by_pattern["installed_apps_list"][0]["severity"] == "MEDIUM"
    assert by_pattern["call_log_read"][0]["severity"] == "HIGH"

    # Kinds aggregated correctly
    assert "imei_read" in by_kind
    assert "android_id_read" in by_kind
    assert "installed_apps_read" in by_kind
    assert "call_log_read" in by_kind

    # JSON written
    out = ctx.scan_dir / "privacy.json"
    assert out.exists()
    payload = json.loads(out.read_text())
    assert "by_kind" in payload and "by_pattern" in payload


def test_empty_tree_yields_no_findings(tmp_path: Path):
    ctx = _ctx(tmp_path)
    # No source files at all
    result = privacy.run(ctx)
    assert all(items == [] for items in result["by_pattern"].values())
    assert result["by_kind"] == {}


def test_unrelated_source_is_not_flagged(tmp_path: Path):
    ctx = _ctx(tmp_path)
    _src(ctx, "com/app/Safe.java",
         "public class Safe { void run() { System.out.println(\"hi\"); } }")
    result = privacy.run(ctx)
    assert all(items == [] for items in result["by_pattern"].values())
    assert result["by_kind"] == {}


def test_dedup_per_file_per_pattern(tmp_path: Path):
    """Multiple matches in one file produce one hit (file-level dedup)."""
    ctx = _ctx(tmp_path)
    _src(ctx, "com/app/Multi.java",
         "tm.getDeviceId(); tm.getDeviceId(); tm.getDeviceId();")
    result = privacy.run(ctx)
    assert len(result["by_pattern"]["telephony_get_device_id"]) == 1


# ----- findings collector -----

def test_from_privacy_emits_one_finding_per_kind(tmp_path: Path):
    ctx = _ctx(tmp_path)
    _src(ctx, "com/app/A.java", "tm.getDeviceId();")
    _src(ctx, "com/app/B.java", "pm.getInstalledApplications(0);")
    privacy.run(ctx)

    findings = list(_from_privacy(ctx))
    cats = {f["category"] for f in findings}
    assert cats == {"privacy"}
    titles = [f["title"] for f in findings]
    assert any("imei_read" in t for t in titles)
    assert any("installed_apps_read" in t for t in titles)

    # severity preserved from pattern table
    sev_by_kind = {f["title"].split(":")[0]: f["severity"] for f in findings}
    assert sev_by_kind["imei_read"] == "HIGH"
    assert sev_by_kind["installed_apps_read"] == "MEDIUM"


def test_from_privacy_demotes_vendor_matches(tmp_path: Path):
    """A hit inside a vendor SDK namespace (e.g. com/google/) is demoted by one tier."""
    ctx = _ctx(tmp_path)
    # Put the source under a known vendor prefix
    _src(ctx, "com/google/sdk/Tracker.java",
         "public class Tracker { String x = Settings.Secure.ANDROID_ID; }")
    privacy.run(ctx)

    findings = list(_from_privacy(ctx))
    # Should produce exactly one finding tagged as vendor and demoted
    assert len(findings) == 1
    f = findings[0]
    assert "vendor SDK" in f["title"]
    # LOW (base android_id_read) → INFO when demoted
    assert f["severity"] == "INFO"


def test_from_privacy_no_json_yields_nothing(tmp_path: Path):
    ctx = _ctx(tmp_path)
    # privacy.run not called — no privacy.json
    assert list(_from_privacy(ctx)) == []
