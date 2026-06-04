"""Unit tests for the findings collector."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.config import RunContext
from clawditor.report.findings import collect


def _write(ctx: RunContext, rel: str, data) -> None:
    p = ctx.out_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data))


def test_critical_from_verified_trufflehog(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    _write(ctx, "scan/trufflehog.json", [
        {"DetectorName": "AWSAccessKey", "Verified": True,
         "SourceMetadata": {"Data": {"Filesystem": {"file": "x"}}}, "Redacted": "AKIA…"},
    ])
    findings = collect(ctx)
    assert any(f["severity"] == "CRITICAL" and f["category"] == "trufflehog" for f in findings)


def test_high_when_leaked_google_key(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    _write(ctx, "probe/google_keys.json", {
        "AIzaSyEXAMPLE_FAKE_KEY_FOR_TESTS_ONLY99": {
            "services": [
                {"service": "Gemini", "verdict": "LEAKED", "detail": "leaked"},
                {"service": "Translate v2", "verdict": "SUCCESS", "detail": "ok"},
            ],
            "summary": {"LEAKED": 1, "SUCCESS": 1},
        }
    })
    findings = collect(ctx)
    sev = {f["severity"] for f in findings if f["category"] == "google_key"}
    assert "CRITICAL" in sev
    assert "HIGH" in sev


def test_medium_when_cleartext_no_nsc(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    _write(ctx, "scan/manifest.json", {
        "application": {"uses_cleartext_traffic": True, "network_security_config": "",
                        "allow_backup": False, "debuggable": False},
        "exported_components": {"activities": [], "services": [], "receivers": [], "providers": []},
        "deeplinks": [],
    })
    findings = collect(ctx)
    assert any(f["severity"] == "MEDIUM" and "cleartext" in f["title"].lower() for f in findings)
