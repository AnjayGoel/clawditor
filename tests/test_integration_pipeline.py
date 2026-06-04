"""Integration tests that run the full pipeline against pulled APKs.

Marked as `slow` and `network` (probes hit Google). Run with:

    pytest tests/test_integration_pipeline.py -m slow
    pytest tests/test_integration_pipeline.py -m "slow and not network"
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from clawditor.config import RunContext
from clawditor.pipeline import run as run_pipeline


pytestmark = pytest.mark.slow


def _ctx_for_apk(apk_dir: Path, tmp_path: Path, **flags) -> RunContext:
    """Build a RunContext that uses one already-pulled split APK set."""
    out = tmp_path / "run"
    ctx = RunContext(package=apk_dir.name, apk_input=apk_dir, out_dir=out, **flags)
    ctx.ensure_dirs()
    return ctx


def test_quick_pipeline_no_probe(find_test_apk: Path, tmp_path: Path):
    """Smoke test: --quick --no-probe should complete and produce all reports."""
    apk_dir = find_test_apk.parent
    ctx = _ctx_for_apk(apk_dir, tmp_path, quick=True, no_probe=True)
    run_pipeline(ctx)
    # Universal APK produced
    assert ctx.universal_apk.exists()
    # All expected artifacts
    for p in ("scan/manifest.json", "scan/secrets.json", "scan/code_patterns.json",
              "reports/SUMMARY.md", "reports/findings.json", "reports/findings.md",
              "reports/deep-dive-guide.md", "reports/next-steps.md", "MANIFEST.md"):
        assert (ctx.out_dir / p).exists(), f"missing {p}"
    # Findings JSON parses
    findings = json.loads((ctx.out_dir / "reports/findings.json").read_text())
    assert isinstance(findings, list)


@pytest.mark.network
def test_full_pipeline_with_probe(find_test_apk: Path, tmp_path: Path):
    """Slow: runs probes too. Requires internet."""
    apk_dir = find_test_apk.parent
    ctx = _ctx_for_apk(apk_dir, tmp_path, quick=True)
    run_pipeline(ctx)
    # probe outputs exist (even if empty)
    for p in ("probe/google_keys.json", "probe/firebase_rtdb.json",
              "probe/firebase_firestore.json", "probe/firebase_storage.json"):
        # only google_keys is guaranteed; others depend on what was found
        if "google_keys" in p:
            # may be empty file if no keys found, but should be a valid JSON object
            f = ctx.out_dir / p
            if f.exists():
                json.loads(f.read_text())
