"""Shared pytest fixtures."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from clawditor.config import RunContext


@pytest.fixture
def tmp_run(tmp_path: Path) -> RunContext:
    """A RunContext rooted at a tmp dir with no real APK."""
    ctx = RunContext(
        package="test.pkg",
        apk_input=None,
        out_dir=tmp_path,
    )
    ctx.ensure_dirs()
    ctx.write_meta()
    return ctx


@pytest.fixture
def working_apks() -> list[Path]:
    """All pulled APKs under working/<pkg>/base.apk, if any."""
    root = Path(__file__).resolve().parents[1]
    pkgs = root / "working"
    if not pkgs.exists():
        return []
    return sorted(pkgs.glob("*/base.apk"))


@pytest.fixture
def find_test_apk(working_apks: list[Path]) -> Path:
    """One smallish APK to drive integration tests, or skip."""
    if not working_apks:
        pytest.skip("no APKs under working/; run ./scripts/pull-installed.sh first")
    # pick the smallest base.apk to keep tests fast
    return min(working_apks, key=lambda p: p.stat().st_size)
