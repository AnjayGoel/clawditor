"""Unit tests for stack detection."""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from clawditor.detect import stack
from clawditor.config import RunContext


def _fake_apk(path: Path, members: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for m in members:
            z.writestr(m, b"x")


def test_detects_native_only(tmp_path: Path):
    apk = tmp_path / "u.apk"
    _fake_apk(apk, ["AndroidManifest.xml", "classes.dex"])
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    (tmp_path / "apk").mkdir(exist_ok=True)
    import shutil; shutil.copy(apk, ctx.universal_apk)
    d = stack.run(ctx)
    assert d["native_android"]
    assert not d["react_native"]
    assert not d["flutter"]


def test_detects_react_native(tmp_path: Path):
    apk = tmp_path / "u.apk"
    _fake_apk(apk, [
        "AndroidManifest.xml", "classes.dex",
        "lib/arm64-v8a/libhermes.so",
        "assets/index.android.bundle",
    ])
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    import shutil; shutil.copy(apk, ctx.universal_apk)
    d = stack.run(ctx)
    assert d["react_native"]


def test_detects_compose_multiplatform(tmp_path: Path):
    apk = tmp_path / "u.apk"
    _fake_apk(apk, [
        "AndroidManifest.xml", "classes.dex",
        "assets/composeResources/myapp.generated.resources/drawable/x.xml",
    ])
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    import shutil; shutil.copy(apk, ctx.universal_apk)
    d = stack.run(ctx)
    assert d["compose_multiplatform"]


def test_detects_flutter(tmp_path: Path):
    apk = tmp_path / "u.apk"
    _fake_apk(apk, ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libflutter.so"])
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    import shutil; shutil.copy(apk, ctx.universal_apk)
    d = stack.run(ctx)
    assert d["flutter"]
