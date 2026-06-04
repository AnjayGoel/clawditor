"""Acquire the APK. Source: connected ADB device OR local path."""
from __future__ import annotations

import shutil
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log
from clawditor.utils.paths import apkeditor_jar
from clawditor.utils.shell import require, run as sh


def run(ctx: RunContext) -> None:
    if ctx.apk_input:
        _from_local(ctx)
    elif ctx.package:
        _from_adb(ctx)
    else:
        raise RuntimeError("acquire: no package and no --apk")
    _merge_if_split(ctx)


def _from_local(ctx: RunContext) -> None:
    src = Path(ctx.apk_input).resolve()
    if src.is_dir():
        # User passed a dir of splits
        apks = sorted(src.glob("*.apk"))
        if not apks:
            raise RuntimeError(f"no .apk files in {src}")
        for p in apks:
            shutil.copy2(p, ctx.apk_dir / p.name)
        log.ok(f"copied {len(apks)} split APK(s) from {src}")
    else:
        shutil.copy2(src, ctx.apk_dir / src.name)
        log.ok(f"copied {src.name}")


def _from_adb(ctx: RunContext) -> None:
    adb = require("adb")
    # Confirm a single device is connected.
    devs = sh([adb, "devices"]).stdout.strip().splitlines()[1:]
    devs = [d for d in devs if d.strip() and "device" in d.split()]
    if not devs:
        raise RuntimeError("no ADB devices connected. Run `adb devices` to check.")
    log.info(f"adb device: {devs[0].split()[0]}")

    # Locate all split APKs for the package. Some devices return CRLF — strip \r first.
    paths_out = sh([adb, "shell", "pm", "path", ctx.package])
    stdout = paths_out.stdout.replace("\r", "")
    if not stdout.strip():
        raise RuntimeError(f"package not installed on device: {ctx.package}")
    paths = [
        line.strip().replace("package:", "").strip()
        for line in stdout.splitlines() if line.strip()
    ]
    log.info(f"pulling {len(paths)} APK(s) from device")
    for i, p in enumerate(paths):
        suffix = "base" if i == 0 else f"split{i}"
        out_name = f"{ctx.package}.{suffix}.apk"
        sh([adb, "pull", p, str(ctx.apk_dir / out_name)], timeout=180)
    log.ok(f"pulled {len(paths)} APK(s) for {ctx.package}")


def _merge_if_split(ctx: RunContext) -> None:
    apks = sorted(ctx.apk_dir.glob("*.apk"))
    universal = ctx.universal_apk
    if len(apks) == 1:
        # Single APK already universal-ish — just symlink/copy as universal.apk
        shutil.copy2(apks[0], universal)
        log.ok(f"single APK; using as universal ({universal.stat().st_size // 1024} KiB)")
        return
    jar = apkeditor_jar()
    if not jar.exists():
        raise RuntimeError(
            f"APKEditor.jar not found at {jar}. Run ./scripts/bootstrap.sh"
        )
    java = require("java")
    log.info(f"merging {len(apks)} split APKs via APKEditor → universal.apk")
    sh([java, "-jar", str(jar), "m", "-i", str(ctx.apk_dir), "-o", str(universal), "-f"], timeout=300)
    log.ok(f"merged to {universal.name} ({universal.stat().st_size // 1024} KiB)")
