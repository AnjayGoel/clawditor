"""Dump strings from every native .so library in the APK."""
from __future__ import annotations

import zipfile

from clawditor.config import RunContext
from clawditor.utils import logging as log
from clawditor.utils.shell import which, run as sh


def run(ctx: RunContext) -> None:
    ctx.native_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(ctx.universal_apk) as z:
        for name in z.namelist():
            if not (name.startswith("lib/") and name.endswith(".so")):
                continue
            arch = name.split("/")[1]
            lib = name.split("/")[-1]
            out_dir = ctx.native_dir / arch
            out_dir.mkdir(exist_ok=True, parents=True)
            so_path = out_dir / lib
            so_path.write_bytes(z.read(name))
            # also dump strings for grep
            if which("strings"):
                res = sh(["strings", str(so_path)], check=False, timeout=120)
                (out_dir / f"{lib}.strings.txt").write_text(res.stdout)
            count += 1
    log.ok(f"extracted {count} native libs to {ctx.native_dir}")
