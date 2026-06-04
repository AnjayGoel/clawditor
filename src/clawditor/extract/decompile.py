"""APKEditor decode (smali + resources) + optional jadx (Java)."""
from __future__ import annotations

from clawditor.config import RunContext
from clawditor.utils import logging as log
from clawditor.utils.paths import apkeditor_jar
from clawditor.utils.shell import require, run as sh


def run(ctx: RunContext) -> None:
    _apkeditor_decode(ctx)
    if not (ctx.quick or ctx.no_jadx):
        _jadx_decompile(ctx)
    else:
        log.warn("skipping jadx (quick/no-jadx flag)")


def _apkeditor_decode(ctx: RunContext) -> None:
    jar = apkeditor_jar()
    if not jar.exists():
        raise RuntimeError(f"APKEditor.jar not found at {jar}")
    java = require("java")
    log.info("APKEditor decoding (smali + decoded resources)…")
    sh(
        [java, "-jar", str(jar), "d", "-i", str(ctx.universal_apk), "-o", str(ctx.smali_dir), "-t", "xml", "-f"],
        timeout=600,
    )
    log.ok(f"smali at {ctx.smali_dir}")


def _jadx_decompile(ctx: RunContext) -> None:
    jadx = require("jadx")
    log.info("jadx decompiling DEX → Java (this is the slow part)…")
    # --show-bad-code: keep partial decompiles instead of dropping; -j 8: parallelism
    res = sh(
        [jadx, "-d", str(ctx.jadx_dir), "--show-bad-code", "-j", "8", str(ctx.universal_apk)],
        timeout=900,
        check=False,
    )
    # jadx returns nonzero when some classes fail; that's normal. Only fail if 0 sources.
    if not any(ctx.jadx_dir.glob("sources/**/*.java")):
        raise RuntimeError(f"jadx produced no Java sources:\n{res.stderr[-1000:]}")
    log.ok(f"jadx at {ctx.jadx_dir}")
