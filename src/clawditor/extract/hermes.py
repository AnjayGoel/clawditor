"""Decompile React Native Hermes bytecode bundle to JS + disasm."""
from __future__ import annotations

import zipfile
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log
from clawditor.utils.shell import require, run as sh


HERMES_MAGIC = bytes.fromhex("c61fbc03")


def run(ctx: RunContext) -> None:
    bundle = _extract_bundle(ctx)
    if not bundle:
        log.warn("no index.android.bundle found; skipping hermes")
        return
    if not _is_hermes(bundle):
        log.info("bundle is plain JS (not Hermes); copied as-is")
        return
    _decompile(ctx, bundle)


def _extract_bundle(ctx: RunContext) -> Path | None:
    ctx.hermes_dir.mkdir(parents=True, exist_ok=True)
    out = ctx.hermes_dir / "index.android.bundle"
    with zipfile.ZipFile(ctx.universal_apk) as z:
        names = [n for n in z.namelist() if n.endswith("index.android.bundle")]
        if not names:
            return None
        data = z.read(names[0])
        out.write_bytes(data)
    log.info(f"extracted {names[0]} ({len(data)//1024} KiB)")
    return out


def _is_hermes(bundle: Path) -> bool:
    return bundle.read_bytes()[:4] == HERMES_MAGIC


def _decompile(ctx: RunContext, bundle: Path) -> None:
    hbc_decompiler = require("hbc-decompiler")
    out_js = ctx.hermes_dir / "decompiled.js"
    log.info("hermes-dec: bytecode → JS")
    sh([hbc_decompiler, str(bundle), str(out_js)], timeout=600)
    log.ok(f"hermes JS at {out_js}")
    if not ctx.quick:
        try:
            hbc_disasm = require("hbc-disassembler")
        except Exception:
            log.warn("hbc-disassembler missing; skipping disasm")
            return
        out_hasm = ctx.hermes_dir / "disasm.hasm"
        log.info("hermes-dec: disassembling bytecode")
        sh([hbc_disasm, str(bundle), str(out_hasm)], timeout=600)
        log.ok(f"hermes disasm at {out_hasm}")
