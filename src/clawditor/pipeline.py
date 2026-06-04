"""Orchestrator. Sequences acquire → extract → detect → scan → probe → report."""
from __future__ import annotations

from clawditor.config import RunContext
from clawditor.utils import logging as log


def run(ctx: RunContext) -> None:
    ctx.write_meta()
    log.stage(f"clawditor — run started at {ctx.started_at}")
    log.info(f"output dir: {ctx.out_dir}")

    if ctx.probe_only:
        _probe_phase(ctx)
        _report_phase(ctx)
        return

    _acquire_phase(ctx)
    stack = _extract_phase(ctx)
    _scan_phase(ctx, stack)
    if not ctx.no_probe:
        _probe_phase(ctx)
    else:
        log.warn("--no-probe set; skipping active network probes")
    _report_phase(ctx)
    log.ok(f"done. open {ctx.reports_dir / 'SUMMARY.md'}")


def _acquire_phase(ctx: RunContext) -> None:
    log.stage("acquire")
    from clawditor.acquire import acquire as acq
    acq.run(ctx)


def _extract_phase(ctx: RunContext) -> dict:
    log.stage("extract")
    from clawditor.extract import decompile, hermes, native, flutter
    from clawditor.detect import stack as stack_detect
    decompile.run(ctx)
    stack = stack_detect.run(ctx)
    native.run(ctx)  # do this before stack-specific extractors so libapp.so is on disk
    if stack.get("react_native"):
        hermes.run(ctx)
    if stack.get("flutter"):
        flutter.run(ctx)
    return stack


def _scan_phase(ctx: RunContext, stack: dict) -> None:
    log.stage("scan")
    from clawditor.scan import (apkleaks_run, trufflehog_run, secrets, manifest, code_patterns,
                              intent_security, sdk_inventory, network_security, cert_pinning,
                              payment_sdk, asset_inspector, applinks, build_leaks, privacy,
                              jwt_analyzer)
    apkleaks_run.run(ctx)
    trufflehog_run.run(ctx)
    secrets.run(ctx)
    manifest.run(ctx)
    jwt_analyzer.run(ctx)        # depends on secrets.json
    applinks.run(ctx)
    code_patterns.run(ctx)
    intent_security.run(ctx)
    sdk_inventory.run(ctx)
    network_security.run(ctx)
    cert_pinning.run(ctx)
    payment_sdk.run(ctx)
    asset_inspector.run(ctx)
    build_leaks.run(ctx)
    privacy.run(ctx)


def _probe_phase(ctx: RunContext) -> None:
    log.stage("probe")
    from clawditor.probe import (google_keys, firebase_rtdb, firebase_firestore,
                                firebase_storage, ai_keys, s3_buckets)
    google_keys.run(ctx)
    firebase_rtdb.run(ctx)
    firebase_firestore.run(ctx)
    firebase_storage.run(ctx)
    ai_keys.run(ctx)
    s3_buckets.run(ctx)


def _report_phase(ctx: RunContext) -> None:
    log.stage("report")
    from clawditor.report import markdown as md
    md.run(ctx)
