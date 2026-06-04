"""Drive a single capture session against one package.

Assumes ``clawditor dynamic start`` has already booted the emulator, brought up
mitmweb, and started frida-server. Each call to ``capture`` opens a fresh flow
file under ``out_dir/flows.mitm``, launches the app with cert-pinning bypass,
optionally executes a list of ``adb shell input …`` driver commands, sleeps for
``duration_s`` seconds, then stops the app and ingests the captured flows into
``dynamic_capture.json``.
"""
from __future__ import annotations

import time
from pathlib import Path

from clawditor.dynamic import emulator, frida, ingest, mitm
from clawditor.utils import logging as log
from clawditor.utils.shell import run as sh


def _serial_default() -> str:
    return "emulator-5554"


def _assert_ready(serial: str) -> None:
    if not emulator.is_booted(serial):
        raise RuntimeError(
            f"emulator {serial} is not booted. Run `clawditor dynamic start` first."
        )
    if not mitm.is_running():
        raise RuntimeError("mitm proxy is not running. Run `clawditor dynamic start` first.")
    if not frida.is_server_running(serial):
        raise RuntimeError("frida-server is not running on the device. "
                           "Run `clawditor dynamic start` first.")


def _drive(serial: str, drive_script: list[str], total_s: int) -> None:
    """Run a sequence of `adb shell input …` cmds spread across the duration window."""
    if not drive_script:
        return
    gap = max(1, total_s // (len(drive_script) + 1))
    for i, cmd_line in enumerate(drive_script):
        time.sleep(gap)
        log.info(f"drive[{i + 1}/{len(drive_script)}]: {cmd_line}")
        parts = ["adb", "-s", serial, "shell"] + cmd_line.split()
        sh(parts, timeout=15, check=False)


def capture(
    package: str,
    *,
    duration_s: int = 60,
    out_dir: Path,
    flutter: bool = False,
    fast: bool = False,
    bypass_gms: bool = False,
    bypass_pairip: bool = False,
    ignore_hosts: str | None = None,
    drive_script: list[str] | None = None,
    serial: str | None = None,
    proxy_port: int = 8080,
    proxy_web_port: int = 8081,
) -> dict:
    """Capture one session. Returns the dict written to ``dynamic_capture.json``.

    ``fast=True`` swaps the heavy bits for lighter equivalents: headless
    ``mitmdump`` instead of ``mitmweb``, and the reduced ``trust-killer-lite.js``
    Frida script (only matters when ``flutter=False``). Use when the emulator
    or target app is lagging under the default setup.

    ``bypass_gms`` / ``bypass_pairip`` switch the TLS bypass to the mega Frida
    script that also stubs Google Play Services version checks and/or Pairip
    license-check classes. Mega takes precedence over ``fast``'s lite script.

    ``ignore_hosts`` is a single regex of hosts to bypass MITM on. Required for
    apps whose SDK CAs (AppsFlyer, Crashlytics, GMS, Facebook) cause the SDK
    inits to fail and wedge subsequent app traffic.
    """
    serial = serial or _serial_default()
    _assert_ready(serial)
    out_dir.mkdir(parents=True, exist_ok=True)
    flow_file = out_dir / "flows.mitm"
    out_json = out_dir / "dynamic_capture.json"

    mode_bits = []
    mode_bits.append("flutter" if flutter else "objection")
    if bypass_gms or bypass_pairip:
        extras = []
        if bypass_gms: extras.append("gms")
        if bypass_pairip: extras.append("pairip")
        mode_bits.append(f"mega[{','.join(extras)}]")
    elif fast:
        mode_bits.append("fast (headless mitmdump + trust-killer-lite)")
    else:
        mode_bits.append("default (mitmweb + trust-killer)")
    if ignore_hosts:
        mode_bits.append(f"ignore_hosts={ignore_hosts[:40]}{'…' if len(ignore_hosts) > 40 else ''}")
    log.info(f"capture mode: {' / '.join(mode_bits)}")

    # 1. Restart the mitm proxy with a session-specific --save-stream-file.
    #    It must own the file for the whole session for the stream format to be valid.
    mitm.stop()
    mitm.start(port=proxy_port, web_port=proxy_web_port, flow_file=flow_file,
               headless=fast, ignore_hosts=ignore_hosts)
    # Give the proxy a beat to bind sockets before we trigger device traffic.
    time.sleep(2)

    # 2. Launch the app with pinning bypass attached. Bypass tool spawns the app.
    bypass = frida.bypass_pinning_objection(
        package, flutter=flutter, fast=fast,
        bypass_gms=bypass_gms, bypass_pairip=bypass_pairip,
    )
    # Give the bypass tool time to attach + spawn the process.
    time.sleep(5)

    try:
        # 3. Optional UI driver (just spreads adb input commands across the window).
        elapsed_in_drive = 0
        if drive_script:
            _drive(serial, drive_script, duration_s)
            elapsed_in_drive = duration_s  # _drive already sleeps; nothing more to do
        # 4. Otherwise just sleep for the rest of the window.
        if not drive_script:
            log.info(f"capturing for {duration_s}s …")
            time.sleep(duration_s)
        elif elapsed_in_drive < duration_s:
            time.sleep(duration_s - elapsed_in_drive)
    finally:
        log.info("stopping app + bypass tool")
        try:
            bypass.terminate()
        except Exception:
            pass
        sh(["adb", "-s", serial, "shell", "am", "force-stop", package],
           timeout=10, check=False)
        # Flush mitmweb by stopping it; the stream file is now complete.
        mitm.stop()

    log.info(f"ingesting {flow_file} → {out_json}")
    return ingest.ingest(flow_file, out_json, package=package, duration_s=duration_s)
