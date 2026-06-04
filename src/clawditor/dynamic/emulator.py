"""AVD operations: boot the Pixel-7 AVD, wait for boot, install mitm CA, set proxy.

Assumes ``clawditor-pixel7`` was created by ``scripts/setup-dynamic.sh`` using a
``google_apis`` (not ``google_apis_playstore``) system image — the Play Store
image refuses ``adb root`` and ``adb remount``, which kills the system-CA install.
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path


def _resolve_emulator() -> str | None:
    """Locate the Android SDK ``emulator`` binary, preferring the SDK over PATH.

    A stale Homebrew ``emulator`` (an old standalone build) can shadow the real
    SDK one on PATH; that old binary resolves its qemu/Qt libs relative to its
    own dir and dies on launch. So check the SDK locations first, then PATH.
    """
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             os.path.expanduser("~/Library/Android/sdk"),
             os.path.expanduser("~/Android/Sdk")]
    for root in roots:
        if root:
            cand = Path(root) / "emulator" / "emulator"
            if cand.exists():
                return str(cand)
    return shutil.which("emulator")

from clawditor.dynamic import _proc
from clawditor.utils import logging as log
from clawditor.utils.shell import run as sh, ShellError, require


PROC_NAME = "emulator"
BOOT_TIMEOUT_S = 240


def _serial(port: int) -> str:
    return f"emulator-{port}"


def is_booted(serial: str) -> bool:
    try:
        r = sh(["adb", "-s", serial, "shell", "getprop", "sys.boot_completed"],
               timeout=10, check=False)
        return r.ok and r.stdout.strip() == "1"
    except Exception:
        return False


def boot(
    avd_name: str = "clawditor-pixel7",
    port: int = 5554,
    headless: bool = False,
    writable_system: bool = True,
) -> None:
    """Boot the AVD as a detached background process; block until sys.boot_completed=1.

    Idempotent: if a serial is already booted on this port, returns immediately.
    """
    serial = _serial(port)
    if is_booted(serial):
        log.info(f"emulator already booted at {serial}")
        return

    require("adb")
    emu = _resolve_emulator()
    if not emu:
        raise RuntimeError(
            "`emulator` not on PATH. Install via Android SDK and add "
            "$ANDROID_HOME/emulator to PATH, or run scripts/setup-dynamic.sh."
        )

    args = [emu, "-avd", avd_name, "-port", str(port), "-no-snapshot-load"]
    if writable_system:
        args.append("-writable-system")
    if headless:
        args.append("-no-window")
    # Quieter audio + a stable network stack:
    args += ["-no-audio", "-no-boot-anim"]

    log.info(f"launching emulator: {' '.join(args)}")
    _proc.spawn_detached(PROC_NAME, args)

    # Wait for adb to see the device, then for boot completion.
    log.info(f"waiting for {serial} to appear …")
    sh(["adb", "-s", serial, "wait-for-device"], timeout=BOOT_TIMEOUT_S)

    log.info("waiting for sys.boot_completed=1 …")
    deadline = time.time() + BOOT_TIMEOUT_S
    while time.time() < deadline:
        if is_booted(serial):
            log.ok(f"emulator booted: {serial}")
            return
        time.sleep(3)
    raise TimeoutError(f"emulator {serial} did not reach boot_completed within {BOOT_TIMEOUT_S}s")


def adb_root_remount(serial: str) -> None:
    """`adb root` then `adb remount`. Requires a google_apis (non-Play) image."""
    r = sh(["adb", "-s", serial, "root"], timeout=30, check=False)
    if not r.ok and "production builds" in (r.stdout + r.stderr).lower():
        raise RuntimeError(
            "`adb root` refused — this AVD is using a Play Store system image. "
            "Recreate with sdkmanager 'system-images;android-34;google_apis;<arch>'."
        )
    # adb root restarts adbd; re-wait briefly so the next call doesn't race.
    sh(["adb", "-s", serial, "wait-for-device"], timeout=30)
    sh(["adb", "-s", serial, "remount"], timeout=30)


def _android_cert_hash(ca_path: Path) -> str:
    """Compute the Android-style subject hash that names the cert in the trust store."""
    r = sh(["openssl", "x509", "-inform", "PEM", "-in", str(ca_path), "-subject_hash_old", "-noout"],
           timeout=10, check=False)
    if r.ok and r.stdout.strip():
        return r.stdout.strip().splitlines()[0].strip()
    # Fallback to the modern hash if -subject_hash_old isn't available.
    r = sh(["openssl", "x509", "-inform", "PEM", "-in", str(ca_path), "-hash", "-noout"], timeout=10)
    return r.stdout.strip().splitlines()[0].strip()


def install_mitmproxy_ca(serial: str, ca_path: Path) -> bool:
    """Install mitmproxy CA into the Android trust store.

    On Android 14, ``/system/etc/security/cacerts/<hash>.0`` alone is no longer
    enough: apps using the ``com.android.conscrypt`` APEX (i.e. almost all of
    them) read certs from ``/apex/com.android.conscrypt/cacerts/``. We bind-mount
    a tmpfs over that directory, copy all the standard system certs into it,
    then drop the mitm CA in too. The bind-mount is **transient across reboots**,
    so this MUST run every ``dynamic start`` even when the underlying system
    cert is already in place.

    Returns True if the mitm CA was newly pushed to /system, False if it was
    already there. The apex overlay is always (re-)applied either way.
    No reboot is performed: the apex overlay is live immediately, and rebooting
    would wipe the bind-mount we just put in.
    """
    if not ca_path.exists():
        raise FileNotFoundError(
            f"mitmproxy CA not found at {ca_path}. Launch `mitmproxy` once "
            "to generate ~/.mitmproxy/mitmproxy-ca-cert.cer, then retry."
        )
    h = _android_cert_hash(ca_path)
    dest = f"/system/etc/security/cacerts/{h}.0"
    chk = sh(["adb", "-s", serial, "shell", "ls", dest], timeout=10, check=False)
    pushed_new = not (chk.ok and dest in chk.stdout)
    if pushed_new:
        log.info(f"pushing mitm CA → {dest}")
        sh(["adb", "-s", serial, "push", str(ca_path), dest], timeout=30)
        sh(["adb", "-s", serial, "shell", "chmod", "644", dest], timeout=10)
    else:
        log.info(f"system CA already present at {dest}")

    _install_apex_overlay(serial, hash_name=f"{h}.0")
    return pushed_new


def _install_apex_overlay(serial: str, *, hash_name: str) -> None:
    """Bind-mount tmpfs over /apex/com.android.conscrypt/cacerts/ and seed it.

    Android 14's Conscrypt APEX reads certs from the apex path, not from
    /system. The mount is per-boot. ``mount`` errors with "already mounted"
    are tolerated (idempotent within a boot). After mounting we copy all the
    standard system certs in plus the mitm CA we just pushed, chmod 644 the
    lot, and verify our cert is visible at the expected hashname.
    """
    apex = "/apex/com.android.conscrypt/cacerts/"
    log.info(f"bind-mounting tmpfs over {apex} (transient until next reboot)")
    sh(["adb", "-s", serial, "shell",
        f"mount -t tmpfs tmpfs {apex} 2>/dev/null || true"], timeout=15, check=False)
    sh(["adb", "-s", serial, "shell",
        f"cp /system/etc/security/cacerts/* {apex}"], timeout=30, check=False)
    sh(["adb", "-s", serial, "shell",
        f"chmod 644 {apex}*"], timeout=15, check=False)
    chk = sh(["adb", "-s", serial, "shell", "ls", f"{apex}{hash_name}"],
             timeout=10, check=False)
    if not (chk.ok and hash_name in chk.stdout):
        raise RuntimeError(
            f"apex overlay seed failed: {apex}{hash_name} not visible after copy. "
            f"adb output: {(chk.stdout + chk.stderr).strip()[:200]}\n"
            "On Android 14 this overlay is required for apps using "
            "com.android.conscrypt (~all apps). Re-run `adb root`+`remount` and retry."
        )
    log.ok(f"apex overlay live: {apex}{hash_name}")


def set_proxy(serial: str, host: str = "10.0.2.2", port: int = 8080) -> None:
    """Point the emulator's global HTTP proxy at host:port. 10.0.2.2 = host loopback."""
    sh(["adb", "-s", serial, "shell", "settings", "put", "global",
        "http_proxy", f"{host}:{port}"], timeout=10)
    log.ok(f"proxy set: {serial} → {host}:{port}")


def clear_proxy(serial: str) -> None:
    sh(["adb", "-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"],
       timeout=10, check=False)


def shutdown(serial: str) -> None:
    """Politely kill the emulator. Best-effort: tolerate failures."""
    sh(["adb", "-s", serial, "emu", "kill"], timeout=15, check=False)
    _proc.stop(PROC_NAME)


def detect_arch(serial: str) -> str:
    """Return Android ABI name ('arm64-v8a' / 'x86_64'). Used to pick frida-server."""
    r = sh(["adb", "-s", serial, "shell", "getprop", "ro.product.cpu.abi"], timeout=10)
    return r.stdout.strip() or "arm64-v8a"
