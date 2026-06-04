"""Push + start frida-server on the emulator, drive objection / raw Frida for pinning bypass."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from clawditor.dynamic import _proc
from clawditor.utils import logging as log
from clawditor.utils.paths import dynamic_scripts_dir
from clawditor.utils.shell import run as sh


DEVICE_PATH = "/data/local/tmp/frida-server"
PROC_NAME = "frida-server-pusher"


def push_server(serial: str, server_binary: Path) -> None:
    """Push frida-server binary to /data/local/tmp and chmod 755. Idempotent."""
    if not server_binary.exists():
        raise FileNotFoundError(
            f"frida-server binary not found at {server_binary}. "
            "Run scripts/setup-dynamic.sh to download it."
        )
    log.info(f"pushing {server_binary.name} → {DEVICE_PATH}")
    sh(["adb", "-s", serial, "push", str(server_binary), DEVICE_PATH], timeout=60)
    sh(["adb", "-s", serial, "shell", "chmod", "755", DEVICE_PATH], timeout=10)


def is_server_running(serial: str) -> bool:
    r = sh(["adb", "-s", serial, "shell", "pgrep", "-f", "frida-server"],
           timeout=10, check=False)
    return r.ok and bool(r.stdout.strip())


def start_server(serial: str) -> None:
    """Launch frida-server as a detached background process on the emulator."""
    if is_server_running(serial):
        log.info("frida-server already running on device")
        return
    # We launch via `adb shell nohup ... &` and detach. adb root has already run,
    # so the shell is uid 0.
    cmd = (
        f"nohup {DEVICE_PATH} >/data/local/tmp/frida-server.log 2>&1 &"
    )
    sh(["adb", "-s", serial, "shell", "su", "0", "sh", "-c", cmd], timeout=10, check=False)
    # Some images don't have `su` but adb root already gave us uid 0; try again unwrapped.
    if not is_server_running(serial):
        sh(["adb", "-s", serial, "shell", "sh", "-c", cmd], timeout=10, check=False)
    if not is_server_running(serial):
        raise RuntimeError("frida-server did not start. Check /data/local/tmp/frida-server.log on device.")
    log.ok("frida-server running on device")


def stop_server(serial: str) -> None:
    sh(["adb", "-s", serial, "shell", "pkill", "-f", "frida-server"], timeout=10, check=False)


def flutter_tls_script() -> Path:
    """Path to the bundled NVISO disable-flutter-tls Frida script."""
    return dynamic_scripts_dir() / "disable-flutter-tls.js"


def trust_killer_script(*, lite: bool = False, mega: bool = False) -> Path:
    """Path to the bundled generic TLS / pinning bypass Frida script.

    Selection rules (mega wins over lite):
      - ``mega=True`` → ``trust-killer-mega.js`` (TLS + GMS + Pairip bypasses).
        The lite/full TLS-only split is irrelevant once mega is in play, because
        the mega script's extra hooks (GMS, Pairip) are orthogonal to the
        per-handshake SSLContext.init cost that ``lite=True`` exists to avoid.
      - else ``lite=True`` → ``trust-killer-lite.js`` (drops the SSLContext.init
        hook for chatty apps; ``clawditor dynamic capture --fast`` path).
      - else → ``trust-killer.js`` (canonical 4-hook TLS bypass).
    """
    if mega:
        name = "trust-killer-mega.js"
    elif lite:
        name = "trust-killer-lite.js"
    else:
        name = "trust-killer.js"
    return dynamic_scripts_dir() / name


def bypass_pinning_objection(
    package: str,
    *,
    flutter: bool = False,
    fast: bool = False,
    bypass_gms: bool = False,
    bypass_pairip: bool = False,
    extra_script: Path | None = None,
) -> subprocess.Popen:
    """Spawn the app with cert-pinning bypass active. Returns the running Popen.

    Default path: objection's built-in 'android sslpinning disable' + 'android root disable',
    augmented by ``vendor/scripts/trust-killer.js`` as the startup script when no
    ``extra_script`` is supplied.
    With ``flutter=True``: skip objection (no-op on Flutter, which uses BoringSSL) and use
    raw Frida with the NVISO disable-flutter-tls script.
    With ``fast=True`` (non-Flutter only): swap ``trust-killer.js`` for the lite variant
    that drops the SSLContext.init hook. Ignored when ``flutter=True``.
    With ``bypass_gms=True`` or ``bypass_pairip=True`` (non-Flutter only): use
    ``trust-killer-mega.js`` which adds GMS version-check + Pairip license-check
    bypasses on top of the TLS hooks. Mega overrides ``fast`` (see
    ``trust_killer_script``); the extra hooks aren't cost-sensitive the way
    SSLContext.init is.

    The caller owns the returned Popen and is responsible for killing it during teardown.
    """
    if flutter:
        if not shutil.which("frida"):
            raise RuntimeError("`frida` not on PATH. Install with `pipx install frida-tools`.")
        script = extra_script or flutter_tls_script()
        if not script.exists():
            raise FileNotFoundError(
                f"Flutter-TLS bypass script missing at {script}. "
                "Run scripts/setup-dynamic.sh to fetch it."
            )
        cmd = ["frida", "-U", "-l", str(script), "-f", package, "--no-pause"]
    else:
        if not shutil.which("objection"):
            raise RuntimeError("`objection` not on PATH. Install with `pipx install objection`.")
        startup = "android sslpinning disable; android root disable"
        cmd = ["objection", "-g", package, "explore", "--startup-command", startup]
        mega = bypass_gms or bypass_pairip
        script = extra_script or trust_killer_script(lite=fast, mega=mega)
        if script.exists():
            cmd += ["--startup-script", str(script)]
        elif extra_script is not None:
            # Caller asked for a specific script that's missing — surface it.
            raise FileNotFoundError(f"bypass script missing at {script}")

    if flutter:
        variant = "flutter"
    elif bypass_gms or bypass_pairip:
        extras = []
        if bypass_gms: extras.append("gms")
        if bypass_pairip: extras.append("pairip")
        variant = f"objection+trust-killer-mega[{','.join(extras)}]"
    elif fast:
        variant = "objection+trust-killer-lite"
    else:
        variant = "objection+trust-killer"
    log.info(f"launching pinning-bypass for {package} ({variant})")
    # Use Popen directly here because the caller wants the handle.
    name = f"bypass-{package.replace('.', '_')}"
    pid = _proc.spawn_detached(name, cmd)
    # Re-attach a Popen-shaped handle by reading from the process tree.
    # We can't recover the original Popen, but we expose a minimal shim:
    class _Handle:
        def __init__(self, pid: int, name: str) -> None:
            self.pid = pid
            self._name = name
        def terminate(self) -> None:
            _proc.stop(self._name)
        def kill(self) -> None:
            _proc.stop(self._name)
        def poll(self) -> int | None:
            return None if _proc.is_alive(self.pid) else 0
    return _Handle(pid, name)  # type: ignore[return-value]
