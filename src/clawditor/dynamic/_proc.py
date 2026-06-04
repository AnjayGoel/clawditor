"""Helpers for spawning + tracking detached long-running processes.

The dynamic phase needs to run the emulator, mitmweb and frida-server in the
background and keep them alive across CLI invocations. ``clawditor.utils.shell.run``
captures stdout and blocks, which is wrong for those. This module is the only
place we touch ``subprocess.Popen`` directly.
"""
from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from typing import Sequence

from clawditor.utils.paths import pids_dir


def _pidfile(name: str) -> Path:
    return pids_dir() / f"{name}.pid"


def _logfile(name: str) -> Path:
    return pids_dir() / f"{name}.log"


def spawn_detached(
    name: str,
    cmd: Sequence[str | Path],
    *,
    env: dict | None = None,
    cwd: Path | None = None,
) -> int:
    """Spawn cmd in a new session, redirect IO to a log file, record the PID.

    Returns the PID. Subsequent ``read_pid(name)`` calls will return it until
    ``stop(name)`` clears the file.
    """
    log = _logfile(name)
    log.parent.mkdir(parents=True, exist_ok=True)
    out = log.open("ab")
    proc = subprocess.Popen(
        [str(c) for c in cmd],
        stdin=subprocess.DEVNULL,
        stdout=out,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=env,
        cwd=str(cwd) if cwd else None,
    )
    _pidfile(name).write_text(str(proc.pid))
    return proc.pid


def read_pid(name: str) -> int | None:
    p = _pidfile(name)
    if not p.exists():
        return None
    try:
        return int(p.read_text().strip())
    except ValueError:
        return None


def is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def is_running(name: str) -> bool:
    pid = read_pid(name)
    return pid is not None and is_alive(pid)


def stop(name: str, *, sig: int = signal.SIGTERM) -> bool:
    """SIGTERM the named process if alive, then remove the pid file. True if killed."""
    pid = read_pid(name)
    killed = False
    if pid is not None and is_alive(pid):
        try:
            os.killpg(os.getpgid(pid), sig)
            killed = True
        except (OSError, ProcessLookupError):
            try:
                os.kill(pid, sig)
                killed = True
            except (OSError, ProcessLookupError):
                pass
    p = _pidfile(name)
    if p.exists():
        p.unlink()
    return killed


def log_path(name: str) -> Path:
    return _logfile(name)
