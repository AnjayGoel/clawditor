"""Locate vendor JARs and project root."""
from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    # src/clawditor/utils/paths.py → project root is two parents up from this file's package
    return Path(__file__).resolve().parents[3]


def vendor_dir() -> Path:
    return project_root() / "vendor"


def apkeditor_jar() -> Path:
    p = vendor_dir() / "APKEditor.jar"
    if not p.exists():
        env = os.environ.get("APKEDITOR_JAR")
        if env and Path(env).exists():
            return Path(env)
    return p


def default_runs_dir() -> Path:
    return project_root() / "data"


def pids_dir() -> Path:
    p = vendor_dir() / ".pids"
    p.mkdir(parents=True, exist_ok=True)
    return p


def dynamic_captures_dir() -> Path:
    p = default_runs_dir() / "dynamic-captures"
    p.mkdir(parents=True, exist_ok=True)
    return p


def dynamic_scripts_dir() -> Path:
    return vendor_dir() / "scripts"


def frida_server_binary(arch: str) -> Path:
    """Path on disk for the unpacked frida-server binary for the given Android arch."""
    return vendor_dir() / f"frida-server-{arch}"


def mitmproxy_ca_cert() -> Path:
    """Default location mitmproxy writes its CA cert to after first run."""
    return Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"


def mitm_pid_file() -> Path:
    return vendor_dir() / ".mitm.pid"
