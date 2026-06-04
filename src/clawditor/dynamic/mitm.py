"""mitmproxy (mitmweb / mitmdump) lifecycle: start, stop, locate CA, save flow file."""
from __future__ import annotations

import shutil
from pathlib import Path

from clawditor.dynamic import _proc
from clawditor.utils import logging as log
from clawditor.utils.paths import mitmproxy_ca_cert


# Single canonical pid-file name so stop()/is_running() find either binary.
PROC_NAME = "mitmweb"


def get_ca_cert_path() -> Path:
    """Return the mitmproxy CA cert path. Raise helpful error if it doesn't exist yet."""
    p = mitmproxy_ca_cert()
    if not p.exists():
        raise FileNotFoundError(
            f"mitmproxy CA cert not found at {p}.\n"
            "Run `mitmproxy` once interactively (then quit with q) to generate it."
        )
    return p


def is_running() -> bool:
    return _proc.is_running(PROC_NAME)


def start(
    port: int = 8080,
    web_port: int = 8081,
    flow_file: Path | None = None,
    headless: bool = False,
    ignore_hosts: str | None = None,
) -> int:
    """Spawn mitmweb (or mitmdump if ``headless=True``) in the background; return PID.

    Idempotent. When ``headless=True`` the proxy runs as ``mitmdump`` with only
    ``--save-stream-file`` — no web UI, no websocket streaming — which is much
    lighter for chatty apps. The user can still browse the resulting flow file
    afterwards with ``mitmweb --no-server --rfile <flow_file>``.

    ``ignore_hosts`` is a single regex passed through as ``--ignore-hosts``;
    matching hosts are tunnelled through undecoded (no TLS MITM, no decode).
    Use this for SDK domains (AppsFlyer, Crashlytics, Firebase, GMS internals)
    that bundle their own CAs and reject mitmproxy's cert, since their failed
    inits can wedge the rest of the app's traffic.
    """
    if is_running():
        pid = _proc.read_pid(PROC_NAME)
        log.info(f"mitm proxy already running (pid {pid})")
        return pid or -1

    binary = "mitmdump" if headless else "mitmweb"
    if not shutil.which(binary):
        raise RuntimeError(
            f"`{binary}` not on PATH. Install with `brew install mitmproxy` "
            "or run scripts/setup-dynamic.sh."
        )

    cmd: list[str] = [
        binary,
        "--listen-port", str(port),
        "--set", "block_global=false",
    ]
    if not headless:
        cmd += [
            "--web-port", str(web_port),
            "--no-web-open-browser",
            "--set", "web_password=clawditor",
        ]
    if flow_file is not None:
        flow_file.parent.mkdir(parents=True, exist_ok=True)
        cmd += ["--save-stream-file", str(flow_file)]
    if ignore_hosts:
        cmd += ["--ignore-hosts", ignore_hosts]

    mode = "headless" if headless else f"web={web_port}"
    extras = f" ignore_hosts={ignore_hosts}" if ignore_hosts else ""
    log.info(f"launching {binary}: listen={port} {mode} flow={flow_file or '-'}{extras}")
    pid = _proc.spawn_detached(PROC_NAME, cmd)
    if headless:
        log.ok(f"{binary} pid={pid}; headless (re-open flows later with "
               f"`mitmweb --no-server --rfile {flow_file or '<flows.mitm>'}`)")
    else:
        log.ok(f"{binary} pid={pid}; web UI at http://127.0.0.1:{web_port}")
    return pid


def stop() -> bool:
    """SIGTERM the running mitm proxy and clear pid file. True if a process was killed."""
    return _proc.stop(PROC_NAME)
