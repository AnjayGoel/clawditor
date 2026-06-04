"""WireGuard transport for capturing proxy-ignoring apps (Flutter, Dart, etc.).

Why this exists
---------------
The default capture path sets the Android **global HTTP proxy** and points it at
mitmproxy. That only works for apps that honor the system proxy. **Flutter's Dart
``HttpClient`` ignores it entirely**, so a proxy-based capture of a Flutter app
sees only the OS connectivity checks — none of the app's own traffic.

mitmproxy's WireGuard mode (`mitmdump --mode wireguard`) solves this at the
*network* layer: the device joins a WireGuard tunnel whose only peer is
mitmproxy, so **all** egress is routed through it regardless of proxy-awareness
or which TLS stack the app uses.

Hard-won gotchas baked into this module (each cost real debugging time)
-----------------------------------------------------------------------
1. **UNSET the global HTTP proxy.** If `dynamic start` left `http_proxy` pointing
   at `10.0.2.2:8080`, apps send proxy-style requests *to that address*, and
   mitmproxy-WG then tries to connect upstream to itself and fails
   (`Connect call failed ('10.0.2.2', 8080)`). WG mode is transparent; the proxy
   setting must be cleared. This is the #1 cause of "tunnel up but nothing
   decrypts."
2. **Block QUIC (UDP/443).** Google/Firebase default to HTTP/3; mitmproxy can't
   reliably MITM QUIC. Reject UDP/443 on the device so traffic falls back to
   interceptable TCP/TLS.
3. **Pass through pinned Google/Firebase/GMS infra.** App Check, Remote Config,
   Installations, Crashlytics, GMS internals pin their own CAs (and run in the
   *GMS* process, which our app-scoped Frida bypass can't hook). If intercepted
   they fail their handshake and the app blocks on them at startup → ANR. Ignore
   them (see ``DEFAULT_IGNORE``) so they reach the real endpoints; the app's own
   API + third-party SDKs still get decrypted.
4. **Dual pinning bypass.** Flutter apps that use the native Firebase SDK pin at
   *two* layers: Dart BoringSSL (``disable-flutter-tls.js``) AND Java/Conscrypt
   (``trust-killer.js``). Load both — see ``frida.bypass_pinning_objection``'s
   flutter+extra path / ``capture`` with ``transport='wireguard'``.
5. **The endpoint must be ``10.0.2.2:51820``** as seen from the emulator (host
   loopback via qemu SLIRP), not the host's LAN IP that mitmproxy prints.
6. **VPN consent + tunnel toggle are one-time UI actions.** Android requires the
   user to approve the VpnService ("Connection request" → OK) and the tunnel to
   be toggled on. ``activate`` attempts this via ``adb input`` but the consent
   tap is inherently fragile; if it fails, the module prints instructions.

This module is plain functions (like the rest of ``dynamic/``), invoked by the
``clawditor dynamic capture --wireguard`` path. Nothing here is imported by the
static pipeline.
"""
from __future__ import annotations

import time
from pathlib import Path

from clawditor.dynamic import _proc, emulator
from clawditor.utils import logging as log
from clawditor.utils.paths import vendor_dir, mitmproxy_ca_cert
from clawditor.utils.shell import run as sh, which

PROC_NAME = "mitm-wireguard"
WG_PACKAGE = "com.wireguard.android"
WG_APK_URL = "https://download.wireguard.com/android-client/"
TUNNEL_NAME = "clawditor"

# Pinned/GMS-process infra that wedges the app if intercepted — pass through
# undecoded. The app's own backend + third-party SDKs are still decrypted.
DEFAULT_IGNORE = (
    r"(\.google\.com|googleapis\.com|gstatic|gvt[0-9]|\.gvt1|doubleclick"
    r"|googleadservices|googletagmanager|crashlytics|firebase|app-measurement"
    r"|google-analytics|googlesyndication)"
)


def is_running() -> bool:
    return _proc.is_running(PROC_NAME)


# ─────────────────────────── mitmproxy WG server ───────────────────────────

def start_proxy(flow_file: Path, *, ignore_hosts: str = DEFAULT_IGNORE,
                listen_port: int = 51820, restart: bool = False) -> int:
    """Spawn ``mitmdump --mode wireguard`` in the background; return its PID.

    Idempotent unless ``restart=True`` (used to repoint at a session-specific
    flow file). Keys persist in ``~/.mitmproxy/wireguard.conf`` so a restart
    reuses the same server identity and the device's tunnel config stays valid —
    the WG client reconnects automatically.
    """
    if restart and is_running():
        _proc.stop(PROC_NAME)
        time.sleep(1)
    if is_running():
        pid = _proc.read_pid(PROC_NAME) or -1
        log.info(f"WG mitmproxy already running (pid {pid})")
        return pid
    if not which("mitmdump"):
        raise RuntimeError("`mitmdump` not on PATH. `brew install mitmproxy` "
                           "or run scripts/setup-dynamic.sh.")
    # Ensure the CA exists (device must already trust it from `dynamic start`).
    mitmproxy_ca_cert()
    cmd = ["mitmdump", "--mode", f"wireguard:{listen_port}",
           "--ignore-hosts", ignore_hosts, "-w", str(flow_file)]
    pid = _proc.spawn_detached(PROC_NAME, cmd)
    time.sleep(3)
    log.ok(f"WG mitmproxy up (pid {pid}); ignoring {ignore_hosts[:48]}…")
    return pid


def client_config(*, endpoint_host: str = "10.0.2.2",
                  endpoint_port: int = 51820) -> str:
    """Build the WireGuard client config for the emulator.

    Derived from mitmproxy's persisted keys (``~/.mitmproxy/wireguard.conf``),
    NOT scraped from mitmproxy's stdout — mitmproxy block-buffers stdout when it's
    a file (no TTY), so the printed ``[Interface]`` block never reaches the log.
    The peer's public key is computed from the stored server private key
    (X25519). Endpoint is the host loopback as the guest sees it (10.0.2.2);
    Address/DNS are mitmproxy's fixed WG defaults.
    """
    import json, base64
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    conf_path = mitmproxy_ca_cert().parent / "wireguard.conf"
    if not conf_path.exists():
        raise RuntimeError(
            f"{conf_path} not found — start the WG proxy once (start_proxy) so "
            "mitmproxy generates its WireGuard keys.")
    conf = json.loads(conf_path.read_text())
    server_pub = base64.b64encode(
        X25519PrivateKey.from_private_bytes(base64.b64decode(conf["server_key"]))
        .public_key().public_bytes_raw()
    ).decode()
    return (
        "[Interface]\n"
        f"PrivateKey = {conf['client_key']}\n"
        "Address = 10.0.0.1/32\n"
        "DNS = 10.0.0.53\n\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {endpoint_host}:{endpoint_port}\n"
    )


# ─────────────────────────── WireGuard client (device) ───────────────────────────

def install_client(serial: str) -> None:
    """Install the WireGuard Android client on the device (idempotent)."""
    r = sh(["adb", "-s", serial, "shell", "pm", "list", "packages", WG_PACKAGE],
           timeout=10, check=False)
    if WG_PACKAGE in (r.stdout or ""):
        log.info("WireGuard client already installed")
        return
    apk = _wg_apk()
    log.info(f"installing WireGuard client from {apk.name}")
    sh(["adb", "-s", serial, "install", "-r", str(apk)], timeout=120)


def _wg_apk() -> Path:
    """Locate (or fetch) the WireGuard APK under vendor/."""
    cached = sorted(vendor_dir().glob("com.wireguard.android-*.apk"))
    if cached:
        return cached[-1]
    raise FileNotFoundError(
        f"WireGuard APK not found in {vendor_dir()}. Run scripts/setup-dynamic.sh "
        f"(it downloads the latest from {WG_APK_URL}).")


def push_config(serial: str, conf_text: str, *, tunnel: str = TUNNEL_NAME) -> None:
    """Drop the tunnel config into the WG app's data dir so it loads without the
    import UI. Requires adb root. Ownership + SELinux label are fixed on-device
    so the (unprivileged) app can read it."""
    tmp = f"/data/local/tmp/{tunnel}.conf"
    # Write via a heredoc on the device to avoid host-side file juggling.
    sh(["adb", "-s", serial, "shell", f"cat > {tmp} <<'EOF'\n{conf_text}\nEOF"],
       timeout=10, check=False)
    # Move into the app's files dir, owned + labelled correctly.
    script = (
        f'D=/data/data/{WG_PACKAGE}; u=$(stat -c %u $D); mkdir -p $D/files; '
        f'cp {tmp} $D/files/{tunnel}.conf && chown $u:$u $D/files/{tunnel}.conf && '
        f'restorecon $D/files/{tunnel}.conf 2>/dev/null; ls $D/files/{tunnel}.conf'
    )
    r = sh(["adb", "-s", serial, "shell", script], timeout=10, check=False)
    if f"{tunnel}.conf" not in (r.stdout or ""):
        raise RuntimeError(f"failed to place WG config (adb root required): {r.stderr}")
    log.ok(f"WG tunnel '{tunnel}' config placed")


# ─────────────────────────── device prep ───────────────────────────

def prepare_device(serial: str) -> None:
    """Clear the global HTTP proxy (WG is transparent) and block QUIC."""
    emulator.clear_proxy(serial)            # gotcha #1
    block_quic(serial)                      # gotcha #2


def block_quic(serial: str) -> None:
    """Reject outbound UDP/443 so QUIC falls back to interceptable TCP/TLS."""
    for ipt in ("iptables", "ip6tables"):
        sh(["adb", "-s", serial, "shell", ipt, "-A", "OUTPUT", "-p", "udp",
            "--dport", "443", "-j", "REJECT"], timeout=10, check=False)
    log.ok("QUIC (UDP/443) blocked → TCP fallback")


def unblock_quic(serial: str) -> None:
    for ipt in ("iptables", "ip6tables"):
        sh(["adb", "-s", serial, "shell", ipt, "-D", "OUTPUT", "-p", "udp",
            "--dport", "443", "-j", "REJECT"], timeout=10, check=False)


def tunnel_is_up(serial: str) -> bool:
    r = sh(["adb", "-s", serial, "shell", "ip", "addr", "show", "tun0"],
           timeout=10, check=False)
    return "inet " in (r.stdout or "")


def activate(serial: str, *, tunnel: str = TUNNEL_NAME) -> bool:
    """Best-effort: open the WG app, toggle the tunnel, accept the VpnService
    consent. Returns True if ``tun0`` comes up. The consent/toggle taps are
    coordinate-based and fragile; on failure the caller should fall back to
    asking the user to flip the toggle in the WireGuard app manually."""
    if tunnel_is_up(serial):
        log.info("WG tunnel already up")
        return True
    sh(["adb", "-s", serial, "shell", "am", "start", "-n",
        f"{WG_PACKAGE}/.activity.MainActivity"], timeout=10, check=False)
    time.sleep(3)
    # Toggle (right-side switch on the tunnel row) — coords for a 1080x2400 AVD.
    sh(["adb", "-s", serial, "shell", "input", "tap", "972", "388"],
       timeout=10, check=False)
    time.sleep(3)
    # VpnService "Connection request" → OK (bottom-right of the dialog).
    sh(["adb", "-s", serial, "shell", "input", "tap", "890", "1527"],
       timeout=10, check=False)
    time.sleep(3)
    up = tunnel_is_up(serial)
    if up:
        log.ok("WG tunnel up (tun0)")
    else:
        log.warn(f"WG tunnel not up. Open the WireGuard app and toggle "
                 f"'{tunnel}' on manually (accept the VPN consent), then retry.")
    return up


def teardown(serial: str) -> None:
    """Stop the WG proxy, drop the QUIC block. (Tunnel stays configured on-device
    for the next session; toggle it off in the app if you want it gone.)"""
    _proc.stop(PROC_NAME)
    unblock_quic(serial)
