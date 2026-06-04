"""Dynamic analysis: emulator + mitmproxy + Frida.

Orchestrates a Pixel-7 AVD with a writable Android 34 google_apis system image,
installs the mitmproxy CA into the system trust store, runs mitmweb to capture
HTTPS traffic, and pushes frida-server + objection (or raw Frida + the NVISO
disable-flutter-tls script for Flutter apps) to bypass cert pinning so the
captured traffic actually decrypts.

Each submodule exposes plain functions (not the ``run(ctx) -> dict`` contract
used by static scanners). The orchestrating entry point is the
``clawditor dynamic …`` CLI group in ``clawditor.cli``.

Workflow:
    1. ``scripts/setup-dynamic.sh`` once, to install host tools + AVD + frida-server.
    2. ``clawditor dynamic start`` to boot the emulator and bring up mitm + frida.
    3. ``clawditor dynamic capture <pkg>`` per app to record a flow file + JSON summary.
    4. ``clawditor dynamic stop`` to tear everything down.
"""
