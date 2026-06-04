---
name: dynamic-analysis
description: Use when the user asks for dynamic / runtime Android analysis, mitmproxy capture of an APK, Frida hooks against an installed app, SSL / cert pinning bypass, or live extraction of real Firestore collection names / Storage paths / bearer tokens from a running app. Drives the `clawditor dynamic …` CLI group: setup, start, capture (incl. Flutter via BoringSSL bypass), stop. Pass `--fast` for chatty apps (mitmdump + lite Frida hooks), `--ignore-hosts auto` when heavy SDKs (AppsFlyer / Crashlytics / Firebase / GMS) block traffic with their own bundled CAs, `--bypass-pairip` for Play-anti-piracy-wrapped apps that won't start sideloaded, `--bypass-gms` when the app shows the 'Update Google Play services' dialog on launch.
---

# dynamic-analysis

The dynamic-analysis phase of `clawditor` lives at `src/clawditor/dynamic/` and is exposed via the `clawditor dynamic …` CLI group. It runs the target APK on a rooted Pixel-7 AVD (Android 34, **google_apis** image), intercepts HTTPS through mitmproxy with the CA installed as a system root, and uses Frida (via objection — or raw Frida + NVISO `disable-flutter-tls.js` for Flutter apps) to defeat cert pinning so the captured stream actually decrypts.

## When to invoke this skill

Whenever the user asks any of:

- "run dynamic analysis on `<app>`"
- "capture the traffic for `<app>`" / "mitm `<app>`"
- "what Firestore collections does `<app>` actually read?"
- "bypass SSL pinning on `<app>`"
- "Frida hook `<app>`" / "objection on `<app>`"
- "the static run shows X — let me see it live"

…and also when the user has just finished a static `clawditor run …` and wants to confirm endpoints / collection IDs / bearer-token shape against a live capture.

## End-to-end invocation

```bash
# One-time host bootstrap (installs mitmproxy, objection, frida-tools, Android SDK
# packages, creates the clawditor-pixel7 AVD, downloads matching frida-server, and
# fetches disable-flutter-tls.js).
./scripts/setup-dynamic.sh
# or equivalently:
uv run clawditor dynamic setup

# Before first use: launch `mitmproxy` once and quit (q). That writes
# ~/.mitmproxy/mitmproxy-ca-cert.cer — the CA we install onto the AVD.

# Bring up emulator + system-CA + mitmweb + frida-server.
uv run clawditor dynamic start
uv run clawditor dynamic status   # sanity check

# Capture one session against a native / Kotlin / RN / CMP app:
uv run clawditor dynamic capture com.example.app --duration 90

# Lower-overhead capture for chatty apps that lag the emulator (social / livestream apps):
# headless mitmdump (no live UI) + reduced trust-killer-lite Frida hooks.
# Browse the resulting flow file later with `mitmweb --no-server --rfile flows.mitm`.
uv run clawditor dynamic capture com.example.chatty --fast --duration 90

# Capture against a Flutter app (uses BoringSSL bypass):
uv run clawditor dynamic capture com.example.flutter --flutter --duration 90

# Heavy-SDK app: let AppsFlyer / Crashlytics / Firebase / GMS pass through undecoded
# so their bundled-CA pins don't wedge the app's own backend calls.
uv run clawditor dynamic capture com.heavy.sdk.app --ignore-hosts auto

# Sideloaded Play-anti-piracy (Pairip) wrapped app:
uv run clawditor dynamic capture com.wrapped.app --bypass-pairip

# App that gates on Google Play Services version on launch:
uv run clawditor dynamic capture com.gms.gated.app --bypass-gms

# Capture into a directory adjacent to an existing static run:
uv run clawditor dynamic capture com.example.app --run-id com.example.app_20260523-120000

# Tear down:
uv run clawditor dynamic stop
```

## What to read from the output

```
data/dynamic-captures/<pkg>_<ts>/
├── flows.mitm             # raw mitm stream (replay with `mitmproxy -r flows.mitm`)
└── dynamic_capture.json   # summary: hosts, endpoints, firestore.collections,
                           #          storage.paths_observed, auth_token_count,
                           #          jwts_in_responses
```

The JSON is the agent-facing artifact. Read it directly to:

- pick real Firestore collection IDs to feed back into `clawditor probe-firebase <project>`
- pick real Storage paths to verify with `clawditor probe-storage <bucket>`
- confirm or deny suspicions raised by `scan/network_security.json` and `scan/cert_pinning.json`

## Decision tree: which flags to use

Walk this top-down the first time you capture against an unfamiliar app:

1. **App shows an error screen / dialog on launch and never reaches its
   own UI.** Check the latest static run's `scan/manifest.json`:
   - `"has_pairip": true` (and/or `"pairip_hit"` is non-null) → add
     `--bypass-pairip`. The capture command already prints an advisory
     warning when this is the case.
   - Dialog says "Update Google Play services" / app exits silently right
     after splash → add `--bypass-gms`.
   - Also check `scan/network_security.json` — a strict per-app NSC
     `pin-set` overrides the system trust store; if present, Frida hooks
     are doing more work than usual and you should expect to need
     `trust-killer-mega` (i.e. `--bypass-gms` or `--bypass-pairip`) even
     for the TLS bypass alone, since the mega script's TLS hooks are
     identical to the canonical script's.

2. **App launches but `dynamic_capture.json` has zero or only proxy-CDN
   hosts** (no app-owned backend). SDK-pinning is wedging things:
   add `--ignore-hosts auto`. Custom regex if `auto` is too broad/narrow.

3. **App + emulator are visibly lagging** (chatty WebSocket / livestream /
   short-video). Add `--fast`. Combinable with everything else above.

4. **App is Flutter** (look for `libflutter.so` / `assets/flutter_assets/`
   in the static decompile). Add `--flutter`. The other flags don't apply
   in Flutter mode — its TLS bypass is BoringSSL-based and the GMS / Pairip
   classes aren't in play.

If a capture comes back empty and none of the above fits, jump to
`docs/dynamic-analysis.md` → "Known gotchas — read this if traffic isn't
flowing" before re-running with more flags.

## Common failure modes (and how to recover)

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `dynamic start` fails at `adb root` | AVD is the Play Store image | Recreate with `system-images;android-34;google_apis;<arch>`; rerun `setup-dynamic.sh`. |
| `mitmproxy CA not found at ~/.mitmproxy/...` | mitmproxy never launched | `mitmproxy` once interactively, press q, retry. |
| Capture JSON has 0 hosts | Proxy not set or NSC blocks user CA | Check `adb shell settings get global http_proxy`; inspect `scan/network_security.json` for `cleartextTrafficPermitted=false` plus per-app NSC pin-sets that override the system trust store. |
| App refuses to run / kills itself | Play Integrity / strong root detection | Out of scope for this skill — escalate to a physical device with Magisk + Shamiko + Zygisk-MagiskHide-Props. Document the gap in the run report. |
| Capture works but everything is plaintext-empty | App is on HTTP/3 (QUIC) | mitmproxy can't reliably MITM HTTP/3 yet; block UDP/443 on the host firewall to force fallback, or accept the gap. |

## Conventions when extending

- Modules under `src/clawditor/dynamic/` expose plain functions; they do not use the `run(ctx) -> dict` static-scanner contract.
- All subprocess calls go through `clawditor.utils.shell.run()` except detached long-running processes (emulator, mitmweb, frida-server, objection / frida pinning bypass), which go through `clawditor.dynamic._proc.spawn_detached`.
- PIDs live in `vendor/.pids/`; nothing should write a PID file elsewhere.
- Never import anything from `src/clawditor/dynamic/` into `scan/`, `probe/`, or `report/`. The static pipeline must remain runnable without any dynamic-phase code path being touched.
- Don't promote `mitmproxy` to a hard clawditor dependency in `pyproject.toml`. `ingest.py` imports it lazily; the test skips when it isn't available.

## Pointers

- Full user-facing guide: `docs/dynamic-analysis.md` — especially the
  "Known gotchas — read this if traffic isn't flowing" section (Android 14
  APEX cacerts; Chrome's bundled CAs; SDK-level pinning; Pairip; GMS gate;
  two-ADB-device gotchas).
- Module entry point: `src/clawditor/dynamic/__init__.py`
- CLI definitions: `src/clawditor/cli.py` (search for `dynamic_app`)
- Host bootstrap: `scripts/setup-dynamic.sh`
