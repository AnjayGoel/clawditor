# clawditor

Static + active-probe security audit pipeline for Android APKs.

Built to automate the analysis we did manually on a small set of Android apps from the Play Store — detect the cross-platform stack, decompile to the right layer (jadx for Java/Kotlin; hermes-dec for React Native; raw strings for native libs), then run passive scanners (apkleaks, trufflehog, custom regex, manifest analyzer) and active probes (Google API key restriction matrix, Firebase RTDB / Firestore / Storage rule checks).

Dynamic analysis (emulator + mitmproxy + Frida cert-pinning bypass) is now wired up — see [Dynamic analysis](#dynamic-analysis) below and the full guide in [`docs/dynamic-analysis.md`](docs/dynamic-analysis.md).

## Quick start

```bash
# One-time: install Python deps + external CLI tools
cd ~/Documents/auditor
uv sync                            # creates .venv, installs python deps
./scripts/bootstrap.sh             # installs adb, jadx, java, apkleaks, trufflehog, hermes-dec, downloads APKEditor.jar

# Run against a package on a connected device
uv run clawditor run com.example.app

# Run against a local APK
uv run clawditor run --apk /path/to/app.apk

# Skip the active-probe phase (offline / no internet)
uv run clawditor run --apk /path/to/app.apk --no-probe

# Skip the heavy jadx decompile (faster, smali-only)
uv run clawditor run --apk /path/to/app.apk --no-jadx

# Specify output directory (default: ./data/<package>_<timestamp>)
uv run clawditor run --apk /path/to/app.apk --out /tmp/myaudit
```

## What it produces

Per run, a directory containing:

```
data/<package>_<timestamp>/
├── run.json                   # input flags + run metadata
├── MANIFEST.md                # per-run navigation entry point
├── apk/                       # raw + universal APK
├── decompiled/
│   ├── jadx/                  # Java/Kotlin source
│   ├── smali/                 # APKEditor smali + decoded resources
│   ├── hermes/                # decompiled.js + disasm.hasm (RN apps only)
│   └── native/                # strings dumps of every .so file
├── scan/
│   ├── stack.json             # detected cross-platform framework signals
│   ├── manifest.json          # parsed AndroidManifest analysis
│   ├── secrets.json           # custom regex sweep (AIzaSy, JWT, AWS, AI keys, etc.)
│   ├── code_patterns.json     # WebView misconfig, crypto, SQL concat, TLS bypass
│   ├── apkleaks.json          # apkleaks regex sweep (when tool is installed)
│   ├── trufflehog.json        # trufflehog verified secrets (when tool is installed)
│   ├── sdk_inventory.json     # third-party SDK + version catalog
│   ├── network_security.json  # NSC XML analysis (cleartext, pin-sets, user CA)
│   ├── cert_pinning.json      # OkHttp / TrustKit / Conscrypt pinning detection
│   ├── intent_security.json   # exported component × unsafe extra-consumption x-ref
│   └── flutter.json           # Dart strings triage (Flutter apps only)
├── probe/                     # only when --probe (default on)
│   ├── google_keys.json       # restriction matrix per AIzaSy key (~36 services)
│   ├── firebase_rtdb.json     # RTDB unauth + anon-auth probes
│   ├── firebase_firestore.json # Firestore list / owner-read / structured-query probes
│   ├── firebase_storage.json  # Storage listing + 31 common-path enumeration
│   └── ai_keys.json           # OpenAI / Anthropic / xAI / GitHub / Razorpay / Mapbox / Sentry probes
└── reports/
    ├── SUMMARY.md             # executive summary (start here for humans)
    ├── findings.md            # ranked findings table (mirror of findings.json)
    ├── findings.json          # canonical structured findings (start here for agents)
    ├── deep-dive-guide.md     # per-category investigation guidance
    └── next-steps.md          # prioritized action checklist
```

Full JSON schemas + `jq` recipes for every file above: see [`docs/output-schemas.md`](docs/output-schemas.md).

## Architecture

```
clawditor/
├── cli.py                # typer entry point: `clawditor run …`
├── pipeline.py           # orchestrator
├── acquire/              # APK source: adb device pull, or local path
├── extract/              # universal-merge, APKEditor decode, jadx, hermes-dec, native strings
├── detect/               # cross-platform stack detection
├── scan/                 # passive analyzers (no network)
├── probe/                # active probes (network out → Google/Firebase)
├── report/               # markdown + json writers
└── dynamic/              # emulator + Frida + mitmproxy (stub; coming soon)
```

Each module is a thin wrapper that produces structured JSON; the report module joins them. Modules can be invoked individually for debugging:

```bash
uv run python -m clawditor.scan.apkleaks --apk app.apk --out scan/
uv run python -m clawditor.probe.google_keys --keys-file secrets.json --out probe/
```

## Modes

- **Default**: full pipeline (acquire → extract → scan → probe → report).
- **`--no-probe`**: skip all network-touching steps. Safe to run on any APK.
- **`--quick`**: skip jadx decompile (smali only). Skips hermes-dec disasm. ~10× faster.
- **`--probe-only`**: assume artifacts already exist; just re-run the active probes.

## External tools

Bootstrap installs / checks:

| Tool | Purpose | Install |
|---|---|---|
| `adb` | pull APKs from device | Android SDK platform-tools |
| `java` | run APKEditor.jar | OpenJDK 17+ |
| `jadx` | DEX → Java | `brew install jadx` |
| `apkleaks` | regex secrets/endpoints | `pipx install apkleaks` |
| `trufflehog` | verified secrets | `brew install trufflehog` |
| `hermes-dec` | RN Hermes bytecode → JS | `pipx install hermes-dec` |
| `APKEditor.jar` | merge splits + decode resources | downloaded to `vendor/` |
| `strings` | dump strings from native .so | system (binutils on Linux, built into macOS) |
| `xargs` | optional, for ad-hoc parallel batches outside `clawditor batch` | system (standard Unix) |

**Batch runs**: prefer `uv run clawditor batch --parallel 3` over hand-rolled shell parallelism. It handles concurrency, isolates output dirs, and surfaces per-package logs at `/tmp/clawditor-<package>.log`.

## Dynamic analysis

Spin up a rooted Pixel-7 emulator with the mitmproxy CA installed as a
system root, push frida-server + drive objection (or raw Frida with the NVISO
disable-flutter-tls script, for Flutter apps) to bypass SSL pinning, and
record decrypted HTTPS traffic into a per-app JSON summary that surfaces real
Firestore collection IDs, real Storage paths and real bearer tokens.

```bash
./scripts/setup-dynamic.sh                                  # one-time
uv run clawditor dynamic start                                # boot emu + mitm + frida
uv run clawditor dynamic capture com.example.app --duration 90
uv run clawditor dynamic capture com.flutter.app --flutter --duration 90
uv run clawditor dynamic stop
```

CLI subcommands:

| Command | Purpose |
| --- | --- |
| `clawditor dynamic setup` | runs `scripts/setup-dynamic.sh` (idempotent host bootstrap) |
| `clawditor dynamic status` | shows emulator / mitmweb / frida-server status |
| `clawditor dynamic start` | boots `clawditor-pixel7`, installs the mitm CA, starts mitmweb + frida-server |
| `clawditor dynamic capture <pkg>` | records one session → `data/dynamic-captures/<pkg>_<ts>/dynamic_capture.json` |
| `clawditor dynamic stop` | tears the whole stack down |

Full guide, image-choice rationale, Flutter notes, troubleshooting, Play
Integrity limits: [`docs/dynamic-analysis.md`](docs/dynamic-analysis.md).

## Authorized use only

This tool performs active probes against APIs referenced by the target app — Google API key restriction checks, Firebase rule probes, Storage path enumeration. Run it only against apps you own or have written permission to test.
