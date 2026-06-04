# Clawditor — Claude operational notes

You are working on an Android APK security audit pipeline. This file briefs you on how the pipeline is laid out, the conventions to follow when modifying it, and how to drive it end-to-end.

## What this is

`clawditor` automates the static + active-probe audit we previously ran by hand on a small set of Android consumer apps from the Play Store. The pipeline:

1. Acquires the APK (pulls from a connected ADB device, or takes a local path).
2. Decompiles to the appropriate layer for the stack — jadx for native Kotlin/Java + Compose Multiplatform; hermes-dec for React Native bytecode; raw strings dump for native `.so` libraries.
3. Runs passive scanners: apkleaks, trufflehog (with provider verification), custom regex sweep (AIzaSy keys, JWTs, OAuth client IDs), AndroidManifest analyzer (exported components, cleartext traffic, backup rules), code-pattern grep (WebView `setAllowFileAccessFromFileURLs` + `addJavascriptInterface`, hardcoded crypto keys, RawQuery SQL).
4. Runs active probes: Google API key restriction matrix across ~35 services, Firebase RTDB unauth + authenticated read, Firestore collection/structured-query probes, Storage bucket path enumeration.
5. Writes a markdown executive summary plus per-section JSON.

Dynamic analysis (emulator + mitmproxy + Frida cert-pinning bypass) lives at `src/clawditor/dynamic/` and is wired up as a `clawditor dynamic …` CLI group. See the "Dynamic phase" section below and `docs/dynamic-analysis.md` for the full picture.

## How to run

```bash
cd ~/Documents/auditor
uv sync                                   # one time
./scripts/bootstrap.sh                    # one time: external tools
uv run clawditor run com.example.app        # pulls from device
uv run clawditor run --apk /path/app.apk    # local APK
```

See `README.md` for all flags.

## Layout & conventions

- Source under `src/clawditor/<module>/`. Each module is small (~50-200 lines) and exposes a `run(...) -> dict` function plus a `__main__` so it can be invoked standalone for debugging.
- All inter-module communication is via JSON files written to the run directory (`data/<package>_<ts>/`). No global state, no hidden coupling. Each module reads what it needs from the run dir and writes its own JSON.
- The orchestrator (`pipeline.py`) is the only thing that knows the run sequence. Don't add cross-module imports between scanners/probes.
- External CLI tools (adb, jadx, java, trufflehog, apkleaks, hermes-dec) are called via `clawditor.utils.shell.run()`. That wrapper does timeout, capture, error normalization. Do not call `subprocess` directly.
- Network I/O uses `httpx` synchronously. No async unless absolutely needed.
- Logging via `rich.console.Console` from `clawditor.utils.logging`. Stage banners in cyan, findings in yellow, errors in red.

## What to do when extending

**Add a new passive scanner** → drop a file in `src/clawditor/scan/<name>.py` with a `run(decompiled_dir: Path, out: Path) -> dict` function, register it in `pipeline.py:SCAN_STEPS`.

**Add a new active probe** → drop in `src/clawditor/probe/<name>.py` with the same signature. Register in `pipeline.py:PROBE_STEPS`. Probes must respect `--no-probe`.

**Add a new framework target** → extend `src/clawditor/detect/stack.py` with the signature (file path / lib name pattern) and the post-detection extractor module if special handling is needed (like `extract/hermes.py` for React Native).

**Add a new finding type to reports** → extend `src/clawditor/report/findings.py:FINDING_RULES` with a (severity, category, source-json, jq-path-or-callable) entry.

**Touch the dynamic stub** → reserve `src/clawditor/dynamic/` namespace. Don't import dynamic modules from static modules; the dynamic phase is opt-in via a future `--dynamic` flag.

## Conventions for the active probes

- Every probe ends every API call with a deliberately invalid argument that triggers an app-level validation error before any user-visible side effect (no SMS sent, no email delivered, no data written). When you add a new probe, do the same.
- Probes report `REACHED_ENDPOINT` when the call passes all GCP-side gates and is rejected only by app-level validation — that's the gold-standard "this endpoint is exposed even though we didn't actually trigger the action" signal.
- For Firebase Identity Toolkit, the methods to test (and what each reveals when reachable) are documented in `src/clawditor/probe/google_keys.py:IDENTITY_METHODS`. Match the existing pattern.

## Dynamic phase

Lives at `src/clawditor/dynamic/`. Six small modules:

- `emulator.py` — boot the `clawditor-pixel7` AVD (Pixel 7, API 34, **google_apis** image — NOT Play Store, which refuses `adb root`), wait for boot, `adb root + remount`, push the mitmproxy CA into `/system/etc/security/cacerts/<hash>.0`, reboot once so it's trusted, set the global HTTP proxy to `10.0.2.2:8080`.
- `mitm.py` — start/stop `mitmweb` as a detached background process, surface the CA cert path.
- `frida.py` — push the right-arch `frida-server` binary to `/data/local/tmp/`, launch it as root, and either drive `objection` (`android sslpinning disable; android root disable`) or — for Flutter apps — raw `frida` with the bundled NVISO `disable-flutter-tls.js` script.
- `capture.py` — orchestrate one capture session per app: open a fresh `flows.mitm`, attach pinning bypass, optionally drive UI via `adb shell input …` commands, sleep, stop, ingest.
- `ingest.py` — read the mitm flow file (via `mitmproxy.io` Python API), emit `dynamic_capture.json` with hosts, endpoints, real Firestore collection IDs, real Storage paths, auth-header counts, JWT counts in response bodies.
- `_proc.py` — internal helper for spawning detached long-running processes and tracking PIDs in `vendor/.pids/`.

Unlike scanners and probes, these don't follow the `run(ctx) -> dict` contract — they're plain functions invoked by the `clawditor dynamic …` CLI group (`setup`, `status`, `start`, `capture`, `stop`).

Host bootstrap is `scripts/setup-dynamic.sh` (idempotent). It installs `mitmproxy` / `objection` / `frida-tools`, the Android SDK packages, creates the AVD, downloads the architecture-matched `frida-server` to `vendor/`, and fetches the disable-flutter-tls script.

Gotchas worth remembering when extending this:

- **Don't add `mitmproxy` as a hard clawditor dep.** It's an external CLI. `ingest.py` imports `mitmproxy.io` lazily and raises a clear error if it's missing. The test (`tests/test_unit_dynamic_ingest.py`) skips on `ImportError`.
- **The CA install reboots the emulator.** Sequencing matters in `dynamic start`: boot → root → remount → push CA → reboot → wait again → root again → set proxy → mitm → frida.
- **The static pipeline must still run without anything from `dynamic/`.** No import from `scan/`, `probe/`, `report/` into `dynamic/`. The eventual feedback path (real Firestore collections back into `probe/firebase_firestore.py`) goes through reading `dynamic_capture.json` from the run dir, not Python imports.

## What NOT to do

- Don't add a step that writes to the target's Firestore / Storage / RTDB. Reading only.
- Don't add a real SMS/email send. The probes for `sendVerificationCode` and `sendOobCode` use deliberately invalid params; don't change that.
- Don't add a step that exfiltrates discovered data to a third-party service. All output is local-only.
- Don't `subprocess.run` directly — go through `clawditor.utils.shell`. Otherwise the timeout / error handling won't fire.
- Don't introduce a global config singleton. Pass the `RunContext` through.

## Tested environments

Built on macOS (Darwin) + zsh/fish. Linux should work; external tools and paths are different. Windows untested.

## Where to find what

- **Per-file JSON schemas** — `docs/output-schemas.md`. Canonical reference for every JSON the pipeline writes (scan/, probe/, reports/) including real-shaped examples and `jq` recipes. Read this first when consuming run output.
- **Architecture + module contract** — `docs/architecture.md`. The pipeline shape, the `RunContext`, and the module write-one-JSON contract.
- **Finding category taxonomy** — `docs/finding-categories.md`. What each `category` value in `findings.json` means and its severity range.
- **Probe verdict taxonomy** — `docs/probe-verdicts.md`. What `LEAKED`, `SUCCESS`, `REACHED_ERR`, `BLOCKED_ANDROID`, etc. mean.
- **Extending the pipeline** — `docs/extending.md`.
- **Per-run navigation** — `<run>/MANIFEST.md` (entry point) and `<run>/reports/deep-dive-guide.md` (per-category drill-in).

## Vendor-namespace demotion

Many regex-based scanners match string literals inside third-party SDK code (Glide, Stripe, Firebase, gRPC, …) rather than the app's own code. `clawditor.utils.vendor.is_vendor(path)` and `split_vendor(items, file_key="file")` partition findings into app-owned vs vendor. `report/findings.py` uses `split_vendor` in `_from_secrets` and `_from_code_patterns` and **demotes** vendor matches by one severity tier (`CRITICAL→MEDIUM`, `HIGH→LOW`, `MEDIUM→LOW`, `LOW→INFO`). Any finding whose title contains `vendor SDK hit` or `vendor SDK code` is demoted-and-tagged this way — treat as informational unless context suggests otherwise. To tweak which prefixes count as vendor, edit `VENDOR_PREFIXES` in `src/clawditor/utils/vendor.py`.

## Reference reports (from the manual audit this pipeline replaces)

The pipeline's report format descends from a set of hand-written audit reports
(an executive summary across several apps, a Google-key restriction matrix, a
leaked-key abuse-vector deep dive, per-package reports, and an apkleaks report).
Those source documents are kept out of this repo.

When extending the report module, mirror their structure (one-paragraph app summary → findings table with severity / category / file:line / evidence → 3-6 line impact for High/Critical → notes/limitations section).
