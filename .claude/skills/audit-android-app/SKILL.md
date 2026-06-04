---
name: audit-android-app
description: Use to run a full static + active-probe security audit on an Android app. Accepts a package name (auto-pulls APK from connected ADB device) or a path to a local APK. Produces decompiled artifacts plus markdown + JSON reports. Triggers when the user asks to "audit an Android app", "scan APK for vulnerabilities", "check Firebase rules for an APK", "run clawditor on …", or names a package like com.example.app in a security context.
---

# audit-android-app

Run the `clawditor` pipeline at `~/Documents/auditor/` against a target Android app.

## When to invoke

- "Audit `com.example.app`"
- "Run a security scan on this APK: …"
- "Check what API keys are in /path/to/app.apk"
- "Find Firebase misconfigurations in this app"

## How to invoke

The pipeline lives at `~/Documents/auditor/`. Always `cd` there first so `uv run` picks up the project.

### Package name (preferred when device is connected)

```bash
cd ~/Documents/auditor
uv run clawditor run <package.name>
```

This will:
1. Find the package on connected ADB devices.
2. Pull every split APK to `data/<pkg>_<ts>/apk/`.
3. Merge to universal APK via APKEditor.
4. Run the rest of the pipeline.

### Local APK path

```bash
cd ~/Documents/auditor
uv run clawditor run --apk /absolute/path/to/app.apk
```

### Useful flags

| Flag | Effect |
|---|---|
| `--no-probe` | Skip active network probes (offline-only). Use when the user explicitly says "no network" or the environment is air-gapped. |
| `--quick` | Skip jadx decompile + hermes disassembly. ~10× faster but loses Java source. |
| `--no-jadx` | Same as `--quick` for the Java decompile only. |
| `--probe-only` | Re-run only the active probes against an existing `data/<run>/` directory. Pass `--out` to specify which. |
| `--out PATH` | Output directory. Default: `data/<pkg>_<timestamp>` under the clawditor project. |

## What to report back to the user

After the run completes, show:

1. The path to the run directory (e.g. `~/Documents/auditor/data/com.example.app_20260523-1605/`).
2. The path to `reports/SUMMARY.md` — open this for the user.
3. The top 3 findings by severity (read from `reports/findings.json`).
4. Counts: total findings by severity.

If the run fails, surface the failing stage from the log output. Common failures:
- `adb` not finding the package → user needs to install it on the device first, or pass `--apk`.
- `APKEditor.jar` missing → run `./scripts/bootstrap.sh`.
- Probes timing out → suggest re-running with `--probe-only` later.

## Authorization

Active probes (`--probe`, default) call Google / Firebase APIs against the target app's project. Only run against apps the user owns or has explicit written permission to test. If the user is auditing a third-party app for the first time, ask whether to use `--no-probe` first.

## Out of scope (today)

- APK download from public stores. If no device is connected and no `--apk` path is given, the pipeline errors out. Don't try to scrape APKPure / APKMirror.
- Dynamic analysis (emulator, Frida, mitmproxy). The `dynamic/` module is a stub; do not invoke `--dynamic`.

## Don't invoke for

- iOS apps (this is Android-only).
- Web app security audits.
- Reviewing already-decompiled code that didn't come through this pipeline (use general code-review tools).
