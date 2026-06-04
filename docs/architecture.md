# Architecture

A linear pipeline that turns an APK into a markdown report. Each stage writes JSON to a known location; later stages and the report module read from those JSONs.

```
   ┌─────────┐    ┌─────────┐    ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐
   │ acquire │ →  │ extract │ →  │ detect │ →  │  scan  │ →  │ probe  │ →  │ report │
   └─────────┘    └─────────┘    └────────┘    └────────┘    └────────┘    └────────┘
       ↓              ↓              ↓             ↓             ↓             ↓
    apk/           decompiled/   scan/stack    scan/*.json   probe/*.json   reports/*
```

## Module contract

Every module exposes a single `run(ctx: RunContext, ...) -> dict | None` function. It:

- reads ONLY from paths on the `RunContext` (no globals, no env)
- writes its primary output to **exactly one** well-named JSON at a well-known path:
  - scan modules → `<run>/scan/<name>.json` (e.g. `manifest.json`, `secrets.json`, `code_patterns.json`)
  - probe modules → `<run>/probe/<name>.json` (e.g. `google_keys.json`, `firebase_rtdb.json`)
  - `clawditor.config.RunContext.write_meta` → `<run>/run.json`
- returns the same data it wrote (lets the orchestrator do simple chaining)
- raises on hard failure, but logs and returns `{}` for "external tool missing" / "no input to work on" cases (so the rest of the pipeline still runs). When that happens the JSON file is typically NOT written — the report layer tolerates absence.

The full schema of every output JSON, plus real-shaped examples and `jq` recipes for each, lives in **`docs/output-schemas.md`**. Reach for that doc before consuming any pipeline output.

This means a single module can be invoked standalone for debugging:

```bash
uv run python -m clawditor.scan.apkleaks_run --apk ... --out ...
```

(Standalone invocation harness is a small addition per module — not required by the contract, but encouraged for slow scanners.)

## RunContext

`clawditor.config.RunContext` is a frozen dataclass passed through every stage. Holds:
- `out_dir` — root of the run directory
- properties for every sub-directory (`apk_dir`, `scan_dir`, `probe_dir`, etc.)
- the runtime flags (`no_probe`, `quick`, `no_jadx`, `probe_only`)
- helper methods to write `run.json` metadata

Modules should construct paths via the context properties, never hardcode subdirs.

## External tools

| Tool | Used by | Required? |
|---|---|---|
| `adb` | `acquire/acquire.py` | Only if pulling from device |
| `java` | `acquire/acquire.py` (split merge), `extract/decompile.py` (APKEditor) | Yes |
| `APKEditor.jar` | as above | Yes (in `vendor/` or `APKEDITOR_JAR` env) |
| `jadx` | `extract/decompile.py` | Optional (`--quick`/`--no-jadx` skips) |
| `hbc-decompiler`, `hbc-disassembler` | `extract/hermes.py` | Only if app is React Native |
| `apkleaks` | `scan/apkleaks_run.py` | Optional (module logs warn and skips) |
| `trufflehog` | `scan/trufflehog_run.py` | Optional |
| `strings` | `extract/native.py`, hand calls in `scan/secrets.py` | Optional |
| `rg` (ripgrep) | `scan/code_patterns.py` | Optional (falls back to grep) |

All external calls go through `clawditor.utils.shell.run()` — never `subprocess.run` directly.

## Active probes

The `probe/` modules issue real HTTP requests to Google / Firebase. They:

- use deliberately invalid params to confirm reachability without triggering side effects (no real SMS sent, no email delivered)
- never write to remote services
- read remote services only at the rule boundary (1 doc read, 1 list, 1 structured query — not exhaustive enumeration)
- mint a single anonymous Firebase identity per run when needed; the token is scoped to the run and never persisted

See `probe/google_keys.py` for the 36-service matrix and the rationale for each.

## Reports

`report/markdown.py` is the orchestrator for the reporting phase. It calls:

- `findings.collect(ctx)` — joins every JSON into a uniform `[{severity, category, title, location, evidence}, ...]` list using `findings.py:FINDING_RULES`-style logic.
- `markdown._write_findings_md` + `_write_summary` — the human-readable outputs.
- `manifest.run` — the per-run entry-point file (`MANIFEST.md`).
- `deep_dive_guide.run` — agent guidance (`reports/deep-dive-guide.md`).
- `next_steps.run` — actionable checklist (`reports/next-steps.md`).

## Dynamic phase

Reserved at `src/clawditor/dynamic/`. Future work — emulator orchestration, Frida cert-pinning bypass, mitmproxy traffic capture. The static pipeline must run without anything from this package.
