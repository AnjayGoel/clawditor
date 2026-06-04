# Extending the pipeline

How to add new scanners, probes, framework targets, finding types, and dynamic-analysis hooks. Each addition is a single new file plus a one-line registration.

## Add a passive scanner

1. Create `src/clawditor/scan/<name>.py`:

```python
"""One-line description."""
from __future__ import annotations
import json
from clawditor.config import RunContext
from clawditor.utils import logging as log


def run(ctx: RunContext) -> dict:
    # read from ctx.decompiled_dir / ...
    result = {}
    out = ctx.scan_dir / "<name>.json"
    out.write_text(json.dumps(result, indent=2))
    log.ok(f"<name>: ...")
    return result
```

2. Register in `src/clawditor/pipeline.py::_scan_phase`:

```python
from clawditor.scan import ..., <name>_run
<name>_run.run(ctx)
```

3. Map findings in `src/clawditor/report/findings.py`:

```python
def _from_<name>(ctx: RunContext) -> Iterator[dict]:
    d = _read_json(ctx.scan_dir / "<name>.json")
    ...
    yield _f("HIGH", "<name>", "title", "location", "evidence")
```

And register it in `collect()`.

## Add an active probe

Same shape, but in `src/clawditor/probe/`. Must respect `--no-probe` (no special handling required; the orchestrator gates the whole `_probe_phase`).

Conventions for probes:
- Never write to remote services.
- Use deliberately invalid args to confirm reachability without triggering side effects.
- Mint at most one anonymous Firebase identity per probe; reuse it via the shared `_try_mint_anon` helper.
- Time-bound every HTTP call (8-12s).
- Sleep 50-100ms between calls to be polite.

Add to `_probe_phase` and `findings.py` like a scanner.

## Add a framework target (cross-platform stack)

1. Add the signature to `src/clawditor/detect/stack.py::SIGNALS`:

```python
SIGNALS = {
    ...,
    "my_framework": ["assets/myframework/", "lib/arm64-v8a/libmf.so"],
}
```

2. If the framework has its own bytecode format (like Hermes), add an extractor in `src/clawditor/extract/<framework>.py` mirroring `extract/hermes.py`.

3. Wire it into `pipeline.py::_extract_phase`:

```python
if stack.get("my_framework"):
    my_framework.run(ctx)
```

## Add a new finding type

If a finding doesn't fit any existing category, **prefer to extend an existing one** rather than create a new category. New categories should be documented in `docs/finding-categories.md` and added to the report templates.

To extend an existing category:
- Modify the corresponding `_from_<category>` function in `report/findings.py`.
- Add severity rules / action hints in `report/next_steps.py::_action_hints`.

## Add a CLI subcommand

Extend `src/clawditor/cli.py`:

```python
@app.command(name="my-cmd")
def my_cmd(arg: str = typer.Argument(...)):
    """Description shown in --help."""
    ...
```

If the command operates on an existing run, use `_resolve_run(arg)` to support both names and absolute paths.

## Add a Claude skill

`.claude/skills/<name>/SKILL.md` with frontmatter:

```yaml
---
name: <name>
description: When to use this skill. The description must contain the trigger keywords Claude looks for.
---
```

Skills are meta-instructions; they shouldn't introduce capabilities — they should explain when to invoke existing pipeline functions / CLI subcommands.

## Wire in the dynamic phase (future)

Reserved at `src/clawditor/dynamic/`. The orchestrator hook will be in `pipeline.py`:

```python
def run(ctx: RunContext) -> None:
    ...
    if not ctx.no_probe:
        _probe_phase(ctx)
    if ctx.dynamic:                       # new flag
        from clawditor.dynamic import emulator, frida, mitm
        emulator.start(ctx)
        frida.bypass_pinning(ctx)
        mitm.capture(ctx)
    _report_phase(ctx)
```

Dynamic modules:
- Must be skippable (not all environments have an emulator).
- Should write captured artifacts to `ctx.out_dir / "dynamic"`.
- Should feed harvested data into static probes (e.g. real Firestore collection IDs into `probe/firebase_firestore.py`) rather than duplicate the rule-check logic.

## Conventions

- Keep modules under 200 lines.
- No global state. Pass `RunContext` everywhere.
- All subprocess calls through `clawditor.utils.shell.run()` (timeout + error normalization).
- Logging via `clawditor.utils.logging.console` / `log.info` / `log.ok` / `log.warn` / `log.err`.
- Output goes to `ctx.out_dir`. Never write outside the run dir.
