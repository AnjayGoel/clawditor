"""CLI entry point: `uv run clawditor …`."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from clawditor.config import RunContext
from clawditor.pipeline import run as run_pipeline
from clawditor.utils.paths import default_runs_dir

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Android APK security audit pipeline.")
console = Console()

dynamic_app = typer.Typer(no_args_is_help=True, help="Dynamic analysis: emulator + mitmproxy + Frida")
app.add_typer(dynamic_app, name="dynamic")


# ─────────────────── primary commands ───────────────────

@app.command()
def run(
    package: str = typer.Argument(None, help="Package name to pull via adb. Omit if using --apk."),
    apk: Path = typer.Option(None, "--apk", help="Path to a local APK (or directory of split APKs)."),
    out: Path = typer.Option(None, "--out", help="Output directory. Default: data/<pkg>_<ts>/."),
    no_probe: bool = typer.Option(False, "--no-probe", help="Skip active network probes."),
    quick: bool = typer.Option(False, "--quick", help="Skip jadx + hermes disasm (faster)."),
    no_jadx: bool = typer.Option(False, "--no-jadx", help="Skip jadx decompile only."),
    probe_only: bool = typer.Option(False, "--probe-only", help="Re-run only probes on existing run dir (requires --out)."),
):
    """Run the full pipeline (acquire → extract → scan → probe → report)."""
    if not package and not apk:
        raise typer.BadParameter("must provide either a package name or --apk")
    if probe_only and not out:
        raise typer.BadParameter("--probe-only requires --out pointing at an existing run dir")
    ctx = RunContext.for_run(
        package=package, apk=apk, out=out,
        no_probe=no_probe, quick=quick, no_jadx=no_jadx, probe_only=probe_only,
    )
    run_pipeline(ctx)


@app.command()
def batch(
    apk_dir: Path = typer.Option(Path("working"), "--apk-dir", help="Directory of <package>/base.apk subdirs (default: ./working)."),
    parallel: int = typer.Option(3, "--parallel", "-j", help="Max concurrent pipelines."),
    quick: bool = typer.Option(True, "--quick/--no-quick", help="Pass --quick to each run."),
    no_probe: bool = typer.Option(False, "--no-probe"),
    suffix: str = typer.Option("batch", "--suffix", help="Run-dir suffix to disambiguate batches."),
):
    """Run the pipeline against every package directory under --apk-dir, in parallel.

    Each package is run as a separate pipeline; the runs are independent.
    """
    import concurrent.futures as cf
    import subprocess
    pkgs = sorted([p for p in apk_dir.iterdir() if p.is_dir() and any(p.glob("*.apk"))])
    if not pkgs:
        console.print(f"[yellow]no package directories under {apk_dir}[/]")
        raise typer.Exit(1)
    console.print(f"running pipeline on {len(pkgs)} package(s) with --parallel={parallel}")
    flags = []
    if quick: flags.append("--quick")
    if no_probe: flags.append("--no-probe")

    def _run_one(pkg_dir: Path) -> tuple[Path, int]:
        out = Path("data") / f"{pkg_dir.name}_{suffix}"
        cmd = ["uv", "run", "clawditor", "run", "--apk", str(pkg_dir), "--out", str(out), *flags]
        log_file = Path("/tmp") / f"clawditor-{pkg_dir.name}.log"
        with log_file.open("w") as f:
            r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
        return pkg_dir, r.returncode

    with cf.ThreadPoolExecutor(max_workers=parallel) as ex:
        futs = {ex.submit(_run_one, p): p for p in pkgs}
        for fut in cf.as_completed(futs):
            pkg_dir, rc = fut.result()
            mark = "[green]✓[/]" if rc == 0 else "[red]✗[/]"
            console.print(f"  {mark} {pkg_dir.name} (log: /tmp/clawditor-{pkg_dir.name}.log)")
    console.print(f"\nDone. Inspect with: `uv run clawditor list`")


@app.command()
def check():
    """Check that external tools are installed."""
    from clawditor.utils.shell import which
    from clawditor.utils.paths import apkeditor_jar
    rows = [
        ("adb", which("adb")),
        ("java", which("java")),
        ("jadx", which("jadx")),
        ("apkleaks", which("apkleaks")),
        ("trufflehog", which("trufflehog")),
        ("hbc-decompiler", which("hbc-decompiler")),
        ("APKEditor.jar", str(apkeditor_jar()) if apkeditor_jar().exists() else None),
    ]
    for name, p in rows:
        mark = "[green]✓[/]" if p else "[red]✗[/]"
        console.print(f"  {mark} {name:<18} {p or '(missing)'}")
    if any(p is None for _, p in rows):
        console.print("\nRun ./scripts/bootstrap.sh to install missing tools.")
        raise typer.Exit(1)


@app.command()
def complete(
    run_id: str = typer.Argument(..., help="Existing run dir name or absolute path."),
    no_probe: bool = typer.Option(False, "--no-probe", help="Skip probe modules."),
    force: bool = typer.Option(False, "--force", help="Re-run modules even if their JSON exists."),
):
    """Fill in missing scan/probe outputs on an existing run dir, then rebuild reports.

    Only runs the modules whose JSON output is missing — does NOT redo the slow
    decompile / apkleaks / trufflehog phases unless those JSONs are also missing.
    Idempotent.
    """
    from clawditor.config import RunContext
    run_dir = _resolve_run(run_id)
    if not (run_dir / "decompiled").exists():
        console.print(f"[red]No decompiled/ in {run_dir.name}. Run `clawditor run` from scratch.[/]")
        raise typer.Exit(1)
    ctx = RunContext(package=None, apk_input=None, out_dir=run_dir)
    ctx.ensure_dirs()
    scan_mods = [
        ("manifest", "scan/manifest.json"),
        ("secrets", "scan/secrets.json"),
        ("jwt_analyzer", "scan/jwt_analyzer.json"),
        ("applinks", "scan/applinks.json"),
        ("code_patterns", "scan/code_patterns.json"),
        ("intent_security", "scan/intent_security.json"),
        ("sdk_inventory", "scan/sdk_inventory.json"),
        ("network_security", "scan/network_security.json"),
        ("cert_pinning", "scan/cert_pinning.json"),
        ("payment_sdk", "scan/payment_sdk.json"),
        ("asset_inspector", "scan/asset_inspector.json"),
        ("build_leaks", "scan/build_leaks.json"),
        ("privacy", "scan/privacy.json"),
    ]
    probe_mods = [
        ("google_keys", "probe/google_keys.json"),
        ("firebase_rtdb", "probe/firebase_rtdb.json"),
        ("firebase_firestore", "probe/firebase_firestore.json"),
        ("firebase_storage", "probe/firebase_storage.json"),
        ("ai_keys", "probe/ai_keys.json"),
        ("s3_buckets", "probe/s3_buckets.json"),
    ]
    import importlib
    ran: list[str] = []
    skipped: list[str] = []
    for mod_name, json_path in scan_mods:
        if not force and (run_dir / json_path).exists():
            skipped.append(f"s/{mod_name}"); continue
        try:
            mod = importlib.import_module(f"clawditor.scan.{mod_name}")
            mod.run(ctx); ran.append(f"s/{mod_name}")
        except Exception as e:
            console.print(f"  [red]✗[/] scan/{mod_name}: {e}")
    if not no_probe:
        for mod_name, json_path in probe_mods:
            if not force and (run_dir / json_path).exists():
                skipped.append(f"p/{mod_name}"); continue
            try:
                mod = importlib.import_module(f"clawditor.probe.{mod_name}")
                mod.run(ctx); ran.append(f"p/{mod_name}")
            except Exception as e:
                console.print(f"  [red]✗[/] probe/{mod_name}: {e}")
    # Rebuild report
    from clawditor.report import markdown as md
    md.run(ctx)
    console.print(f"\n[green]✓[/] {run_dir.name}: ran {len(ran)} | skipped {len(skipped)} (already present)")
    if ran:
        console.print(f"   ran: {' '.join(ran)}")


# ─────────────────── inspection commands ───────────────────

@app.command(name="list")
def list_runs(
    runs_dir: Path = typer.Option(None, "--dir", help="Override the runs directory."),
):
    """List all completed runs in the data/ directory."""
    base = runs_dir or default_runs_dir()
    if not base.exists():
        console.print(f"[yellow]No runs directory yet at {base}.[/]")
        console.print("[dim]Run `clawditor run <package>` or `clawditor run --apk <path>` to create one.[/]")
        raise typer.Exit(0)
    t = Table(title=f"Runs in {base}")
    t.add_column("Run")
    t.add_column("Started")
    t.add_column("Target")
    t.add_column("Findings")
    rows = 0
    for d in sorted(base.glob("*"), reverse=True):
        meta_p = d / "run.json"
        fnd_p = d / "reports" / "findings.json"
        if not meta_p.exists():
            continue
        meta = json.loads(meta_p.read_text())
        target = meta.get("package") or (Path(meta.get("apk_input") or "?").name)
        findings_summary = "_no report_"
        if fnd_p.exists():
            findings = json.loads(fnd_p.read_text())
            from collections import Counter
            c = Counter(f["severity"] for f in findings)
            findings_summary = " ".join(f"{k[0]}:{v}" for k, v in c.most_common())
        t.add_row(d.name, meta.get("started_at", "?"), target, findings_summary)
        rows += 1
    if rows == 0:
        console.print(f"[yellow]No completed runs in {base}.[/]")
        raise typer.Exit(0)
    console.print(t)


@app.command()
def show(
    run_id: str = typer.Argument(..., help="Run directory name or absolute path."),
    keys: bool = typer.Option(False, "--keys", help="Show Google key probe matrix."),
    firebase: bool = typer.Option(False, "--firebase", help="Show Firebase RTDB+Firestore+Storage results."),
    findings: bool = typer.Option(False, "--findings", help="Show findings table only."),
    raw: bool = typer.Option(False, "--raw", help="Print raw findings.json."),
):
    """Show the summary or focused sections of an existing run."""
    run_dir = _resolve_run(run_id)
    if findings:
        _show_findings(run_dir)
    elif keys:
        _show_keys(run_dir)
    elif firebase:
        _show_firebase(run_dir)
    elif raw:
        p = run_dir / "reports" / "findings.json"
        console.print(p.read_text() if p.exists() else "_no findings.json_")
    else:
        p = run_dir / "reports" / "SUMMARY.md"
        console.print(p.read_text() if p.exists() else "_no SUMMARY.md_")


@app.command()
def inspect(
    run_id: str = typer.Argument(..., help="Run directory name or absolute path."),
    finding: int = typer.Option(None, "--finding", help="Index in findings.json (0-based)."),
    severity: str = typer.Option(None, "--severity", help="Filter: CRITICAL/HIGH/MEDIUM/LOW/INFO."),
    category: str = typer.Option(None, "--category", help="Filter by finding category."),
    grep: str = typer.Option(None, "--grep", help="Substring match in title/evidence."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable NDJSON output."),
    limit: int = typer.Option(20, "--limit", help="Max findings to print (default 20)."),
):
    """Deep-dive a single finding from an existing run."""
    from clawditor.report import inspect as _ins
    run_dir = _resolve_run(run_id)
    fp = run_dir / "reports" / "findings.json"
    if not fp.exists():
        console.print(f"[red]no findings.json at {fp}[/]")
        raise typer.Exit(1)
    findings = json.loads(fp.read_text())
    picked = _ins.select(
        findings,
        finding=finding, severity=severity, category=category, grep=grep, limit=limit,
    )
    if not picked:
        console.print("[yellow]no findings matched[/]")
        raise typer.Exit(0)
    import sys
    for i, f in enumerate(picked):
        if json_out:
            # Bypass rich so the JSON isn't line-wrapped or styled.
            sys.stdout.write(json.dumps(_ins.render_json(run_dir, f)) + "\n")
        else:
            if i > 0:
                console.rule(style="dim")
            _ins.render_rich(console, run_dir, f)


@app.command()
def compare(
    run_a: str = typer.Argument(..., help="First run (directory name or absolute path)."),
    run_b: str = typer.Argument(..., help="Second run (directory name or absolute path)."),
    by: str = typer.Option(None, "--by", help="Grouping mode for the findings table. Currently supports: category."),
    shared: bool = typer.Option(False, "--shared", help="Only print findings present in both."),
    only_a: bool = typer.Option(False, "--only-a", help="Only print findings unique to A."),
    only_b: bool = typer.Option(False, "--only-b", help="Only print findings unique to B."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
):
    """Diff two existing pipeline runs (findings + SDKs + endpoints + API keys)."""
    from clawditor.report import compare as _cmp
    if sum([shared, only_a, only_b]) > 1:
        raise typer.BadParameter("--shared, --only-a, --only-b are mutually exclusive")
    a_dir = _resolve_run(run_a)
    b_dir = _resolve_run(run_b)
    result = _cmp.compute(a_dir, b_dir)
    if json_out:
        # Use sys.stdout directly so rich doesn't soft-wrap the document.
        import sys
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return
    _cmp.render_rich(
        console, result,
        only_shared=shared, only_a=only_a, only_b=only_b,
        by_category=(by == "category"),
    )


# ─────────────────── standalone probe commands ───────────────────

@app.command(name="probe-key")
def probe_key(key: str = typer.Argument(..., help="An AIzaSy* Google API key.")):
    """Run the full restriction matrix against a single API key."""
    from clawditor.probe.google_keys import services
    from clawditor.probe._http import call, classify
    import time
    if not key.startswith("AIzaSy"):
        raise typer.BadParameter("key must start with AIzaSy")
    t = Table(title=f"Key: {key}")
    t.add_column("Service"); t.add_column("Verdict"); t.add_column("Detail", max_width=70)
    counts: dict[str, int] = {}
    for name, method, url, body in services(key):
        st, b = call(method, url, body)
        v, d = classify(st, b)
        counts[v.split("(")[0]] = counts.get(v.split("(")[0], 0) + 1
        color = _verdict_color(v)
        t.add_row(name, f"[{color}]{v}[/]", d[:80])
        time.sleep(0.1)
    console.print(t)
    console.print("\nVerdict counts: " + " ".join(f"[{_verdict_color(k)}]{k}[/]:{v}" for k, v in sorted(counts.items(), key=lambda x: -x[1])))


@app.command(name="probe-firebase")
def probe_firebase(project: str = typer.Argument(..., help="Firebase project ID (the slug before `.firebaseio.com` or `.appspot.com`).")):
    """Probe RTDB + Firestore + Storage for a single Firebase project (no key needed for unauth tests)."""
    from clawditor.probe._http import call
    console.rule(f"[cyan]Firebase project: {project}[/]")

    console.print("\n[bold]RTDB[/] (unauthenticated)")
    for path in ["", "users", "config", "settings"]:
        url = f"https://{project}.firebaseio.com/{path}.json?shallow=true"
        st, body = call("GET", url, timeout=8)
        console.print(f"  /{path:<10} HTTP {st}  {body[:120].strip()}")

    console.print("\n[bold]Firestore[/] (unauthenticated → expect 401)")
    url = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/users?pageSize=1"
    st, body = call("GET", url, timeout=8)
    console.print(f"  /users  HTTP {st}  {body[:120].strip()}")

    console.print("\n[bold]Storage[/] (default bucket name)")
    for bucket in (f"{project}.appspot.com", f"{project}.firebasestorage.app"):
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1"
        st, body = call("GET", url, timeout=8)
        console.print(f"  {bucket}  HTTP {st}  {body[:120].strip()}")


@app.command(name="probe-storage")
def probe_storage(bucket: str = typer.Argument(..., help="Firebase Storage bucket, e.g. mybucket.appspot.com.")):
    """Enumerate common file paths against a Firebase Storage bucket."""
    from clawditor.probe.firebase_storage import _probe_bucket
    res = _probe_bucket(bucket)
    console.print(f"\nListing: HTTP {res['listing']['http']}  {res['listing']['snippet']}")
    console.print(f"GCS listing: HTTP {res['gcs_listing']['http']}  {res['gcs_listing']['snippet']}")
    console.print(f"\nPublic paths: {res['publicly_readable_paths'] or '_none_'}")
    interesting = {p: r for p, r in res["path_probe"].items() if r["http"] not in (403, 404)}
    if interesting:
        console.print("\nNon-403/404 responses (worth a look):")
        for p, r in interesting.items():
            console.print(f"  HTTP {r['http']:<4}  {p:<32}  {r['snippet']}")


# ─────────────────── helpers ───────────────────

def _resolve_run(run_id: str) -> Path:
    p = Path(run_id)
    if p.exists() and p.is_dir():
        return p
    candidate = default_runs_dir() / run_id
    if candidate.exists():
        return candidate
    raise typer.BadParameter(f"run not found: {run_id} (tried {candidate})")


def _show_findings(run_dir: Path) -> None:
    p = run_dir / "reports" / "findings.json"
    if not p.exists():
        console.print("[red]no findings.json[/]")
        raise typer.Exit(1)
    findings = json.loads(p.read_text())
    t = Table()
    t.add_column("Sev"); t.add_column("Cat"); t.add_column("Title"); t.add_column("Location", max_width=50)
    for f in findings:
        t.add_row(f["severity"], f["category"], f["title"], f["location"])
    console.print(t)


def _show_keys(run_dir: Path) -> None:
    p = run_dir / "probe" / "google_keys.json"
    if not p.exists():
        console.print("[red]no google_keys.json[/]")
        raise typer.Exit(1)
    data = json.loads(p.read_text())
    for k, info in data.items():
        t = Table(title=f"Key: {k}")
        t.add_column("Service"); t.add_column("Verdict"); t.add_column("Detail", max_width=70)
        for r in info["services"]:
            t.add_row(r["service"], f"[{_verdict_color(r['verdict'])}]{r['verdict']}[/]", r["detail"][:70])
        console.print(t)


def _show_firebase(run_dir: Path) -> None:
    for name in ("firebase_rtdb.json", "firebase_firestore.json", "firebase_storage.json"):
        p = run_dir / "probe" / name
        if not p.exists():
            continue
        console.rule(f"[cyan]{name}[/]")
        console.print(p.read_text()[:4000])


def _verdict_color(v: str) -> str:
    v = v.split("(")[0]
    return {
        "SUCCESS": "bold red", "LEAKED": "bold red",
        "REACHED_ERR": "yellow",
        "BLOCKED_ANDROID": "green", "BLOCKED_API_RESTR": "green",
        "BLOCKED_METHOD": "cyan",
        "API_DISABLED": "dim",
        "KEY_INVALID": "dim",
    }.get(v, "white")


# ─────────────────── dynamic-analysis commands ───────────────────

def _dyn_serial(port: int) -> str:
    return f"emulator-{port}"


@dynamic_app.command("setup")
def dynamic_setup():
    """Run scripts/setup-dynamic.sh to install host tools + AVD + frida-server."""
    import subprocess
    from clawditor.utils.paths import project_root
    script = project_root() / "scripts" / "setup-dynamic.sh"
    if not script.exists():
        console.print(f"[red]missing {script}[/]")
        raise typer.Exit(1)
    rc = subprocess.call(["bash", str(script)])
    raise typer.Exit(rc)


@dynamic_app.command("status")
def dynamic_status(port: int = 5554):
    """Show emulator / mitmproxy / frida-server status."""
    from clawditor.dynamic import emulator as _em, mitm as _mm, frida as _fr
    from clawditor.dynamic._proc import read_pid, is_alive
    serial = _dyn_serial(port)
    booted = _em.is_booted(serial)
    mitm_pid = read_pid(_mm.PROC_NAME)
    mitm_running = mitm_pid is not None and is_alive(mitm_pid)
    frida_running = booted and _fr.is_server_running(serial)
    t = Table(title=f"dynamic status ({serial})")
    t.add_column("component"); t.add_column("status"); t.add_column("detail")
    t.add_row("emulator", "[green]booted[/]" if booted else "[red]down[/]", serial)
    t.add_row("mitmweb", "[green]running[/]" if mitm_running else "[red]down[/]",
              f"pid={mitm_pid}" if mitm_pid else "no pid file")
    t.add_row("frida-server", "[green]running[/]" if frida_running else "[red]down[/]",
              "on device /data/local/tmp/frida-server" if frida_running else "not detected")
    console.print(t)


@dynamic_app.command("start")
def dynamic_start(
    avd: str = "clawditor-pixel7",
    port: int = 5554,
    proxy_port: int = 8080,
    proxy_web_port: int = 8081,
    headless: bool = False,
    wireguard: bool = typer.Option(False, "--wireguard", help="Provision a mitmproxy WireGuard tunnel on the device instead of the HTTP proxy. Use for Flutter / proxy-ignoring apps. Installs the WG client, pushes the tunnel config, clears the global proxy, and blocks QUIC. The one-time VPN consent may need a manual tap in the WireGuard app."),
):
    """Boot the emulator, start mitmproxy, push + start frida-server, install system CA."""
    from clawditor.dynamic import emulator as _em, mitm as _mm, frida as _fr
    from clawditor.dynamic import wireguard as _wg
    from clawditor.utils.paths import frida_server_binary, dynamic_captures_dir
    serial = _dyn_serial(port)

    console.rule("[bold cyan]dynamic start[/]")
    _em.boot(avd_name=avd, port=port, headless=headless, writable_system=True)
    _em.adb_root_remount(serial)
    ca = _mm.get_ca_cert_path()
    # No reboot anymore: install_mitmproxy_ca now bind-mounts the apex overlay
    # which is live immediately and would be wiped by a reboot.
    _em.install_mitmproxy_ca(serial, ca)

    arch = _em.detect_arch(serial)
    fbin = frida_server_binary(arch)
    _fr.push_server(serial, fbin)
    _fr.start_server(serial)

    if wireguard:
        # Transport for proxy-ignoring (Flutter/Dart) apps. NOTE: no global proxy
        # (WG is transparent) — setting it would poison WG mode (see wireguard.py).
        flow = dynamic_captures_dir() / "_wg_session" / "flows.mitm"
        flow.parent.mkdir(parents=True, exist_ok=True)
        _wg.start_proxy(flow)
        _wg.install_client(serial)
        _wg.push_config(serial, _wg.client_config())
        _wg.prepare_device(serial)   # clear proxy + block QUIC
        up = _wg.activate(serial)
        console.print(f"\n[green]✓[/] dynamic stack up (WireGuard transport). "
                      f"tunnel={'up' if up else 'NOT up — toggle it on in the WireGuard app'}")
        console.print("Next: [bold]clawditor dynamic capture <pkg> --flutter --wireguard[/]")
        return

    _em.set_proxy(serial, host="10.0.2.2", port=proxy_port)
    _mm.start(port=proxy_port, web_port=proxy_web_port)
    console.print(f"\n[green]✓[/] dynamic stack is up. mitm web UI: "
                  f"http://127.0.0.1:{proxy_web_port}")
    console.print("Next: [bold]clawditor dynamic capture <pkg>[/]")


# Default SDK-bundled-CA ignore regex. These SDKs ship their own pinned CA sets
# and reject mitmproxy's cert; letting their traffic through undecoded lets the
# SDK inits finish so the app proceeds to its own backend calls. See
# `docs/dynamic-analysis.md` → "Known gotchas" → SDK-level cert pinning.
_DEFAULT_IGNORE_HOSTS = (
    r"(graph\.facebook\.com|firebase-settings\.crashlytics\.com|"
    r".*appsflyersdk\.com|.*\.appsflyer\.com|.*\.googleapis\.com|"
    r"connectivitycheck\.gstatic\.com|.*\.gvt1\.com|update\.googleapis\.com|"
    r"play\.googleapis\.com|www\.google\.com|crashlytics\.googleapis\.com)"
)


def _latest_static_manifest(package: str) -> Path | None:
    """Return the newest data/<package>*/scan/manifest.json on disk, or None."""
    base = default_runs_dir()
    if not base.exists():
        return None
    candidates = sorted(
        base.glob(f"{package}*/scan/manifest.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _maybe_warn_pairip(package: str, bypass_pairip: bool) -> None:
    """If the most recent static run flagged Pairip and --bypass-pairip isn't set, advise."""
    if bypass_pairip:
        return
    mf = _latest_static_manifest(package)
    if mf is None:
        return
    try:
        data = json.loads(mf.read_text())
    except Exception:
        return
    if not data.get("has_pairip"):
        return
    hit = data.get("pairip_hit") or "com.pairip.*"
    console.print(
        f"[yellow]⚠[/] static scan shows {hit} in this app (see {mf}).\n"
        "  Consider re-running with --bypass-pairip if the app refuses to start past splash."
    )


@dynamic_app.command("capture")
def dynamic_capture(
    package: str = typer.Argument(..., help="Android package id, e.g. com.example.app"),
    duration: int = 60,
    out: Path = typer.Option(None, "--out", help="Where to write flows.mitm + dynamic_capture.json"),
    flutter: bool = typer.Option(False, "--flutter", help="Use Flutter BoringSSL bypass instead of objection."),
    fast: bool = typer.Option(False, "--fast", help="Lower-overhead capture: headless mitmdump + reduced Frida hooks. Use when the app or emulator is lagging."),
    bypass_gms: bool = typer.Option(False, "--bypass-gms", help="Also bypass Google Play Services version check (for apps that show 'Update Google Play services' on launch)."),
    bypass_pairip: bool = typer.Option(False, "--bypass-pairip", help="Also bypass Pairip license check (for apps wrapped with Google Play's anti-piracy framework). Detect Pairip presence via `com.pairip.licensecheck` in the manifest or `com.pairip.*` smali classes."),
    ignore_hosts: str = typer.Option(None, "--ignore-hosts", help="When set, mitmproxy lets traffic to these hosts pass through undecoded. Use `auto` for the default SDK allowlist (AppsFlyer, Crashlytics, Facebook, GMS internals) that works for most consumer apps with heavy SDK pinning. Pass a custom regex to override."),
    run_id: str = typer.Option(None, "--run-id", help="If set, capture into data/<run_id>/dynamic/ alongside a static run."),
    wireguard: bool = typer.Option(False, "--wireguard", help="Network-layer capture via mitmproxy WireGuard mode instead of the HTTP proxy. REQUIRED for Flutter / Dart / any app that ignores the Android system proxy. Implies the dual (Flutter BoringSSL + Java/Conscrypt) pinning bypass, unsets the global proxy, and blocks QUIC. Run `clawditor dynamic start --wireguard` first to provision the on-device tunnel."),
    proxy_port: int = 8080,
    port: int = 5554,
):
    """Capture HTTPS traffic from one app for N seconds."""
    from clawditor.dynamic import capture as _cap
    from clawditor.utils.paths import dynamic_captures_dir, default_runs_dir
    import datetime as _dt

    if out is None:
        if run_id:
            out = default_runs_dir() / run_id / "dynamic"
        else:
            ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            out = dynamic_captures_dir() / f"{package}_{ts}"
    out.mkdir(parents=True, exist_ok=True)
    # Resolve --ignore-hosts auto → default regex; explicit user regex passes through.
    if ignore_hosts and ignore_hosts.lower() == "auto":
        ignore_hosts = _DEFAULT_IGNORE_HOSTS
    console.rule(f"[bold cyan]dynamic capture {package}[/]")
    _maybe_warn_pairip(package, bypass_pairip)
    summary = _cap.capture(
        package, duration_s=duration, out_dir=out, flutter=flutter, fast=fast,
        bypass_gms=bypass_gms, bypass_pairip=bypass_pairip,
        ignore_hosts=ignore_hosts,
        serial=_dyn_serial(port), proxy_port=proxy_port,
        transport="wireguard" if wireguard else "proxy",
    )
    console.print(f"[green]✓[/] wrote {out / 'dynamic_capture.json'}")
    console.print(
        f"  hosts={summary['host_count']}  "
        f"firestore.collections={len(summary['firestore']['collections'])}  "
        f"storage.paths={len(summary['storage']['paths_observed'])}  "
        f"auth_tokens={summary['auth_token_count']}"
    )


@dynamic_app.command("stop")
def dynamic_stop(port: int = 5554):
    """Stop mitmproxy, kill frida-server, shut down emulator."""
    from clawditor.dynamic import emulator as _em, mitm as _mm, frida as _fr
    serial = _dyn_serial(port)
    if _em.is_booted(serial):
        try:
            _em.clear_proxy(serial)
            _fr.stop_server(serial)
        except Exception as e:
            console.print(f"[yellow]warn:[/] {e}")
    _mm.stop()
    _em.shutdown(serial)
    console.print("[green]✓[/] dynamic stack stopped")


if __name__ == "__main__":
    app()
