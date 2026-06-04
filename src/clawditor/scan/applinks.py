"""App Links + deeplink security audit.

Reads `scan/manifest.json` (deeplinks) and:
- For HTTPS deeplinks declared with android:autoVerify="true", probes the
  associated https://<host>/.well-known/assetlinks.json to confirm Android can
  actually verify domain ownership at install time. If the file is missing,
  malformed, or doesn't list this app's package, App Links silently fall back to
  the disambiguation dialog — any other app can claim the same URL.
- Flags broad deeplinks that have no path restriction at all (entire host space).
- Flags intent filters with suspiciously high android:priority (potential
  system-intent hijack).

Writes `scan/applinks.json`. HTTP probes use an 8s timeout and read-only GETs;
assetlinks.json is publicly fetchable by design.
"""
from __future__ import annotations

import json

from clawditor.config import RunContext
from clawditor.probe._http import call
from clawditor.utils import logging as log


_HTTP_TIMEOUT = 8


def run(ctx: RunContext) -> dict:
    mf_path = ctx.scan_dir / "manifest.json"
    if not mf_path.exists():
        log.warn("applinks: manifest.json not found; skipping")
        return {}
    manifest = json.loads(mf_path.read_text())
    deeplinks = manifest.get("deeplinks", []) or []
    package = manifest.get("package")

    if not deeplinks:
        out = ctx.scan_dir / "applinks.json"
        out.write_text(json.dumps({"package": package, "findings": []}, indent=2))
        log.ok("applinks: no deeplink filters declared")
        return {"package": package, "findings": []}

    findings: list[dict] = []
    # Cache assetlinks.json fetches across multiple intent-filters on same host.
    seen_host: dict[str, dict] = {}

    for link in deeplinks:
        schemes = link.get("schemes", []) or []
        hosts = link.get("hosts", []) or []
        paths = link.get("paths", []) or []
        auto_verify = bool(link.get("auto_verify"))
        priority = link.get("priority")

        if "https" in schemes and auto_verify:
            for host in hosts:
                if not host or "*" in host:
                    continue
                if host in seen_host:
                    base = dict(seen_host[host])
                    base["activity"] = link.get("activity")
                    findings.append(base)
                    continue
                result = _probe_assetlinks(host, package)
                result["activity"] = link.get("activity")
                seen_host[host] = {k: v for k, v in result.items() if k != "activity"}
                findings.append(result)

        # Generic deeplink risk: scheme://host with no path restriction.
        if schemes and hosts and not paths:
            findings.append({
                "type": "no_path_restriction",
                "activity": link.get("activity"),
                "schemes": schemes,
                "hosts": hosts,
                "finding": "deeplink has no path restriction (entire host space)",
            })

        # Suspicious priority — Android default is 0. Anything above 100 is unusual.
        if priority is not None:
            try:
                p = int(priority)
            except (TypeError, ValueError):
                p = 0
            if p > 100:
                findings.append({
                    "type": "high_priority_intent_filter",
                    "activity": link.get("activity"),
                    "priority": p,
                    "schemes": schemes,
                    "hosts": hosts,
                    "finding": f"intent-filter has high priority={p} (system-intent hijack risk)",
                })

    payload = {"package": package, "findings": findings}
    (ctx.scan_dir / "applinks.json").write_text(json.dumps(payload, indent=2))
    log.ok(f"applinks: {len(findings)} deeplink finding(s)")
    return payload


def _probe_assetlinks(host: str, package: str | None) -> dict:
    """GET https://<host>/.well-known/assetlinks.json and validate."""
    url = f"https://{host}/.well-known/assetlinks.json"
    status, body = call("GET", url, timeout=_HTTP_TIMEOUT)
    result: dict = {
        "type": "applink_assetlinks",
        "domain": host,
        "url": url,
        "http": status,
        "assetlinks_present": status == 200,
    }
    if status != 200:
        # Distinguish network / DNS failure from a real 4xx/5xx response.
        if status == 0:
            result["finding"] = (
                "App Link autoVerify=true but assetlinks.json unreachable "
                "(network/DNS error) — domain may not resolve; hijackable"
            )
        else:
            result["finding"] = (
                f"App Link autoVerify=true but assetlinks.json missing "
                f"(HTTP {status}) — Android falls back to disambiguation; hijackable"
            )
        return result

    try:
        doc = json.loads(body)
    except Exception:
        result["finding"] = "assetlinks.json present but malformed JSON — Android will reject verification"
        return result

    if not isinstance(doc, list):
        result["finding"] = "assetlinks.json present but not a JSON array — Android will reject verification"
        return result

    pkg_listed = False
    for entry in doc:
        if not isinstance(entry, dict):
            continue
        target = entry.get("target") or {}
        if target.get("package_name") == package:
            pkg_listed = True
            break

    if not pkg_listed and package:
        result["finding"] = (
            f"assetlinks.json present but does not declare package {package} — "
            "App Link verification fails; hijackable"
        )
    result["package_declared"] = pkg_listed
    return result


if __name__ == "__main__":  # pragma: no cover
    import sys
    from clawditor.config import RunContext
    from pathlib import Path

    if len(sys.argv) != 2:
        print("usage: python -m clawditor.scan.applinks <run_dir>")
        sys.exit(2)
    out_dir = Path(sys.argv[1]).resolve()
    ctx = RunContext(package=None, apk_input=None, out_dir=out_dir)
    print(json.dumps(run(ctx), indent=2))
