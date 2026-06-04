"""Probe leaked AI / SaaS / payment keys against their providers' read-only endpoints.

Verdicts: VALID | INVALID | UNAUTHORIZED | RATE_LIMITED | ERROR
All probes are GETs on list/info endpoints — never a chat/messages/payment write call.
"""
from __future__ import annotations

import base64
import json
import re

from clawditor.config import RunContext
from clawditor.probe._http import call
from clawditor.utils import logging as log


def run(ctx: RunContext) -> dict:
    secrets_file = ctx.scan_dir / "secrets.json"
    if not secrets_file.exists():
        return {}
    secrets = json.loads(secrets_file.read_text())
    results: dict[str, dict] = {}

    for k in [h["value"] for h in secrets.get("openai_key", [])]:
        results[k] = _probe_openai(k)
    for k in [h["value"] for h in secrets.get("anthropic_key", [])]:
        results[k] = _probe_anthropic(k)
    for k in [h["value"] for h in secrets.get("xai_grok_key", [])]:
        results[k] = _probe_xai(k)
    for k in [h["value"] for h in secrets.get("github_token", [])]:
        results[k] = _probe_github(k)
    for k in [h["value"] for h in secrets.get("razorpay_key", [])]:
        results[k] = _probe_razorpay(k)
    for k in [h["value"] for h in secrets.get("mapbox_token", [])]:
        results[k] = _probe_mapbox(k)
    for k in [h["value"] for h in secrets.get("sentry_dsn", [])]:
        results[k] = _probe_sentry(k)

    if results:
        (ctx.probe_dir / "ai_keys.json").write_text(json.dumps(results, indent=2))
        verified = sum(1 for v in results.values() if v.get("verdict") == "VALID")
        log.ok(f"ai_keys: {len(results)} probed, {verified} VALID")
    return results


def _verdict(status: int, body: str, provider: str, ok_codes=(200,)) -> dict:
    if status in ok_codes:
        return {"provider": provider, "verdict": "VALID", "detail": body[:140]}
    if status == 401 or status == 403:
        return {"provider": provider, "verdict": "INVALID", "detail": body[:140]}
    if status == 429:
        return {"provider": provider, "verdict": "RATE_LIMITED", "detail": body[:140]}
    if status == 0:
        return {"provider": provider, "verdict": "ERROR", "detail": body[:140]}
    return {"provider": provider, "verdict": "ERROR", "detail": f"HTTP{status}: {body[:120]}"}


def _probe_openai(key: str) -> dict:
    status, body = call("GET", "https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {key}"})
    return _verdict(status, body, "openai")


def _probe_anthropic(key: str) -> dict:
    status, body = call("GET", "https://api.anthropic.com/v1/models",
                        headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
    return _verdict(status, body, "anthropic")


def _probe_xai(key: str) -> dict:
    status, body = call("GET", "https://api.x.ai/v1/models",
                        headers={"Authorization": f"Bearer {key}"})
    return _verdict(status, body, "xai")


def _probe_github(key: str) -> dict:
    # GitHub requires a User-Agent header.
    status, body = call("GET", "https://api.github.com/user",
                        headers={"Authorization": f"Bearer {key}", "User-Agent": "clawditor"})
    return _verdict(status, body, "github")


def _probe_razorpay(key: str) -> dict:
    # Basic auth: key as username, empty password. Read-only list call (?count=1).
    token = base64.b64encode(f"{key}:".encode()).decode()
    status, body = call("GET", "https://api.razorpay.com/v1/payments?count=1",
                        headers={"Authorization": f"Basic {token}"})
    return _verdict(status, body, "razorpay")


def _probe_mapbox(key: str) -> dict:
    status, body = call("GET", f"https://api.mapbox.com/tokens/v2?access_token={key}")
    return _verdict(status, body, "mapbox")


def _probe_sentry(dsn: str) -> dict:
    # DSN reveals project + ingest endpoint; we just check the host is reachable.
    # Format: https://<publickey>@<host>/<projectid>
    m = re.match(r"https://([a-f0-9]{32})@([^/]+)/(\d+)", dsn)
    if not m:
        return {"provider": "sentry", "verdict": "ERROR", "detail": "unparsable DSN"}
    host = m.group(2)
    project_id = m.group(3)
    # The store endpoint exists for every valid DSN; a HEAD/GET on the project envelope URL
    # without auth tends to 401, which still confirms reachability.
    url = f"https://{host}/api/{project_id}/envelope/"
    status, body = call("GET", url)
    if status == 0:
        return {"provider": "sentry", "verdict": "ERROR", "detail": body[:140]}
    # Any HTTP response (incl. 401/405) means the ingest endpoint is live.
    return {"provider": "sentry", "verdict": "VALID",
            "detail": f"reachable HTTP{status}; host={host} project={project_id}"}
