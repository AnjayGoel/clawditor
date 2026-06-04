"""Probe Firebase Realtime DB rules unauthenticated AND with a minted anon token."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from clawditor.config import RunContext
from clawditor.probe._http import call
from clawditor.utils import logging as log


COMMON_PATHS = ["", "users", "config", "app_config", "settings", "remote_config",
                "app", "catalog", "stories", "episodes", "shows", "channels",
                "messages", "chats", "leaderboard"]


def run(ctx: RunContext) -> dict:
    secrets_file = ctx.scan_dir / "secrets.json"
    if not secrets_file.exists():
        return {}
    secrets = json.loads(secrets_file.read_text())
    rtdb_urls = [h["value"] for h in secrets.get("firebase_rtdb_url", [])]
    # Some apps also embed naked project IDs; derive RTDB URLs from buckets if needed
    if not rtdb_urls:
        for h in secrets.get("firebase_storage_bucket", []):
            v = h["value"]
            if v.endswith(".appspot.com"):
                proj = v.removesuffix(".appspot.com")
                rtdb_urls.append(f"https://{proj}.firebaseio.com")
    if not rtdb_urls:
        log.info("no Firebase RTDB URLs found; skipping")
        return {}

    keys = [h["value"] for h in secrets.get("google_api_key", [])]
    out: dict[str, dict] = {}
    for url in sorted(set(rtdb_urls)):
        log.info(f"  RTDB: {url}")
        out[url] = _probe_one(url, keys)
    (ctx.probe_dir / "firebase_rtdb.json").write_text(json.dumps(out, indent=2))
    return out


def _probe_one(rtdb_url: str, candidate_keys: list[str]) -> dict:
    project_host = urlparse(rtdb_url).hostname or ""
    project = project_host.split(".")[0]

    # Unauthenticated probes on common paths
    unauth = {}
    for p in COMMON_PATHS:
        u = f"{rtdb_url}/{p}.json?shallow=true"
        st, body = call("GET", u, timeout=8)
        unauth[p or "/"] = {"http": st, "snippet": body[:120].replace("\n", " ")}

    # Try to mint an anon token in any of the candidate keys' projects, then re-test.
    # We only use the token to confirm whether authenticated reads succeed (rule boundary).
    auth = {}
    tok = _try_mint_anon(candidate_keys)
    if tok:
        for p in COMMON_PATHS:
            u = f"{rtdb_url}/{p}.json?shallow=true&auth={tok}"
            st, body = call("GET", u, timeout=8)
            auth[p or "/"] = {"http": st, "snippet": body[:120].replace("\n", " ")}
    return {"project": project, "unauth": unauth, "auth": auth, "auth_used": bool(tok)}


def _try_mint_anon(keys: list[str]) -> str | None:
    for k in keys:
        st, body = call(
            "POST",
            f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={k}",
            b'{"returnSecureToken":true}',
            timeout=10,
        )
        try:
            d = json.loads(body)
        except Exception:
            continue
        if isinstance(d, dict) and d.get("idToken"):
            return d["idToken"]
    return None
