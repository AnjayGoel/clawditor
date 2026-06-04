"""Probe Firestore rules with a minted anon Firebase identity."""
from __future__ import annotations

import json

from clawditor.config import RunContext
from clawditor.probe._http import call
from clawditor.utils import logging as log


COMMON_COLLECTIONS = ["users", "config", "app_config", "remote_config", "catalog",
                      "episodes", "stories", "shows", "settings", "public",
                      "products", "orders", "messages", "chats"]


def run(ctx: RunContext) -> dict:
    secrets_file = ctx.scan_dir / "secrets.json"
    if not secrets_file.exists():
        return {}
    secrets = json.loads(secrets_file.read_text())
    keys = [h["value"] for h in secrets.get("google_api_key", [])]
    if not keys:
        return {}

    # Derive project IDs from storage buckets / RTDB URLs / and code patterns
    projects = _enumerate_projects(secrets)
    if not projects:
        log.info("no Firebase projects identified; skipping firestore probe")
        return {}

    out: dict[str, dict] = {}
    for proj in projects:
        log.info(f"  Firestore project: {proj}")
        out[proj] = _probe_project(proj, keys)
    (ctx.probe_dir / "firebase_firestore.json").write_text(json.dumps(out, indent=2))
    return out


def _enumerate_projects(secrets: dict) -> list[str]:
    projs: set[str] = set()
    for h in secrets.get("firebase_storage_bucket", []):
        v = h["value"]
        if v.endswith(".appspot.com"):
            projs.add(v.removesuffix(".appspot.com"))
        elif v.endswith(".firebasestorage.app"):
            projs.add(v.removesuffix(".firebasestorage.app"))
    for h in secrets.get("firebase_rtdb_url", []):
        from urllib.parse import urlparse
        host = urlparse(h["value"]).hostname or ""
        projs.add(host.split(".")[0])
    return sorted(p for p in projs if p)


def _probe_project(project: str, keys: list[str]) -> dict:
    tok, uid = _try_mint_anon(keys)
    result: dict = {"auth_used": bool(tok), "uid": uid}
    if not tok:
        result["status"] = "could not mint anon identity (no key reached Identity Toolkit)"
        return result
    headers_auth = {"Authorization": f"Bearer {tok}"}
    db_base = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"

    # 1. Existence: does Firestore default DB exist?
    st, body = _get_auth(db_base + "?pageSize=1", tok)
    result["db_existence_check"] = {"http": st, "snippet": body[:200].replace("\n", " ")}

    # 2. Common-collection list
    lists = {}
    for c in COMMON_COLLECTIONS:
        st2, body2 = _get_auth(f"{db_base}/{c}?pageSize=1", tok)
        lists[c] = {"http": st2, "snippet": body2[:120].replace("\n", " ")}
    result["collection_list"] = lists

    # 3. Read user's own UID (the standard owner-only rule)
    st3, body3 = _get_auth(f"{db_base}/users/{uid}", tok)
    result["own_uid_read"] = {"http": st3, "snippet": body3[:120].replace("\n", " ")}

    # 4. Unfiltered structured query (rules-driven; fails 403 if rules require filter)
    sq = {"structuredQuery": {"from": [{"collectionId": "users"}], "limit": 1}}
    import httpx
    try:
        with httpx.Client(timeout=10) as cli:
            r = cli.post(f"{db_base}:runQuery",
                         headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                         content=json.dumps(sq).encode())
            st4, body4 = r.status_code, r.text
    except Exception as e:
        st4, body4 = 0, f"NETERR:{e}"
    result["structured_query_users"] = {"http": st4, "snippet": body4[:200].replace("\n", " ")}

    return result


def _get_auth(url: str, tok: str) -> tuple[int, str]:
    import httpx
    try:
        with httpx.Client(timeout=10) as cli:
            r = cli.get(url, headers={"Authorization": f"Bearer {tok}"})
            return r.status_code, r.text
    except Exception as e:
        return 0, f"NETERR:{e}"


def _try_mint_anon(keys: list[str]) -> tuple[str | None, str | None]:
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
            return d["idToken"], d.get("localId")
    return None, None
