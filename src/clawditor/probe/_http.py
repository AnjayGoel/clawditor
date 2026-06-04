"""Shared probe HTTP helpers."""
from __future__ import annotations

import json
from typing import Any

import httpx


def call(
    method: str,
    url: str,
    body: bytes | dict | None = None,
    timeout: float = 10.0,
    headers: dict | None = None,
) -> tuple[int, str]:
    h: dict = dict(headers) if headers else {}
    data: Any = None
    if body is not None:
        h.setdefault("Content-Type", "application/json")
        data = body if isinstance(body, (bytes, str)) else json.dumps(body).encode()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as cli:
            r = cli.request(method, url, content=data, headers=h)
            return r.status_code, r.text
    except Exception as e:
        return 0, f"NETERR:{e}"


def classify(status: int, body: str) -> tuple[str, str]:
    """Map raw response to a verdict tag + a short detail string."""
    try:
        d = json.loads(body)
    except Exception:
        return f"HTTP{status}", body[:120].replace("\n", " ")

    if isinstance(d, dict) and "error" in d:
        e = d["error"]
        st = e.get("status", "")
        msg = (e.get("message") or "")[:200]
        lo = msg.lower()
        if "leaked" in lo:
            return "LEAKED", msg
        if "android" in lo and "block" in lo:
            return "BLOCKED_ANDROID", msg
        if "ip address" in lo and "block" in lo:
            return "BLOCKED_IP", msg
        if "referer" in lo or "referrer" in lo:
            return "BLOCKED_REFERRER", msg
        if "not authorized to use this service" in lo or "api restrictions" in lo:
            return "BLOCKED_API_RESTR", msg
        if "has not been used in project" in lo or "is disabled" in lo or "not activated" in lo:
            return "API_DISABLED", msg
        if "method" in lo and "block" in lo:
            return "BLOCKED_METHOD", msg
        if "api key not valid" in lo:
            return "KEY_INVALID", msg
        if "quota" in lo or st == "RESOURCE_EXHAUSTED":
            return "QUOTA", msg
        return f"REACHED_ERR({st})", msg

    if isinstance(d, dict) and d.get("status") in ("REQUEST_DENIED", "OVER_QUERY_LIMIT",
                                                   "INVALID_REQUEST", "ZERO_RESULTS", "OK"):
        s = d["status"]
        em = (d.get("error_message") or "")[:200]
        lo = em.lower()
        if "not authorized to use this service" in lo:
            return "BLOCKED_API_RESTR", em
        if "not activated" in lo or "enable this api" in lo:
            return "API_DISABLED", em
        if "android" in lo and "block" in lo:
            return "BLOCKED_ANDROID", em
        if s in ("OK", "ZERO_RESULTS"):
            return "SUCCESS", em or body[:120]
        return f"MAPS_{s}", em

    return "SUCCESS", body[:140]
