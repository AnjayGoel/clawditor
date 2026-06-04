"""Structural JWT decoder. Reads `secrets.json:jwt` and surfaces interesting tokens.

No signature verification — stdlib `base64` + `json` only. We classify each token
by header (`alg`, `kid`), payload claims (`iss`, `exp`, ...), expiry vs current
time, and whether the issuer looks like a real production endpoint or a
well-known SDK / docs test fixture.
"""
from __future__ import annotations

import base64
import json
import re
import time
from typing import Any

from clawditor.config import RunContext
from clawditor.utils import logging as log


# Issuers seen in real production token mints. A token bearing one of these
# issuers in a shipped binary is almost always a leaked live session.
PRODUCTION_ISSUER_PATTERNS = (
    re.compile(r"^https://securetoken\.google\.com/.+"),
    re.compile(r"^https://accounts\.google\.com/?$"),
    re.compile(r"^https://appleid\.apple\.com/?$"),
    re.compile(r"^https://login\.microsoftonline\.com/.+"),
    re.compile(r"^https://[a-z0-9-]+\.auth0\.com/?$"),
    re.compile(r"^https://cognito-idp\.[a-z0-9-]+\.amazonaws\.com/.+"),
    re.compile(r"^https://api\.twitter\.com/?$"),
    re.compile(r"^https://www\.facebook\.com/?$"),
    re.compile(r"^https://oauth2\.googleapis\.com/?$"),
    re.compile(r"^https://[a-z0-9-]+\.firebaseapp\.com/?$"),
    re.compile(r"^https://[a-z0-9-]+\.okta\.com/?$"),
)

# Issuers explicitly used in SDK docs / examples / fixtures. A token bearing one
# of these is almost certainly demo data.
TEST_FIXTURE_ISSUERS = {
    "https://example.com",
    "https://example.com/",
    "https://jwt.io",
    "https://jwt.io/",
    "urn:example:issuer",
    "joe",  # RFC 7519 example
    "test",
    "test-issuer",
    "issuer",
    "Online JWT Builder",
}


def run(ctx: RunContext) -> dict:
    secrets_path = ctx.scan_dir / "secrets.json"
    if not secrets_path.exists():
        log.warn("jwt_analyzer: scan/secrets.json not found; skipping")
        return {}
    try:
        secrets = json.loads(secrets_path.read_text())
    except Exception as e:
        log.err(f"jwt_analyzer: failed to parse secrets.json: {e}")
        return {}

    raw_tokens = secrets.get("jwt") or []
    tokens: list[dict] = []
    now = int(time.time())
    for item in raw_tokens:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        file = item.get("file", "?")
        if not isinstance(value, str):
            continue
        decoded = _decode_jwt(value)
        if decoded is None:
            tokens.append({
                "file": file,
                "header": {},
                "payload_claims": {},
                "is_expired": False,
                "is_test_fixture": False,
                "issuer_class": "unknown",
                "findings": ["malformed"],
            })
            continue
        header, payload = decoded
        tokens.append(_classify(file, header, payload, now))

    result = {"tokens": tokens}
    out = ctx.scan_dir / "jwt_analyzer.json"
    out.write_text(json.dumps(result, indent=2))
    if tokens:
        log.ok(f"jwt_analyzer: {len(tokens)} token(s) decoded")
    return result


def _decode_jwt(token: str) -> tuple[dict, dict] | None:
    """Split + base64url-decode header & payload. Returns None on any structural error."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _decode_segment(parts[0])
        payload = _decode_segment(parts[1])
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _decode_segment(seg: str) -> Any:
    # JWT base64url omits trailing '='; pad to a multiple of 4 before decoding.
    pad = "=" * (-len(seg) % 4)
    raw = base64.urlsafe_b64decode(seg + pad)
    return json.loads(raw.decode("utf-8", errors="replace"))


def _classify(file: str, header: dict, payload: dict, now: int) -> dict:
    alg = _stringish(header.get("alg"))
    typ = _stringish(header.get("typ"))
    kid = _stringish(header.get("kid"))
    iss = _stringish(payload.get("iss"))
    exp = payload.get("exp") if isinstance(payload.get("exp"), (int, float)) else None
    is_expired = bool(exp is not None and int(exp) < now)

    issuer_class = _classify_issuer(iss)
    is_test_fixture = issuer_class == "test_fixture"

    findings: list[str] = []
    if isinstance(alg, str) and alg.lower() == "none":
        findings.append("alg_none")
    if isinstance(alg, str) and alg.upper().startswith("HS") and "k" in payload:
        # Symmetric secret embedded in the payload is non-standard but seen in
        # broken examples; harmless flag.
        findings.append("hmac_secret_in_payload")
    if is_expired:
        findings.append("expired")
    if issuer_class == "production":
        findings.append("production_issuer")
    if issuer_class == "test_fixture":
        findings.append("test_fixture_issuer")
    if issuer_class == "internal":
        findings.append("internal_issuer")

    payload_claims = {
        k: payload.get(k)
        for k in ("iss", "aud", "sub", "exp", "iat", "nbf")
        if k in payload
    }

    return {
        "file": file,
        "header": {"alg": alg, "typ": typ, "kid": kid},
        "payload_claims": payload_claims,
        "is_expired": is_expired,
        "is_test_fixture": is_test_fixture,
        "issuer_class": issuer_class,
        "findings": findings,
    }


def _classify_issuer(iss: Any) -> str:
    if not isinstance(iss, str) or not iss:
        return "unknown"
    if iss in TEST_FIXTURE_ISSUERS:
        return "test_fixture"
    for rx in PRODUCTION_ISSUER_PATTERNS:
        if rx.match(iss):
            return "production"
    # Heuristic: internal / staging / private hostnames.
    if re.match(r"^https?://(?:[a-z0-9-]+\.)*(?:internal|corp|local|staging|dev|test)\b", iss):
        return "internal"
    return "unknown"


def _stringish(v: Any) -> Any:
    return v if isinstance(v, (str, int, float, bool)) or v is None else str(v)


if __name__ == "__main__":  # pragma: no cover - debug entry
    import argparse, sys
    from pathlib import Path
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="path to a run dir")
    args = ap.parse_args()
    out = Path(args.run)
    ctx = RunContext(package=None, apk_input=None, out_dir=out)
    ctx.ensure_dirs()
    print(json.dumps(run(ctx), indent=2))
