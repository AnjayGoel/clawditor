"""Unit tests for the JWT structural analyzer + its findings mapping."""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from clawditor.config import RunContext
from clawditor.scan.jwt_analyzer import run as run_jwt
from clawditor.report.findings import _from_jwt_analyzer


def _b64u(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(header: dict, payload: dict, sig: str = "sig") -> str:
    return f"{_b64u(header)}.{_b64u(payload)}.{sig}"


def _ctx(tmp_path: Path) -> RunContext:
    ctx = RunContext(package="p", apk_input=None, out_dir=tmp_path)
    ctx.ensure_dirs()
    return ctx


def _write_secrets(ctx: RunContext, jwts: list[str]) -> None:
    secrets = {"jwt": [{"value": j, "file": f"smali/T{i}.smali"} for i, j in enumerate(jwts)]}
    (ctx.scan_dir / "secrets.json").write_text(json.dumps(secrets))


def test_alg_none_classified_and_yields_critical(tmp_path: Path):
    ctx = _ctx(tmp_path)
    tok = _jwt({"alg": "none", "typ": "JWT"}, {"iss": "evil", "sub": "u1"}, sig="")
    _write_secrets(ctx, [tok])
    out = run_jwt(ctx)
    assert "alg_none" in out["tokens"][0]["findings"]
    # Severity
    findings = list(_from_jwt_analyzer(ctx))
    assert any(f["severity"] == "CRITICAL" and "alg:none" in f["title"] for f in findings)


def test_live_production_issuer_yields_high(tmp_path: Path):
    ctx = _ctx(tmp_path)
    future = int(time.time()) + 3600
    tok = _jwt(
        {"alg": "RS256", "typ": "JWT", "kid": "abc"},
        {"iss": "https://securetoken.google.com/myproj", "sub": "uid1", "exp": future, "aud": "myproj"},
    )
    _write_secrets(ctx, [tok])
    out = run_jwt(ctx)
    t = out["tokens"][0]
    assert t["issuer_class"] == "production"
    assert t["is_expired"] is False
    assert "production_issuer" in t["findings"]
    findings = list(_from_jwt_analyzer(ctx))
    assert any(f["severity"] == "HIGH" and "securetoken" in f["title"] for f in findings)


def test_expired_test_fixture_classified_as_fixture_and_info(tmp_path: Path):
    ctx = _ctx(tmp_path)
    past = int(time.time()) - 3600
    tok = _jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"iss": "https://example.com", "sub": "user", "exp": past},
    )
    _write_secrets(ctx, [tok])
    out = run_jwt(ctx)
    t = out["tokens"][0]
    assert t["issuer_class"] == "test_fixture"
    assert t["is_test_fixture"] is True
    assert t["is_expired"] is True
    assert "expired" in t["findings"]
    findings = list(_from_jwt_analyzer(ctx))
    assert any(f["severity"] == "INFO" and "test-fixture" in f["title"] for f in findings)


def test_malformed_jwt_classified_as_malformed(tmp_path: Path):
    ctx = _ctx(tmp_path)
    # Two-part token (missing signature segment) — structurally bad.
    _write_secrets(ctx, ["not-a-jwt.really-not"])
    out = run_jwt(ctx)
    t = out["tokens"][0]
    assert t["findings"] == ["malformed"]
    assert t["issuer_class"] == "unknown"
    # Malformed should NOT produce a finding row (no severity match).
    findings = list(_from_jwt_analyzer(ctx))
    assert not findings


def test_expired_production_issuer_yields_medium(tmp_path: Path):
    ctx = _ctx(tmp_path)
    past = int(time.time()) - 3600
    tok = _jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"iss": "https://securetoken.google.com/realproj", "exp": past},
    )
    _write_secrets(ctx, [tok])
    run_jwt(ctx)
    findings = list(_from_jwt_analyzer(ctx))
    assert any(f["severity"] == "MEDIUM" and "expired" in f["title"] for f in findings)


def test_missing_secrets_file_returns_empty(tmp_path: Path):
    ctx = _ctx(tmp_path)
    out = run_jwt(ctx)
    assert out == {}
    assert not (ctx.scan_dir / "jwt_analyzer.json").exists()
