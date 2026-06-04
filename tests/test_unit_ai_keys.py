"""Unit tests for the AI / SaaS key probe module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawditor.config import RunContext
from clawditor.probe import ai_keys as mod
from clawditor.scan.secrets import PATTERNS


# --- Regex sanity (mirrors test_unit_secrets but locally for ai_keys-relevant types) ---

def test_openai_classic_and_project_keys():
    assert PATTERNS["openai_key"].search("sk-" + "a" * 30)
    assert PATTERNS["openai_key"].search("sk-proj-" + "X" * 30)


def test_anthropic_key_shape():
    # 80+ chars after the sk-ant-apiNN- prefix
    assert PATTERNS["anthropic_key"].search("sk-ant-api03-" + "a" * 90)
    assert not PATTERNS["anthropic_key"].search("sk-ant-api03-tooShort")


# --- Probe behaviour with mocked HTTP ---

def _write_secrets(ctx: RunContext, data: dict) -> None:
    (ctx.scan_dir / "secrets.json").write_text(json.dumps(data))


def test_run_skips_when_no_secrets_file(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    # secrets.json absent
    out = mod.run(ctx)
    assert out == {}


def test_run_probes_openai_valid(tmp_path: Path, monkeypatch):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    _write_secrets(ctx, {"openai_key": [{"value": "sk-" + "a" * 30, "file": "x"}]})

    def fake_call(method, url, body=None, timeout=10.0, headers=None):
        assert url.startswith("https://api.openai.com/v1/models")
        assert headers["Authorization"].startswith("Bearer sk-")
        return 200, '{"data":[]}'

    monkeypatch.setattr(mod, "call", fake_call)
    out = mod.run(ctx)
    assert len(out) == 1
    v = next(iter(out.values()))
    assert v["provider"] == "openai"
    assert v["verdict"] == "VALID"


def test_run_probes_anthropic_invalid(tmp_path: Path, monkeypatch):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    _write_secrets(ctx, {"anthropic_key": [{"value": "sk-ant-api03-" + "a" * 90, "file": "x"}]})

    def fake_call(method, url, body=None, timeout=10.0, headers=None):
        assert "api.anthropic.com" in url
        assert headers.get("x-api-key", "").startswith("sk-ant-")
        assert headers.get("anthropic-version") == "2023-06-01"
        return 401, '{"error":"invalid x-api-key"}'

    monkeypatch.setattr(mod, "call", fake_call)
    out = mod.run(ctx)
    v = next(iter(out.values()))
    assert v["provider"] == "anthropic"
    assert v["verdict"] == "INVALID"


def test_run_probes_github_rate_limited(tmp_path: Path, monkeypatch):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    _write_secrets(ctx, {"github_token": [{"value": "ghp_" + "A" * 40, "file": "x"}]})

    def fake_call(method, url, body=None, timeout=10.0, headers=None):
        assert "api.github.com/user" in url
        assert headers.get("User-Agent") == "clawditor"
        return 429, "rate limited"

    monkeypatch.setattr(mod, "call", fake_call)
    out = mod.run(ctx)
    v = next(iter(out.values()))
    assert v["verdict"] == "RATE_LIMITED"


def test_run_probes_razorpay_uses_basic_auth(tmp_path: Path, monkeypatch):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    _write_secrets(ctx, {"razorpay_key": [{"value": "rzp_live_abcdefghij1234", "file": "x"}]})

    captured = {}

    def fake_call(method, url, body=None, timeout=10.0, headers=None):
        captured["url"] = url
        captured["auth"] = headers.get("Authorization", "")
        return 200, '{"items":[]}'

    monkeypatch.setattr(mod, "call", fake_call)
    out = mod.run(ctx)
    v = next(iter(out.values()))
    assert v["verdict"] == "VALID"
    assert captured["auth"].startswith("Basic ")
    assert "api.razorpay.com" in captured["url"]


def test_run_probes_mapbox_passes_token_in_query(tmp_path: Path, monkeypatch):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    tok = "pk.eyJ" + "a" * 40 + ".xyz"
    _write_secrets(ctx, {"mapbox_token": [{"value": tok, "file": "x"}]})

    captured = {}

    def fake_call(method, url, body=None, timeout=10.0, headers=None):
        captured["url"] = url
        return 200, '{"token":"x"}'

    monkeypatch.setattr(mod, "call", fake_call)
    out = mod.run(ctx)
    assert next(iter(out.values()))["verdict"] == "VALID"
    assert "access_token=pk.eyJ" in captured["url"]


def test_run_probes_sentry_dsn_parses_host(tmp_path: Path, monkeypatch):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    dsn = "https://" + "f" * 32 + "@o123.ingest.sentry.io/678"
    _write_secrets(ctx, {"sentry_dsn": [{"value": dsn, "file": "x"}]})

    captured = {}

    def fake_call(method, url, body=None, timeout=10.0, headers=None):
        captured["url"] = url
        return 401, "unauth"  # typical even for valid DSN ingest endpoint

    monkeypatch.setattr(mod, "call", fake_call)
    out = mod.run(ctx)
    v = next(iter(out.values()))
    # Any HTTP response = ingest reachable.
    assert v["verdict"] == "VALID"
    assert "o123.ingest.sentry.io" in captured["url"]
    assert "/api/678/" in captured["url"]


def test_run_writes_ai_keys_json(tmp_path: Path, monkeypatch):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    _write_secrets(ctx, {"openai_key": [{"value": "sk-" + "a" * 30, "file": "x"}]})

    monkeypatch.setattr(mod, "call", lambda *a, **k: (200, "{}"))
    mod.run(ctx)
    out_file = ctx.probe_dir / "ai_keys.json"
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert len(data) == 1
