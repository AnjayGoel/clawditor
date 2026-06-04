"""Unit tests for the App Links / deeplinks scanner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawditor.config import RunContext
from clawditor.scan import applinks


def _ctx_with_manifest(tmp_path: Path, manifest: dict) -> RunContext:
    ctx = RunContext("test.pkg", None, tmp_path)
    ctx.ensure_dirs()
    (ctx.scan_dir / "manifest.json").write_text(json.dumps(manifest))
    return ctx


def _valid_assetlinks(package: str) -> str:
    return json.dumps([
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": package,
                "sha256_cert_fingerprints": ["AA:BB:CC"],
            },
        }
    ])


def test_no_deeplinks_returns_empty(tmp_path: Path, monkeypatch):
    ctx = _ctx_with_manifest(tmp_path, {"package": "test.pkg", "deeplinks": []})
    monkeypatch.setattr(applinks, "call",
                        lambda *a, **k: pytest.fail("should not have been called"))
    out = applinks.run(ctx)
    assert out["findings"] == []
    # JSON file should still be written.
    written = json.loads((ctx.scan_dir / "applinks.json").read_text())
    assert written["findings"] == []


def test_assetlinks_missing_flags_hijack(tmp_path: Path, monkeypatch):
    """https + autoVerify=true on a domain whose assetlinks.json returns 404."""
    manifest = {
        "package": "test.pkg",
        "deeplinks": [{
            "activity": ".Deep",
            "schemes": ["https"],
            "hosts": ["nope.example.com"],
            "paths": ["/promo"],
            "auto_verify": True,
            "priority": None,
        }],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)

    monkeypatch.setattr(applinks, "call", lambda *a, **k: (404, "<html>not found</html>"))

    out = applinks.run(ctx)
    al = [f for f in out["findings"] if f.get("type") == "applink_assetlinks"]
    assert len(al) == 1
    assert al[0]["domain"] == "nope.example.com"
    assert al[0]["assetlinks_present"] is False
    assert "missing" in al[0]["finding"]


def test_assetlinks_present_and_valid_no_finding(tmp_path: Path, monkeypatch):
    """https + autoVerify=true + assetlinks.json lists our package → no finding."""
    manifest = {
        "package": "test.pkg",
        "deeplinks": [{
            "activity": ".Deep",
            "schemes": ["https"],
            "hosts": ["good.example.com"],
            "paths": ["/promo"],
            "auto_verify": True,
            "priority": None,
        }],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)

    monkeypatch.setattr(applinks, "call",
                        lambda *a, **k: (200, _valid_assetlinks("test.pkg")))

    out = applinks.run(ctx)
    al = [f for f in out["findings"] if f.get("type") == "applink_assetlinks"]
    assert len(al) == 1
    assert al[0]["assetlinks_present"] is True
    assert al[0]["package_declared"] is True
    # No `finding` key because everything checks out.
    assert "finding" not in al[0]


def test_assetlinks_present_but_wrong_package(tmp_path: Path, monkeypatch):
    """assetlinks.json returns 200 but doesn't list our package."""
    manifest = {
        "package": "test.pkg",
        "deeplinks": [{
            "activity": ".Deep",
            "schemes": ["https"],
            "hosts": ["other.example.com"],
            "paths": ["/x"],
            "auto_verify": True,
            "priority": None,
        }],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)

    monkeypatch.setattr(applinks, "call",
                        lambda *a, **k: (200, _valid_assetlinks("other.pkg")))

    out = applinks.run(ctx)
    al = [f for f in out["findings"] if f.get("type") == "applink_assetlinks"]
    assert len(al) == 1
    assert al[0]["assetlinks_present"] is True
    assert al[0]["package_declared"] is False
    assert "does not declare package test.pkg" in al[0]["finding"]


def test_deeplink_no_path_restriction(tmp_path: Path, monkeypatch):
    """Custom scheme deeplink with no path restriction → MEDIUM finding."""
    manifest = {
        "package": "test.pkg",
        "deeplinks": [{
            "activity": ".OpenAll",
            "schemes": ["myapp"],
            "hosts": ["open"],
            "paths": [],
            "auto_verify": False,
            "priority": None,
        }],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)
    monkeypatch.setattr(applinks, "call",
                        lambda *a, **k: pytest.fail("non-https/autoVerify should not probe"))
    out = applinks.run(ctx)
    no_path = [f for f in out["findings"] if f.get("type") == "no_path_restriction"]
    assert len(no_path) == 1
    assert no_path[0]["activity"] == ".OpenAll"


def test_high_priority_intent_filter(tmp_path: Path, monkeypatch):
    """priority > 100 → LOW finding flagged."""
    manifest = {
        "package": "test.pkg",
        "deeplinks": [{
            "activity": ".Hijack",
            "schemes": ["sms"],
            "hosts": ["receive"],
            "paths": ["/x"],
            "auto_verify": False,
            "priority": "999",
        }],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)
    monkeypatch.setattr(applinks, "call", lambda *a, **k: (0, "should not run"))
    out = applinks.run(ctx)
    hp = [f for f in out["findings"] if f.get("type") == "high_priority_intent_filter"]
    assert len(hp) == 1
    assert hp[0]["priority"] == 999


def test_combined_manifest(tmp_path: Path, monkeypatch):
    """Three intent-filters: (a) https+autoVerify 404, (b) https+autoVerify 200 valid,
    (c) custom scheme with no path restriction. Asserts each produces its expected finding."""
    manifest = {
        "package": "test.pkg",
        "deeplinks": [
            {"activity": ".A", "schemes": ["https"], "hosts": ["bad.example.com"],
             "paths": ["/x"], "auto_verify": True, "priority": None},
            {"activity": ".B", "schemes": ["https"], "hosts": ["good.example.com"],
             "paths": ["/y"], "auto_verify": True, "priority": None},
            {"activity": ".C", "schemes": ["myapp"], "hosts": ["open"],
             "paths": [], "auto_verify": False, "priority": None},
        ],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)

    def fake_call(method, url, **kw):
        assert method == "GET"
        assert kw.get("timeout") == 8
        if "bad.example.com" in url:
            return 404, ""
        if "good.example.com" in url:
            return 200, _valid_assetlinks("test.pkg")
        pytest.fail(f"unexpected url {url}")

    monkeypatch.setattr(applinks, "call", fake_call)

    out = applinks.run(ctx)
    findings = out["findings"]

    bad = [f for f in findings if f.get("domain") == "bad.example.com"]
    good = [f for f in findings if f.get("domain") == "good.example.com"]
    nopath = [f for f in findings if f.get("type") == "no_path_restriction"]

    assert len(bad) == 1 and "missing" in bad[0]["finding"]
    assert len(good) == 1 and good[0]["package_declared"] is True
    assert len(nopath) == 1 and nopath[0]["activity"] == ".C"


def test_malformed_assetlinks_json(tmp_path: Path, monkeypatch):
    manifest = {
        "package": "test.pkg",
        "deeplinks": [{
            "activity": ".Deep", "schemes": ["https"], "hosts": ["malformed.example.com"],
            "paths": ["/x"], "auto_verify": True, "priority": None,
        }],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)
    monkeypatch.setattr(applinks, "call", lambda *a, **k: (200, "not json {"))
    out = applinks.run(ctx)
    al = [f for f in out["findings"] if f.get("type") == "applink_assetlinks"]
    assert len(al) == 1
    assert "malformed" in al[0]["finding"]


def test_network_error_distinguished_from_4xx(tmp_path: Path, monkeypatch):
    manifest = {
        "package": "test.pkg",
        "deeplinks": [{
            "activity": ".Deep", "schemes": ["https"], "hosts": ["dead.example.com"],
            "paths": ["/x"], "auto_verify": True, "priority": None,
        }],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)
    monkeypatch.setattr(applinks, "call", lambda *a, **k: (0, "NETERR:dns"))
    out = applinks.run(ctx)
    al = [f for f in out["findings"] if f.get("type") == "applink_assetlinks"]
    assert len(al) == 1
    assert "unreachable" in al[0]["finding"]


def test_assetlinks_fetched_once_per_host(tmp_path: Path, monkeypatch):
    """Two intent-filters on the same host → only one network call."""
    manifest = {
        "package": "test.pkg",
        "deeplinks": [
            {"activity": ".A", "schemes": ["https"], "hosts": ["dup.example.com"],
             "paths": ["/x"], "auto_verify": True, "priority": None},
            {"activity": ".B", "schemes": ["https"], "hosts": ["dup.example.com"],
             "paths": ["/y"], "auto_verify": True, "priority": None},
        ],
    }
    ctx = _ctx_with_manifest(tmp_path, manifest)
    calls = []

    def fake_call(method, url, **kw):
        calls.append(url)
        return 200, _valid_assetlinks("test.pkg")

    monkeypatch.setattr(applinks, "call", fake_call)
    applinks.run(ctx)
    assert len(calls) == 1
