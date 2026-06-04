"""Unit tests for the S3 bucket active probe."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawditor.config import RunContext
from clawditor.probe import s3_buckets


LIST_BUCKET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    '<Name>acme-public</Name><KeyCount>1</KeyCount>'
    '<Contents><Key>index.html</Key></Contents>'
    '</ListBucketResult>'
)

NO_SUCH_BUCKET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Error><Code>NoSuchBucket</Code>'
    '<Message>The specified bucket does not exist</Message></Error>'
)


def _ctx_with_secrets(tmp_path: Path, secrets: dict) -> RunContext:
    ctx = RunContext("p", None, tmp_path)
    ctx.ensure_dirs()
    (ctx.scan_dir / "secrets.json").write_text(json.dumps(secrets))
    return ctx


def test_listable_bucket(tmp_path: Path, monkeypatch):
    secrets = {"s3_bucket_url": [{"value": "https://acme-public.s3.amazonaws.com",
                                    "file": "x.java"}]}
    ctx = _ctx_with_secrets(tmp_path, secrets)

    def fake_call(method, url, **kw):
        if url.endswith(".amazonaws.com/"):
            return 200, LIST_BUCKET_XML
        # any common-path fetch — return 403
        return 403, "<Error><Code>AccessDenied</Code></Error>"

    monkeypatch.setattr("clawditor.probe.s3_buckets.call", fake_call)
    out = s3_buckets.run(ctx)
    assert out["acme-public"]["listable"] is True
    assert out["acme-public"]["exists"] is True


def test_private_bucket_returns_403(tmp_path: Path, monkeypatch):
    secrets = {"s3_bucket_url": [{"value": "https://locked.s3.us-east-1.amazonaws.com",
                                    "file": "x.java"}]}
    ctx = _ctx_with_secrets(tmp_path, secrets)

    def fake_call(method, url, **kw):
        return 403, "<Error><Code>AccessDenied</Code></Error>"

    monkeypatch.setattr("clawditor.probe.s3_buckets.call", fake_call)
    out = s3_buckets.run(ctx)
    r = out["locked"]
    assert r["listable"] is False
    assert r["exists"] is True


def test_no_such_bucket(tmp_path: Path, monkeypatch):
    secrets = {"s3_bucket_url": [{"value": "https://ghost.s3.amazonaws.com", "file": "x"}]}
    ctx = _ctx_with_secrets(tmp_path, secrets)

    def fake_call(method, url, **kw):
        return 404, NO_SUCH_BUCKET_XML

    monkeypatch.setattr("clawditor.probe.s3_buckets.call", fake_call)
    out = s3_buckets.run(ctx)
    r = out["ghost"]
    assert r["exists"] is False
    # No common-path probes should be issued for a nonexistent bucket.
    assert r["path_probe"] == {}


def test_enumeration_suffixes_are_tried(tmp_path: Path, monkeypatch):
    secrets = {"s3_bucket_url": [{"value": "https://acme.s3.amazonaws.com", "file": "x"}]}
    ctx = _ctx_with_secrets(tmp_path, secrets)

    seen_buckets: set[str] = set()

    def fake_call(method, url, **kw):
        # url like https://<bucket>.s3.amazonaws.com/...
        host = url.split("//", 1)[1].split("/", 1)[0]
        bucket = host.split(".")[0]
        seen_buckets.add(bucket)
        return 404, NO_SUCH_BUCKET_XML

    monkeypatch.setattr("clawditor.probe.s3_buckets.call", fake_call)
    out = s3_buckets.run(ctx)
    # The original + all five suffixes
    for suf in ("", "-staging", "-backup", "-uploads", "-dev", "-prod"):
        assert f"acme{suf}" in out
        assert f"acme{suf}" in seen_buckets
    # Suffix variants are marked as guessed
    assert out["acme"]["guessed"] is False
    assert out["acme-staging"]["guessed"] is True


def test_virtual_path_url_extracts_bucket(tmp_path: Path, monkeypatch):
    secrets = {
        "s3_virtual_path_url": [{"value": "https://s3.amazonaws.com/path-bucket",
                                    "file": "x"}],
    }
    ctx = _ctx_with_secrets(tmp_path, secrets)

    def fake_call(method, url, **kw):
        return 403, ""

    monkeypatch.setattr("clawditor.probe.s3_buckets.call", fake_call)
    out = s3_buckets.run(ctx)
    assert "path-bucket" in out


def test_public_partial_200_no_listing(tmp_path: Path, monkeypatch):
    secrets = {"s3_bucket_url": [{"value": "https://semi.s3.amazonaws.com", "file": "x"}]}
    ctx = _ctx_with_secrets(tmp_path, secrets)

    def fake_call(method, url, **kw):
        # Listing endpoint returns 200 but body is some HTML (not ListBucketResult)
        if url.endswith(".amazonaws.com/"):
            return 200, "<html>welcome</html>"
        return 403, ""

    monkeypatch.setattr("clawditor.probe.s3_buckets.call", fake_call)
    out = s3_buckets.run(ctx)
    r = out["semi"]
    assert r["listable"] is False
    assert r.get("public_partial") is True


def test_no_buckets_returns_empty(tmp_path: Path, monkeypatch):
    ctx = _ctx_with_secrets(tmp_path, {})
    monkeypatch.setattr("clawditor.probe.s3_buckets.call",
                        lambda *a, **k: pytest.fail("should not have been called"))
    out = s3_buckets.run(ctx)
    assert out == {}
