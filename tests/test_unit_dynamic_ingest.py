"""Unit tests for clawditor.dynamic.ingest.

mitmproxy is intentionally NOT a hard clawditor dependency (it's an external CLI
tool installed via brew + a script). When it isn't present in the venv these
tests skip with a clear message.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


pytest.importorskip(
    "mitmproxy",
    reason="mitmproxy not installed in this venv; ingest tests need its FlowWriter."
)


def _build_flow_file(tmp_path: Path) -> Path:
    """Write 3 fake HTTPS flows in mitmproxy stream format to a temp file."""
    from mitmproxy import http
    from mitmproxy.io import FlowWriter
    from mitmproxy.test import tflow

    flow_path = tmp_path / "flows.mitm"
    with flow_path.open("wb") as fh:
        w = FlowWriter(fh)

        # 1. Plain API call with Authorization header + JWT in response body.
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9."
            "abcdefghijklmnopqrstuvwx12345678"
        )
        f1 = tflow.tflow(
            req=tflow.treq(host="api.example.com", path="/v1/login", method=b"POST"),
            resp=tflow.tresp(content=f'{{"token":"{jwt}"}}'.encode()),
        )
        f1.request.headers["Authorization"] = "Bearer xyz"
        w.add(f1)

        # 2. Firestore document read.
        f2 = tflow.tflow(
            req=tflow.treq(
                host="firestore.googleapis.com",
                path="/v1/projects/myproj/databases/(default)/documents/users?pageSize=1",
                method=b"GET",
            ),
            resp=tflow.tresp(content=b'{"documents":[]}'),
        )
        w.add(f2)

        # 3. Firebase Storage object fetch (URL-encoded path).
        f3 = tflow.tflow(
            req=tflow.treq(
                host="firebasestorage.googleapis.com",
                path="/v0/b/myproj.appspot.com/o/users%2F123%2Favatar.jpg",
                method=b"GET",
            ),
            resp=tflow.tresp(content=b"\x89PNG..."),
        )
        w.add(f3)

    return flow_path


def test_ingest_summarizes_hosts_endpoints_and_special_paths(tmp_path: Path):
    from clawditor.dynamic.ingest import ingest

    flow_file = _build_flow_file(tmp_path)
    out_json = tmp_path / "dynamic_capture.json"
    summary = ingest(flow_file, out_json, package="com.test.app", duration_s=42)

    # File written + matches return value.
    assert out_json.exists()
    on_disk = json.loads(out_json.read_text())
    assert on_disk == summary

    # Shape + content.
    assert summary["duration_s"] == 42
    assert summary["package"] == "com.test.app"
    assert summary["host_count"] == 3
    assert set(summary["hosts"]) == {
        "api.example.com",
        "firestore.googleapis.com",
        "firebasestorage.googleapis.com",
    }
    assert "/v1/login" in summary["endpoints"]["api.example.com"]

    # Firestore extraction:
    assert summary["firestore"]["projects"] == ["myproj"]
    assert summary["firestore"]["collections"] == ["users"]

    # Storage extraction (path decoded):
    assert summary["storage"]["buckets"] == ["myproj.appspot.com"]
    assert "users/123/avatar.jpg" in summary["storage"]["paths_observed"]

    # Auth + JWT counters:
    assert summary["auth_token_count"] == 1
    assert summary["jwts_in_responses"] == 1


def test_ingest_handles_empty_flow_file(tmp_path: Path):
    from clawditor.dynamic.ingest import ingest

    empty = tmp_path / "empty.mitm"
    empty.write_bytes(b"")
    out_json = tmp_path / "out.json"
    summary = ingest(empty, out_json, package="x", duration_s=0)
    assert summary["host_count"] == 0
    assert summary["hosts"] == []
    assert summary["firestore"]["collections"] == []
