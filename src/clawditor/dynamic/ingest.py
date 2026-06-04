"""Post-process a mitmproxy flow file into a small JSON capture summary.

Extracts: unique hosts, unique URL paths per host, real Firestore collection IDs,
real Storage paths, JWT shapes seen in responses, count of Authorization-bearing
requests. The static probes downstream (probe/firebase_firestore.py,
probe/firebase_storage.py) can consume these to confirm rule exposure on the
exact endpoints the app actually hits, rather than guessing.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable


# Matches /v1/projects/<project>/databases/(default)/documents/<collection>[/<doc>...]
_FIRESTORE_PATH = re.compile(
    r"/v1/projects/(?P<project>[^/]+)/databases/[^/]+/documents/(?P<rest>[^?#]+)"
)
# Matches /v0/b/<bucket>/o[/<path>]
_STORAGE_PATH = re.compile(r"/v0/b/(?P<bucket>[^/]+)/o(?:/(?P<obj>[^?#]+))?")
# Permissive JWT shape (b64url . b64url . b64url, header starts with eyJ)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


def _load_flows(flow_file: Path) -> Iterable[dict]:
    """Yield ``{host, path, method, status, req_headers, resp_text}`` dicts.

    Requires the ``mitmproxy`` package to be importable in the current venv.
    Raises ``ImportError`` with a clear message otherwise — we don't add
    mitmproxy as a hard clawditor dep, but ingest is unusable without it.
    """
    try:
        from mitmproxy import io as mio  # type: ignore
        from mitmproxy.http import HTTPFlow  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "mitmproxy Python API not available in this venv. Install with "
            "`uv pip install mitmproxy` or `pip install mitmproxy` in .venv. "
            "(mitmproxy is intentionally not a hard clawditor dependency — "
            "it's used here only by the dynamic-analysis post-processor.)"
        ) from e

    with flow_file.open("rb") as f:
        reader = mio.FlowReader(f)
        for flow in reader.stream():
            if not isinstance(flow, HTTPFlow):
                continue
            req = flow.request
            rsp = flow.response
            yield {
                "host": req.pretty_host or req.host or "",
                "path": req.path or "",
                "method": req.method or "",
                "status": (rsp.status_code if rsp else 0),
                "req_headers": {k.lower(): v for k, v in (req.headers.items() if req.headers else [])},
                "resp_text": (rsp.get_text(strict=False) or "" if rsp else ""),
            }


def _summarize(records: Iterable[dict], package: str, duration_s: int) -> dict:
    hosts: set[str] = set()
    endpoints: dict[str, set[str]] = defaultdict(set)
    methods: dict[str, int] = defaultdict(int)
    statuses: dict[str, int] = defaultdict(int)
    firestore_projects: set[str] = set()
    firestore_collections: set[str] = set()
    storage_buckets: set[str] = set()
    storage_paths: set[str] = set()
    auth_count = 0
    jwt_count = 0

    for r in records:
        host = r["host"]
        path = r["path"]
        if host:
            hosts.add(host)
            if path:
                endpoints[host].add(path)
        methods[r["method"] or "?"] += 1
        statuses[str(r["status"] or 0)] += 1
        if r["req_headers"].get("authorization"):
            auth_count += 1

        if "firestore.googleapis.com" in host:
            m = _FIRESTORE_PATH.search(path)
            if m:
                firestore_projects.add(m.group("project"))
                rest = m.group("rest").split("/")[0]
                if rest:
                    firestore_collections.add(rest)
        if "firebasestorage.googleapis.com" in host:
            m = _STORAGE_PATH.search(path)
            if m:
                storage_buckets.add(m.group("bucket"))
                obj = m.group("obj")
                if obj:
                    # mitm leaves URL-encoded; cheap unescape:
                    storage_paths.add(obj.replace("%2F", "/"))

        body = r["resp_text"]
        if body and _JWT.search(body):
            jwt_count += 1

    return {
        "duration_s": duration_s,
        "package": package,
        "host_count": len(hosts),
        "hosts": sorted(hosts),
        "endpoints": {h: sorted(eps) for h, eps in sorted(endpoints.items())},
        "request_methods": dict(sorted(methods.items())),
        "response_status_counts": dict(sorted(statuses.items())),
        "firestore": {
            "projects": sorted(firestore_projects),
            "collections": sorted(firestore_collections),
        },
        "storage": {
            "buckets": sorted(storage_buckets),
            "paths_observed": sorted(storage_paths),
        },
        "auth_token_count": auth_count,
        "jwts_in_responses": jwt_count,
    }


def ingest(flow_file: Path, out_json: Path, *, package: str = "", duration_s: int = 0) -> dict:
    """Read ``flow_file`` (mitmproxy stream format), write a JSON summary, return the dict."""
    records = list(_load_flows(flow_file))
    summary = _summarize(records, package=package, duration_s=duration_s)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(summary, indent=2))
    return summary
