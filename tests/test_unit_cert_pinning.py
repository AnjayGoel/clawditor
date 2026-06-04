"""Unit tests for the cert-pinning scanner."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.config import RunContext
from clawditor.scan.cert_pinning import run as run_cp


PINNED_JAVA = """package com.example;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

class Net {
    static OkHttpClient build() {
        CertificatePinner pinner = new CertificatePinner.Builder()
                .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build();
        return new OkHttpClient.Builder()
                .certificatePinner(pinner)
                .build();
    }
}
"""

UNPINNED_JAVA = """package com.example;
import okhttp3.OkHttpClient;

class Plain {
    static OkHttpClient build() {
        return new OkHttpClient.Builder()
                .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                .build();
    }
}
"""

TRUSTKIT_JAVA = """package com.example;
import com.datatheorem.android.trustkit.TrustKit;

class T { static void init() { TrustKit.initializeWithNetworkSecurityConfiguration(null); } }
"""


def _seed_sources(ctx: RunContext, files: dict[str, str]) -> None:
    src = ctx.jadx_dir / "sources"
    src.mkdir(parents=True, exist_ok=True)
    for rel, txt in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt)


def test_detects_pinner_and_unpinned_builder(tmp_run: RunContext):
    _seed_sources(tmp_run, {
        "com/example/Net.java": PINNED_JAVA,
        "com/example/Plain.java": UNPINNED_JAVA,
        "com/example/TK.java": TRUSTKIT_JAVA,
    })
    d = run_cp(tmp_run)
    # Pinned file: CertificatePinner.Builder + .certificatePinner( hits
    types = {p["type"] for p in d["pinners_found"]}
    assert "OkHttpCertificatePinner" in types
    assert "OkHttpCertificatePinnerApply" in types
    # TrustKit detected
    assert d["trust_kit_used"] is True
    # Unpinned: Plain.java has builder but no .certificatePinner -> flagged
    files_no_pin = {e["file"] for e in d["okhttp_without_pinning"]}
    assert any("Plain.java" in f for f in files_no_pin)
    assert not any("Net.java" in f for f in files_no_pin)


def test_sensitive_app_heuristic_via_package_name(tmp_path: Path):
    ctx = RunContext("com.mybank.wallet", None, tmp_path); ctx.ensure_dirs()
    _seed_sources(ctx, {"a.java": UNPINNED_JAVA})
    d = run_cp(ctx)
    assert d["sensitive_app"] is True
    assert d["okhttp_without_pinning"]
    assert d["pinners_found"] == []


def test_sensitive_app_heuristic_via_billing_permission(tmp_path: Path):
    ctx = RunContext("com.example.benign", None, tmp_path); ctx.ensure_dirs()
    (ctx.scan_dir / "manifest.json").write_text(json.dumps({
        "package": "com.example.benign",
        "permissions_requested": ["com.android.vending.BILLING"],
    }))
    _seed_sources(ctx, {"a.java": UNPINNED_JAVA})
    d = run_cp(ctx)
    assert d["sensitive_app"] is True


def test_no_source_tree_does_not_crash(tmp_run: RunContext):
    d = run_cp(tmp_run)
    assert d["pinners_found"] == []
    assert (tmp_run.scan_dir / "cert_pinning.json").exists()
