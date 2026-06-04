"""Unit tests for the build-leaks scanner."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.config import RunContext
from clawditor.scan.build_leaks import DEBUG_CERT_SHA1, run as run_build_leaks


def _xml(name: str, body: str, root: Path) -> Path:
    p = root / "smali" / "resources" / "test.pkg" / "res" / "values" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _smali(rel: str, body: str, root: Path) -> Path:
    p = root / "smali" / "classes" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _seed_minimal(tmp_run: RunContext) -> None:
    # Decompiled tree skeleton
    (tmp_run.decompiled_dir / "smali").mkdir(parents=True, exist_ok=True)


def test_detects_unresolved_placeholder_in_resource_xml(tmp_run: RunContext):
    _seed_minimal(tmp_run)
    _xml(
        "strings.xml",
        '<resources><string name="api_flag">${myFlag}</string></resources>',
        tmp_run.decompiled_dir,
    )
    d = run_build_leaks(tmp_run)
    assert any(p["value"] == "${myFlag}" for p in d["unresolved_placeholders"])
    # JSON persisted
    saved = json.loads((tmp_run.scan_dir / "build_leaks.json").read_text())
    assert saved == d


def test_detects_staging_url_in_resource_xml(tmp_run: RunContext):
    _seed_minimal(tmp_run)
    _xml(
        "urls.xml",
        '<resources><string name="base_url">https://api-dev.example.com/v1</string>'
        '<string name="prod_url">https://api.example.com/v1</string></resources>',
        tmp_run.decompiled_dir,
    )
    d = run_build_leaks(tmp_run)
    hosts = {h["host"] for h in d["staging_urls"]}
    # At least one hit on the dev-prefixed host
    assert any("api-dev.example.com" in h or "dev.example.com" in h or "dev" in h for h in hosts)
    # Prod URL should not be flagged
    assert not any("api.example.com/v1" in u["value"] and "dev" not in u["value"]
                   for u in d["staging_urls"])


def test_detects_debug_flag_in_smali(tmp_run: RunContext):
    _seed_minimal(tmp_run)
    _smali(
        "com/example/BuildConfig.smali",
        ".class public Lcom/example/BuildConfig;\n"
        ".super Ljava/lang/Object;\n"
        ".field public static final DEBUG:Z = true\n",
        tmp_run.decompiled_dir,
    )
    d = run_build_leaks(tmp_run)
    assert any(f["constant"].upper() == "DEBUG" for f in d["debug_flags"])


def test_detects_debug_cert_sha1_in_signatures(tmp_run: RunContext):
    _seed_minimal(tmp_run)
    sig_dir = tmp_run.decompiled_dir / "smali" / "signatures"
    sig_dir.mkdir(parents=True, exist_ok=True)
    # Write the SHA-1 fingerprint as a hex string (one way it can appear in side files).
    (sig_dir / "0_V2.signature.info.bin").write_bytes(
        b"some preamble\nSHA1 fingerprint: "
        + DEBUG_CERT_SHA1.encode()
        + b"\nrest of cert info\n"
    )
    d = run_build_leaks(tmp_run)
    assert d["debug_signed"] is not None
    assert d["debug_signed"]["indicator"] == "android_debug_cert_sha1_match"


def test_detects_debug_cn_in_signatures(tmp_run: RunContext):
    _seed_minimal(tmp_run)
    sig_dir = tmp_run.decompiled_dir / "smali" / "signatures"
    sig_dir.mkdir(parents=True, exist_ok=True)
    (sig_dir / "0_V2.signature.info.bin").write_bytes(
        b"\x30\x82DER blob with subject CN=Android Debug,O=Android,C=US embedded"
    )
    d = run_build_leaks(tmp_run)
    assert d["debug_signed"] is not None
    assert d["debug_signed"]["indicator"] == "android_debug_cn_match"


def test_detects_test_metadata_via_manifest_json(tmp_run: RunContext):
    _seed_minimal(tmp_run)
    (tmp_run.scan_dir / "manifest.json").write_text(json.dumps({
        "application": {
            "meta_data": [
                {"name": "com.example.TEST_API_URL", "value": "https://test.api.example.com"},
                {"name": "com.example.NORMAL", "value": "production"},
            ],
        },
    }))
    d = run_build_leaks(tmp_run)
    assert any("TEST_API_URL" in e["name"] for e in d["test_metadata"])


def test_no_findings_on_clean_tree(tmp_run: RunContext):
    _seed_minimal(tmp_run)
    _xml(
        "strings.xml",
        '<resources><string name="ok">hello world</string></resources>',
        tmp_run.decompiled_dir,
    )
    d = run_build_leaks(tmp_run)
    assert d["unresolved_placeholders"] == []
    assert d["debug_flags"] == []
    assert d["debug_signed"] is None
    assert d["test_metadata"] == []


def test_dedupes_repeated_placeholders(tmp_run: RunContext):
    _seed_minimal(tmp_run)
    _xml(
        "strings.xml",
        '<resources>'
        '<string name="a">${myFlag}</string>'
        '<string name="b">${myFlag}</string>'  # duplicate in same file → dedup
        '</resources>',
        tmp_run.decompiled_dir,
    )
    d = run_build_leaks(tmp_run)
    # Same (file, value) tuple should appear once after dedupe
    keys = [(p["file"], p["value"]) for p in d["unresolved_placeholders"]]
    assert len(keys) == len(set(keys))
