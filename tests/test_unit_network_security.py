"""Unit tests for the network security config parser."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.config import RunContext
from clawditor.scan.network_security import run as run_nsc


NSC_WITH_PLACEHOLDER = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="${ipHittingEnabled}">
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2026-01-01">
      <pin digest="SHA-256">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=</pin>
    </pin-set>
  </domain-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain>internal.example.org</domain>
    <domain>10.0.0.1</domain>
  </domain-config>
</network-security-config>
"""


def _write_manifest(ctx: RunContext, nsc_ref: str | None) -> None:
    p = ctx.scan_dir / "manifest.json"
    p.write_text(json.dumps({
        "application": {"network_security_config": nsc_ref},
        "permissions_requested": [],
    }))


def test_parses_placeholder_user_ca_and_cleartext(tmp_run: RunContext):
    # Put NSC under decompiled/smali/resources/<pkg>/res/xml/
    nsc_dir = tmp_run.smali_dir / "resources" / "test.pkg" / "res" / "xml"
    nsc_dir.mkdir(parents=True, exist_ok=True)
    (nsc_dir / "network_security_config.xml").write_text(NSC_WITH_PLACEHOLDER)
    _write_manifest(tmp_run, "@xml/network_security_config")

    d = run_nsc(tmp_run)
    assert d["nsc_path"] is not None
    assert d["user_trust_anchor"] is True
    # Gradle placeholder picked up
    assert any(p["placeholder"] == "${ipHittingEnabled}" for p in d["gradle_placeholders"])
    # cleartext non-IP domain flagged
    assert "internal.example.org" in d["cleartext_domains"]
    # IP-literal domain NOT flagged
    assert "10.0.0.1" not in d["cleartext_domains"]
    # Pin-set captured with owning domain
    assert len(d["pin_sets"]) == 1
    assert d["pin_sets"][0]["domains"] == ["api.example.com"]
    assert d["pin_sets"][0]["pins"][0]["digest"] == "SHA-256"


def test_no_nsc_reference_handled(tmp_run: RunContext):
    _write_manifest(tmp_run, "")
    d = run_nsc(tmp_run)
    assert d["nsc_path"] is None
    assert d["gradle_placeholders"] == []


def test_no_manifest_handled(tmp_run: RunContext):
    d = run_nsc(tmp_run)
    assert (tmp_run.scan_dir / "network_security.json").exists()
    assert d["nsc_path"] is None
