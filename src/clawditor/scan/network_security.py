"""Parse the Android Network Security Config XML referenced by the manifest."""
from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from clawditor.config import RunContext
from clawditor.utils import logging as log


PLACEHOLDER_RX = re.compile(r"\$\{[^}]+\}")
RESOURCE_REF_RX = re.compile(r"^@xml/(?P<name>[A-Za-z0-9_]+)$")
IP_RX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def run(ctx: RunContext) -> dict:
    result: dict = {
        "nsc_path": None,
        "base_config": None,
        "domain_configs": [],
        "pin_sets": [],
        "user_trust_anchor": False,
        "gradle_placeholders": [],
        "cleartext_domains": [],
        "summary": "",
    }

    manifest_json = ctx.scan_dir / "manifest.json"
    if not manifest_json.exists():
        log.warn("network_security: manifest.json not found; skipping")
        _write(ctx, result)
        return result
    try:
        mf = json.loads(manifest_json.read_text())
    except Exception:
        _write(ctx, result)
        return result

    ref = (mf.get("application") or {}).get("network_security_config") or ""
    m = RESOURCE_REF_RX.match(ref)
    nsc_name = m.group("name") if m else None

    nsc_path = _find_nsc_file(ctx.smali_dir, nsc_name)
    if not nsc_path:
        log.ok("network_security: no NSC XML present")
        result["summary"] = "no NSC configured"
        _write(ctx, result)
        return result
    result["nsc_path"] = str(nsc_path.relative_to(ctx.decompiled_dir))

    try:
        root = ET.parse(nsc_path).getroot()
    except ET.ParseError as e:
        log.warn(f"network_security: failed to parse {nsc_path}: {e}")
        _write(ctx, result)
        return result

    # base-config
    base = root.find("base-config")
    if base is not None:
        result["base_config"] = _config_summary(base)
        _collect_placeholders(base, result["gradle_placeholders"], "base-config")

    # domain-config (can nest)
    for dc in _iter_domain_configs(root):
        summary = _config_summary(dc)
        domains = [d.text.strip() for d in dc.findall("domain") if d.text]
        summary["domains"] = domains
        result["domain_configs"].append(summary)
        if summary.get("cleartext_permitted") is True:
            for d in domains:
                if not IP_RX.match(d):
                    result["cleartext_domains"].append(d)
        _collect_placeholders(dc, result["gradle_placeholders"], "domain-config")

    # pin-sets (anywhere)
    for ps in root.iter("pin-set"):
        pins = [{"digest": p.attrib.get("digest", ""), "value": (p.text or "").strip()}
                for p in ps.findall("pin")]
        # Find owning domain-config (parent) — ET doesn't expose parents; do shallow lookup
        owner = _find_owning_domains(root, ps)
        result["pin_sets"].append({"domains": owner, "pins": pins,
                                   "expiration": ps.attrib.get("expiration")})

    # trust-anchors / user-installed CAs
    for ta in root.iter("trust-anchors"):
        for cert in ta.findall("certificates"):
            src = cert.attrib.get("src", "")
            if src == "user":
                result["user_trust_anchor"] = True

    parts = []
    if result["gradle_placeholders"]:
        parts.append(f"{len(result['gradle_placeholders'])} unresolved placeholder(s)")
    if result["user_trust_anchor"]:
        parts.append("user-CA trust enabled")
    if result["cleartext_domains"]:
        parts.append(f"{len(result['cleartext_domains'])} cleartext domain(s)")
    if result["pin_sets"]:
        parts.append(f"{len(result['pin_sets'])} pin-set(s)")
    result["summary"] = "; ".join(parts) if parts else "NSC present, no flagged issues"

    _write(ctx, result)
    log.ok(f"network_security: {result['summary']}")
    return result


def _write(ctx: RunContext, result: dict) -> None:
    (ctx.scan_dir / "network_security.json").write_text(json.dumps(result, indent=2))


def _find_nsc_file(smali_dir: Path, name: str | None) -> Path | None:
    if not smali_dir.exists():
        return None
    candidates: list[Path] = []
    target_names = []
    if name:
        target_names.append(f"{name}.xml")
    # Always also accept the default conventional names
    for default in ("network_security_config.xml", "network_security.xml"):
        if default not in target_names:
            target_names.append(default)
    for fname in target_names:
        candidates.extend(smali_dir.rglob(fname))
    # Prefer files under res/xml/
    for c in candidates:
        if "res/xml" in str(c).replace("\\", "/"):
            return c
    return candidates[0] if candidates else None


def _iter_domain_configs(root):
    """Yield every <domain-config>, including nested ones."""
    for dc in root.iter("domain-config"):
        yield dc


def _config_summary(el) -> dict:
    cleartext = el.attrib.get("cleartextTrafficPermitted")
    parsed = None
    if cleartext is not None and not PLACEHOLDER_RX.search(cleartext):
        parsed = cleartext.lower() == "true"
    return {
        "cleartext_permitted_raw": cleartext,
        "cleartext_permitted": parsed,
    }


def _collect_placeholders(el, sink: list, where: str) -> None:
    for k, v in el.attrib.items():
        for m in PLACEHOLDER_RX.findall(v):
            sink.append({"where": where, "attr": k, "value": v, "placeholder": m})
    for child in list(el):
        _collect_placeholders(child, sink, where)


def _find_owning_domains(root, pin_set) -> list[str]:
    for dc in root.iter("domain-config"):
        for child in list(dc):
            if child is pin_set:
                return [d.text.strip() for d in dc.findall("domain") if d.text]
    return []


if __name__ == "__main__":  # pragma: no cover
    import sys
    out = Path(sys.argv[1])
    ctx = RunContext(package=None, apk_input=None, out_dir=out)
    run(ctx)
