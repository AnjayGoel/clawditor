"""AndroidManifest analyzer: exported components, cleartext traffic, backup rules, debuggable."""
from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree as ET

from clawditor.config import RunContext
from clawditor.utils import logging as log


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def run(ctx: RunContext) -> dict:
    mf = ctx.manifest_xml
    if not mf.exists():
        log.warn(f"manifest not at {mf}; skipping")
        return {}
    root = ET.parse(mf).getroot()

    application = root.find("application")
    app_attrs = application.attrib if application is not None else {}

    pairip_hit = _detect_pairip(application)
    result = {
        "package": root.attrib.get("package"),
        "version_code": root.attrib.get(f"{ANDROID_NS}versionCode"),
        "version_name": root.attrib.get(f"{ANDROID_NS}versionName"),
        "min_sdk": _find_min_sdk(root),
        "target_sdk": _find_target_sdk(root),
        "application": {
            "debuggable": _attr(app_attrs, "debuggable") == "true",
            "allow_backup": _attr(app_attrs, "allowBackup") != "false",
            "uses_cleartext_traffic": _attr(app_attrs, "usesCleartextTraffic") == "true",
            "network_security_config": _attr(app_attrs, "networkSecurityConfig"),
            "backup_agent": _attr(app_attrs, "backupAgent"),
            "data_extraction_rules": _attr(app_attrs, "dataExtractionRules"),
            "full_backup_content": _attr(app_attrs, "fullBackupContent"),
        },
        "permissions_requested": [p.attrib.get(f"{ANDROID_NS}name") for p in root.findall("uses-permission")],
        "exported_components": _exported_components(application),
        "deeplinks": _deeplinks(application),
        "providers": _providers(application),
        # Pairip = Google Play's anti-piracy framework; presence is enough to require
        # --bypass-pairip during dynamic capture or the app refuses to start past splash.
        "has_pairip": bool(pairip_hit),
        "pairip_hit": pairip_hit,
    }

    out = ctx.scan_dir / "manifest.json"
    out.write_text(json.dumps(result, indent=2))

    n_exp = sum(len(v) for v in result["exported_components"].values())
    log.ok(f"manifest: {n_exp} exported component(s), {len(result['deeplinks'])} deeplink filter(s)")
    return result


def _attr(d: dict, name: str) -> str:
    return d.get(f"{ANDROID_NS}{name}", "")


def _find_min_sdk(root) -> str | None:
    u = root.find("uses-sdk")
    return _attr(u.attrib, "minSdkVersion") if u is not None else None


def _find_target_sdk(root) -> str | None:
    u = root.find("uses-sdk")
    return _attr(u.attrib, "targetSdkVersion") if u is not None else None


def _exported_components(application) -> dict:
    """Return dict {activities: [...], services: [...], receivers: [...], providers: [...]} of exported ones."""
    out = {"activities": [], "services": [], "receivers": [], "providers": []}
    if application is None:
        return out
    kinds = {"activity": "activities", "service": "services", "receiver": "receivers", "provider": "providers"}
    for tag, key in kinds.items():
        for el in application.findall(tag):
            name = el.attrib.get(f"{ANDROID_NS}name")
            exported = el.attrib.get(f"{ANDROID_NS}exported")
            permission = el.attrib.get(f"{ANDROID_NS}permission")
            has_intent_filter = el.find("intent-filter") is not None
            # Default exported = true if intent-filter present AND no explicit attr (pre-S, but most apps now declare)
            is_exported = exported == "true" or (exported is None and has_intent_filter)
            if is_exported:
                out[key].append({
                    "name": name,
                    "exported_attr": exported,
                    "permission": permission,
                    "has_intent_filter": has_intent_filter,
                })
    return out


def _deeplinks(application) -> list[dict]:
    if application is None:
        return []
    links = []
    for activity in application.findall("activity"):
        for filt in activity.findall("intent-filter"):
            schemes, hosts, paths = [], [], []
            for data in filt.findall("data"):
                if (s := data.attrib.get(f"{ANDROID_NS}scheme")):
                    schemes.append(s)
                if (h := data.attrib.get(f"{ANDROID_NS}host")):
                    hosts.append(h)
                for k in ("path", "pathPrefix", "pathPattern"):
                    if (v := data.attrib.get(f"{ANDROID_NS}{k}")):
                        paths.append(v)
            if schemes:
                auto_verify = filt.attrib.get(f"{ANDROID_NS}autoVerify") == "true"
                priority = filt.attrib.get(f"{ANDROID_NS}priority")
                links.append({
                    "activity": activity.attrib.get(f"{ANDROID_NS}name"),
                    "schemes": schemes,
                    "hosts": hosts,
                    "paths": paths,
                    "auto_verify": auto_verify,
                    "priority": priority,
                })
    return links


def _detect_pairip(application) -> str | None:
    """Return the first `com.pairip.*` component name found in <application>, or None.

    Pairip is Google Play's anti-piracy framework. Apps wrapped with it refuse
    to run when sideloaded because the license check fails outside Play.
    A typical wrapped app exposes ``com.pairip.licensecheck.LicenseActivity``
    plus ``com.pairip.application.Application`` (as the app's main Application).
    Manifest detection is sufficient — no need to grep smali.
    """
    if application is None:
        return None
    # Check the application class itself (Pairip wraps the app's Application class).
    app_name = application.attrib.get(f"{ANDROID_NS}name") or ""
    if app_name.startswith("com.pairip."):
        return app_name
    for tag in ("activity", "service", "receiver", "provider"):
        for el in application.findall(tag):
            name = el.attrib.get(f"{ANDROID_NS}name") or ""
            if name.startswith("com.pairip."):
                return name
    return None


def _providers(application) -> list[dict]:
    if application is None:
        return []
    out = []
    for p in application.findall("provider"):
        out.append({
            "name": p.attrib.get(f"{ANDROID_NS}name"),
            "authorities": p.attrib.get(f"{ANDROID_NS}authorities"),
            "exported": p.attrib.get(f"{ANDROID_NS}exported"),
            "grant_uri_permissions": p.attrib.get(f"{ANDROID_NS}grantUriPermissions"),
            "read_permission": p.attrib.get(f"{ANDROID_NS}readPermission"),
            "write_permission": p.attrib.get(f"{ANDROID_NS}writePermission"),
        })
    return out
