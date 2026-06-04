"""PII / sensitive identifier reads — DPDP / GDPR / CCPA relevance.

Flags reads of hardware identifiers (IMEI, IMSI, MAC, serial, Android ID),
user content (contacts, SMS, call log, calendar, clipboard), account
enumeration, installed-apps enumeration, and location / cell / Wi-Fi scan
results. Vendor SDKs commonly read these for legitimate analytics — the
findings collector applies `split_vendor` to demote vendor matches.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log


# Pattern key → (compiled regex, kind, severity, description)
PATTERNS: dict[str, tuple[re.Pattern, str, str, str]] = {
    # Hardware identifiers
    "telephony_get_device_id": (
        re.compile(r"\.getDeviceId\s*\("),
        "imei_read", "HIGH",
        "IMEI read via TelephonyManager.getDeviceId() — restricted on Android 10+ and DPDP-relevant",
    ),
    "telephony_get_imei": (
        re.compile(r"\.getImei\s*\("),
        "imei_read", "HIGH",
        "IMEI read via TelephonyManager.getImei()",
    ),
    "telephony_get_subscriber_id": (
        re.compile(r"\.getSubscriberId\s*\("),
        "imsi_read", "HIGH",
        "IMSI read via TelephonyManager.getSubscriberId()",
    ),
    "telephony_get_line1_number": (
        re.compile(r"\.getLine1Number\s*\("),
        "phone_number_read", "HIGH",
        "Phone number read",
    ),
    "telephony_get_simserialnumber": (
        re.compile(r"\.getSimSerialNumber\s*\("),
        "sim_serial_read", "MEDIUM",
        "SIM serial number read",
    ),
    "wifi_get_mac_address": (
        re.compile(r"\.getMacAddress\s*\("),
        "mac_read", "MEDIUM",
        "MAC address read (returns 02:00:00:00:00:00 on Android 6+; still suspicious)",
    ),
    "android_id_read": (
        re.compile(r'Settings\.Secure\.ANDROID_ID|"android_id"'),
        "android_id_read", "LOW",
        "Android ID read",
    ),
    "bluetooth_get_address": (
        re.compile(r"BluetoothAdapter[^;]*\.getAddress\s*\("),
        "bluetooth_mac_read", "MEDIUM",
        "Bluetooth MAC address read",
    ),
    "build_serial_read": (
        re.compile(r"Build\.SERIAL\b|Build\.getSerial\s*\("),
        "device_serial_read", "MEDIUM",
        "Device serial number read",
    ),
    # User content
    "clipboard_read": (
        re.compile(r"ClipboardManager[^;]*\.getPrimaryClip\s*\("),
        "clipboard_read", "MEDIUM",
        "Clipboard read — sensitive if at launch / background",
    ),
    "contacts_uri_read": (
        re.compile(r"ContactsContract\.[A-Za-z.]+_URI"),
        "contacts_read", "MEDIUM",
        "Contacts URI accessed",
    ),
    "sms_uri_read": (
        re.compile(r'"content://sms"|Telephony\.Sms\.CONTENT_URI'),
        "sms_read", "HIGH",
        "SMS provider URI accessed",
    ),
    "call_log_read": (
        re.compile(r"CallLog\.Calls\.CONTENT_URI"),
        "call_log_read", "HIGH",
        "Call log URI accessed",
    ),
    "calendar_read": (
        re.compile(r"CalendarContract\.Events\.CONTENT_URI"),
        "calendar_read", "LOW",
        "Calendar URI accessed",
    ),
    "location_request": (
        re.compile(r"\.requestLocationUpdates\s*\(|LocationManager\.GPS_PROVIDER|FusedLocationProviderClient"),
        "location_request", "INFO",
        "Location request made",
    ),
    # Microphone / camera (inventory; most legitimate)
    "audio_record_start": (
        re.compile(r"\bnew\s+AudioRecord\s*\("),
        "microphone_access", "INFO",
        "AudioRecord instantiated",
    ),
    "media_recorder_start": (
        re.compile(r"\bnew\s+MediaRecorder\s*\("),
        "microphone_access", "INFO",
        "MediaRecorder instantiated",
    ),
    "camera_open": (
        re.compile(r"Camera\.open\s*\(|CameraManager\.openCamera\s*\("),
        "camera_access", "INFO",
        "Camera opened",
    ),
    # Account access
    "account_get_accounts": (
        re.compile(r"AccountManager[^;]*\.getAccounts\s*\("),
        "accounts_read", "HIGH",
        "All accounts on device enumerated",
    ),
    # Installed apps enumeration (Android 11+ requires special permission)
    "installed_apps_list": (
        re.compile(r"getInstalledApplications\s*\(|getInstalledPackages\s*\(|queryIntentActivities\s*\("),
        "installed_apps_read", "MEDIUM",
        "Installed app list queried (privacy-sensitive on Android 11+)",
    ),
    # Network info that leaks user location/identity
    "wifi_scan_results": (
        re.compile(r"\.getScanResults\s*\("),
        "wifi_scan_results_read", "MEDIUM",
        "Wi-Fi scan results read — discloses BSSIDs / SSIDs around the user",
    ),
    "telephony_get_cellinfo": (
        re.compile(r"\.getAllCellInfo\s*\("),
        "cell_info_read", "MEDIUM",
        "Cell tower info read — coarse geolocation possible without permission",
    ),
}


SEARCH_DIRS = ("jadx/sources", "smali", "hermes")
_SKIP_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".bin",
             ".dex", ".odex", ".vdex", ".arsc", ".ttf", ".otf", ".woff", ".so"}
_MAX_BYTES = 10 * 1024 * 1024


def run(ctx: RunContext) -> dict:
    hits: dict[str, list[dict]] = {k: [] for k in PATTERNS}
    seen: dict[str, set[str]] = {k: set() for k in PATTERNS}

    for sub in SEARCH_DIRS:
        base = ctx.decompiled_dir / sub
        if not base.exists():
            continue
        for p in _iter_text_files(base):
            try:
                txt = p.read_text(errors="ignore")
            except Exception:
                continue
            rel = str(p.relative_to(ctx.decompiled_dir))
            for name, (rx, kind, sev, desc) in PATTERNS.items():
                if rel in seen[name]:
                    continue
                if rx.search(txt):
                    hits[name].append({
                        "file": rel,
                        "kind": kind,
                        "severity": sev,
                        "description": desc,
                    })
                    seen[name].add(rel)

    # Aggregate by kind for the JSON output
    by_kind: dict[str, list[dict]] = {}
    for pattern_name, items in hits.items():
        for it in items:
            by_kind.setdefault(it["kind"], []).append(
                {"file": it["file"], "pattern": pattern_name}
            )

    out = {"by_kind": by_kind, "by_pattern": hits}
    (ctx.scan_dir / "privacy.json").write_text(json.dumps(out, indent=2))
    n = sum(len(v) for v in by_kind.values())
    log.ok(f"privacy: {n} PII access(es) across {len(by_kind)} kind(s)")
    return out


def _iter_text_files(base: Path):
    for p in Path(base).rglob("*"):
        if not p.is_file() or p.suffix.lower() in _SKIP_EXT:
            continue
        try:
            if p.stat().st_size > _MAX_BYTES and p.name != "decompiled.js":
                continue
        except OSError:
            continue
        yield p
