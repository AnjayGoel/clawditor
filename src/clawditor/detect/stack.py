"""Detect cross-platform framework signals."""
from __future__ import annotations

import json
import zipfile

from clawditor.config import RunContext
from clawditor.utils import logging as log


SIGNALS = {
    "react_native": [
        "lib/arm64-v8a/libhermes.so",
        "lib/arm64-v8a/libreactnativejni.so",
        "assets/index.android.bundle",
    ],
    "flutter": ["lib/arm64-v8a/libflutter.so", "lib/arm64-v8a/libapp.so"],
    "unity": ["assets/bin/Data/", "lib/arm64-v8a/libil2cpp.so"],
    "xamarin": ["assemblies/"],
    "cordova": ["assets/www/cordova.js"],
    "compose_multiplatform": ["assets/composeResources/"],
}


def run(ctx: RunContext) -> dict:
    detected = {k: False for k in SIGNALS}
    detected["native_android"] = True  # baseline
    with zipfile.ZipFile(ctx.universal_apk) as z:
        names = z.namelist()
    name_set = set(names)
    for stack, sigs in SIGNALS.items():
        for sig in sigs:
            if sig.endswith("/"):
                if any(n.startswith(sig) for n in names):
                    detected[stack] = True
                    break
            elif sig in name_set:
                detected[stack] = True
                break
    flagged = [k for k, v in detected.items() if v and k != "native_android"]
    if flagged:
        log.ok(f"stack: native + {', '.join(flagged)}")
    else:
        log.ok("stack: native Android only")
    (ctx.scan_dir).mkdir(parents=True, exist_ok=True)
    out = ctx.scan_dir / "stack.json"
    out.write_text(json.dumps(detected, indent=2))
    return detected
