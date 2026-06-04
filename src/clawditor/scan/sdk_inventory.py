"""Extract third-party SDK catalog from META-INF and root .properties / version files."""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log


# Keys that, in a .properties file, plausibly hold a version-like value.
VERSION_KEYS = ("version", "client", "buildVersion", "build", "Bundle-Version")

# Filenames at the APK root that hint at SDK + version (e.g. "kotlin-tooling-metadata.json"
# we ignore; but "androidx-version.txt" — name=androidx, version=contents).
VERSION_TXT_RX = re.compile(r"^(?P<name>[A-Za-z0-9_.+-]+?)-version\.txt$")


def run(ctx: RunContext) -> dict:
    sdks: list[dict] = []
    seen: set[tuple[str, str]] = set()

    smali = ctx.smali_dir
    roots = []
    if (smali / "root" / "META-INF").exists():
        roots.append((smali / "root" / "META-INF", "META-INF"))
    if (smali / "root").exists():
        roots.append((smali / "root", "root"))

    # 1. .properties files under those roots
    for root, label in roots:
        for p in root.rglob("*.properties"):
            entry = _from_properties(p, root_label=label, base=smali / "root")
            if entry and (entry["name"], entry.get("version", "")) not in seen:
                seen.add((entry["name"], entry.get("version", "")))
                sdks.append(entry)

    # 2. *-version.txt files at the APK root (smali/root/)
    if (smali / "root").exists():
        for p in (smali / "root").glob("*-version.txt"):
            m = VERSION_TXT_RX.match(p.name)
            if not m:
                continue
            name = m.group("name")
            try:
                version = p.read_text(errors="ignore").strip().splitlines()[0][:100]
            except Exception:
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            sdks.append({"name": name, "version": version,
                         "source": str(p.relative_to(smali / "root"))})

    # 3. *.properties at the root (already covered if roots include /root, but ensure
    # we tag source path correctly for top-level files).

    sdks.sort(key=lambda d: d["name"].lower())
    result = {
        "sdks": sdks,
        "by_category": _categorize(sdks),
    }
    out = ctx.scan_dir / "sdk_inventory.json"
    out.write_text(json.dumps(result, indent=2))
    log.ok(f"sdk_inventory: {len(sdks)} SDKs found")
    return result


def _from_properties(p: Path, root_label: str, base: Path) -> dict | None:
    """Parse a Java .properties file; return {name, version, source} or None."""
    try:
        txt = p.read_text(errors="ignore")
    except Exception:
        return None
    kv: dict[str, str] = {}
    for raw in txt.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        kv[k.strip()] = v.strip()
    name = p.stem  # firebase-analytics.properties -> firebase-analytics
    version = ""
    for k in VERSION_KEYS:
        if k in kv and kv[k]:
            version = kv[k][:100]
            break
    if not version and not kv:
        # Empty / non-parseable; skip
        return None
    try:
        source = str(p.relative_to(base))
    except ValueError:
        source = str(p)
    if root_label == "META-INF" and not source.startswith("META-INF"):
        source = "META-INF/" + p.name
    return {"name": name, "version": version, "source": source}


def _categorize(sdks: list[dict]) -> dict[str, list[dict]]:
    cats: dict[str, list[dict]] = {
        "firebase": [],
        "google_play_services": [],
        "androidx": [],
        "third_party": [],
    }
    for s in sdks:
        n = s["name"].lower()
        if n.startswith("firebase-") or n.startswith("firebase_"):
            cats["firebase"].append(s)
        elif n.startswith("play-services-") or n.startswith("play_services-"):
            cats["google_play_services"].append(s)
        elif n.startswith("androidx-") or n.startswith("androidx."):
            cats["androidx"].append(s)
        else:
            cats["third_party"].append(s)
    return cats


if __name__ == "__main__":  # pragma: no cover
    import sys
    from clawditor.config import RunContext
    out = Path(sys.argv[1])
    ctx = RunContext(package=None, apk_input=None, out_dir=out)
    run(ctx)
