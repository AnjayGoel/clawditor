"""Probe AWS S3 buckets referenced in the binary for public listing / read."""
from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from clawditor.config import RunContext
from clawditor.probe._http import call
from clawditor.utils import logging as log


COMMON_S3_PATHS = [
    "index.html", "robots.txt", "favicon.ico", "config.json",
    "manifest.json", ".env", "backup.zip", "uploads/test.jpg",
    "static/index.html", "public/index.html", "test/test.txt",
]

# Suffixes brute-tried as siblings of every discovered bucket name.
SUFFIXES = ("-staging", "-backup", "-uploads", "-dev", "-prod")


def run(ctx: RunContext) -> dict:
    secrets_file = ctx.scan_dir / "secrets.json"
    if not secrets_file.exists():
        return {}
    secrets = json.loads(secrets_file.read_text())
    buckets = _enumerate_buckets(secrets)
    if not buckets:
        log.info("no S3 buckets identified; skipping")
        return {}

    # Track which buckets are brute-suffix guesses (vs. directly observed) so
    # the report can downplay non-existent guesses.
    expanded: dict[str, bool] = {b: False for b in buckets}  # guessed=False
    for b in buckets:
        for suf in SUFFIXES:
            expanded.setdefault(f"{b}{suf}", True)

    out: dict[str, dict] = {}
    for b in sorted(expanded):
        log.info(f"  bucket: {b}")
        r = _probe_bucket(b)
        r["guessed"] = expanded[b]
        out[b] = r
        time.sleep(0.05)

    (ctx.probe_dir / "s3_buckets.json").write_text(json.dumps(out, indent=2))
    publicly_listable = [k for k, v in out.items() if v.get("listable")]
    log.ok(f"s3_buckets: {len(out)} probed, {len(publicly_listable)} publicly listable")
    return out


def _enumerate_buckets(secrets: dict) -> set[str]:
    names: set[str] = set()
    for h in secrets.get("s3_bucket_url", []):
        u = urlparse(h["value"])
        host = u.hostname or ""
        if host.endswith(".amazonaws.com"):
            stem = host.split(".s3")[0]
            if stem:
                names.add(stem)
    for h in secrets.get("s3_virtual_path_url", []):
        u = urlparse(h["value"])
        parts = u.path.strip("/").split("/", 1)
        if parts and parts[0]:
            names.add(parts[0])
    return names


def _probe_bucket(bucket: str) -> dict:
    result: dict = {"bucket": bucket}
    # Try us-east-1 virtual-host endpoint; AWS will 301 to the bucket's real region.
    listing_url = f"https://{bucket}.s3.amazonaws.com/"
    st, body = call("GET", listing_url, timeout=8)
    result["listing_status"] = st
    result["listing_snippet"] = body[:300]
    if st == 200 and "<ListBucketResult" in body:
        result["listable"] = True
        result["exists"] = True
    elif st == 200:
        result["listable"] = False
        result["exists"] = True
        result["public_partial"] = True
    elif st == 403:
        result["listable"] = False
        result["exists"] = True
    elif "NoSuchBucket" in body:
        result["listable"] = False
        result["exists"] = False
    else:
        result["listable"] = False

    # Common-path read attempts (only if the bucket plausibly exists).
    paths: dict[str, dict] = {}
    if result.get("exists") is not False:
        for p in COMMON_S3_PATHS:
            url = f"https://{bucket}.s3.amazonaws.com/{p}"
            st2, body2 = call("GET", url, timeout=8)
            paths[p] = {"http": st2, "snippet": body2[:120].replace("\n", " ")}
            time.sleep(0.05)
    result["path_probe"] = paths
    result["publicly_readable_paths"] = [p for p, r in paths.items() if r["http"] in (200, 206)]
    return result
