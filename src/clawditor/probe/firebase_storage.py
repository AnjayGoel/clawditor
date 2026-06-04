"""Probe Firebase Storage for unauth bucket listing + common-path reads."""
from __future__ import annotations

import json
import time
from urllib.parse import quote

from clawditor.config import RunContext
from clawditor.probe._http import call
from clawditor.utils import logging as log


COMMON_PATHS = [
    "robots.txt", "index.html", "favicon.ico", "public/index.html",
    "static/config.json", "config/app.json", "config/remote_config.json",
    "app_config.json", "version.json",
    "profile_pictures/test.jpg", "profile/test.jpg", "users/test/profile.jpg",
    "users/test/avatar.jpg", "avatars/test.jpg", "images/test.jpg",
    "uploads/test.jpg", "audio/sample.mp3", "audio/episodes/test.mp3",
    "episodes/test.mp3", "shows/test/cover.jpg", "thumbnails/test.jpg",
    "banners/test.jpg", "videos/test.mp4", "reels/test.mp4", "stories/test.jpg",
    ".gitignore", ".env", "backup.json", "test/test.txt", "tmp/test.txt",
    "admin/config.json",
]


def run(ctx: RunContext) -> dict:
    secrets_file = ctx.scan_dir / "secrets.json"
    if not secrets_file.exists():
        return {}
    secrets = json.loads(secrets_file.read_text())
    buckets = [h["value"] for h in secrets.get("firebase_storage_bucket", [])]
    buckets = sorted(set(b for b in buckets
                          if not any(t in b for t in ("example.", "myservice.", "r.appspot"))))
    if not buckets:
        log.info("no Firebase storage buckets found; skipping")
        return {}

    out: dict[str, dict] = {}
    for b in buckets:
        log.info(f"  bucket: {b}")
        out[b] = _probe_bucket(b)
    (ctx.probe_dir / "firebase_storage.json").write_text(json.dumps(out, indent=2))
    return out


def _probe_bucket(bucket: str) -> dict:
    result: dict = {}

    # 1. Listing: rules_version=2 with allow list would succeed; otherwise 400/403
    list_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1"
    st, body = call("GET", list_url, timeout=10)
    result["listing"] = {"http": st, "snippet": body[:200].replace("\n", " ")}

    # 2. GCS anonymous listing (different rule layer — IAM not Firebase rules)
    gcs_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=1"
    st2, body2 = call("GET", gcs_url, timeout=10)
    result["gcs_listing"] = {"http": st2, "snippet": body2[:200].replace("\n", " ")}

    # 3. Common-path file reads
    paths: dict[str, dict] = {}
    interesting: list[str] = []
    for p in COMMON_PATHS:
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{quote(p, safe='')}?alt=media"
        st3, body3 = call("GET", url, timeout=8)
        snippet = body3[:120].replace("\n", " ")
        paths[p] = {"http": st3, "snippet": snippet}
        if st3 == 200 or st3 == 206:
            interesting.append(p)
        time.sleep(0.03)
    result["path_probe"] = paths
    result["publicly_readable_paths"] = interesting
    return result
