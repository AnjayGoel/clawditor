"""Custom regex sweep for the high-signal Android/Firebase patterns."""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawditor.config import RunContext
from clawditor.utils import logging as log


PATTERNS: dict[str, re.Pattern] = {
    "google_api_key": re.compile(r"\bAIzaSy[A-Za-z0-9_-]{33}\b"),
    "firebase_rtdb_url": re.compile(r"https://[a-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com"),
    "firebase_storage_bucket": re.compile(r"\b[a-z0-9-]+\.(?:appspot\.com|firebasestorage\.app)\b"),
    "google_oauth_client_id": re.compile(r"\b\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_secret_key": re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b"),
    "branch_key": re.compile(r"\bkey_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    "appsflyer_dev_key": re.compile(r'"AF_DEV_KEY"\s*:\s*"([A-Za-z0-9]{20,})"'),
    # AI provider keys
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,}\b"),
    "xai_grok_key": re.compile(r"\bxai-[A-Za-z0-9]{60,}\b"),
    "huggingface_token": re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    # Source / infra
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
    "gcp_service_account_json": re.compile(r'"type"\s*:\s*"service_account"'),
    # Require actual base64 content after the header — not just the marker. This
    # rejects string-literal matches in PEM parser code (e.g. io/grpc/util/CertificateUtils).
    "pem_private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\s*[\r\n]+[A-Za-z0-9+/=\r\n]{60,}-----END"
    ),
    # Payment / geo / observability / chat ops
    "razorpay_key": re.compile(r"\brzp_(?:live|test)_[A-Za-z0-9]{14,20}\b"),
    "mapbox_token": re.compile(r"\bpk\.eyJ[A-Za-z0-9._-]{20,}\b"),
    "sentry_dsn": re.compile(r"\bhttps://[a-f0-9]{32}@[a-z0-9.-]+/[0-9]+\b"),
    "slack_webhook": re.compile(r"\bhttps://hooks\.slack\.com/services/[A-Za-z0-9/_-]+\b"),
    "discord_webhook": re.compile(r"\bhttps://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+\b"),
    "algolia_app_id_key": re.compile(r'\b"X-Algolia-API-Key"\s*[:=,]\s*"([a-f0-9]{32})"'),
    "twilio_account_sid": re.compile(r"\bAC[a-z0-9]{32}\b"),
    "mailgun_key": re.compile(r"\bkey-[a-f0-9]{32}\b"),
    # AWS / S3
    "s3_bucket_url": re.compile(r"\bhttps?://[a-z0-9-]{3,63}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b"),
    "s3_virtual_path_url": re.compile(r"\bhttps?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[a-z0-9-]{3,63}\b"),
    "cloudfront_url": re.compile(r"\b[a-z0-9-]+\.cloudfront\.net\b"),
    "aws_secret_access_key_context": re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key[\s\"':=]+([A-Za-z0-9/+=]{40})"),
    # GCS bucket URLs (non-Firebase)
    "gcs_bucket_url": re.compile(r"\bhttps?://storage\.googleapis\.com/[a-z0-9-_.]{3,63}\b"),
    # Azure Blob
    "azure_blob_url": re.compile(r"\bhttps?://[a-z0-9]{3,24}\.blob\.core\.windows\.net\b"),
    # DigitalOcean Spaces
    "do_spaces_url": re.compile(r"\bhttps?://[a-z0-9-]+\.([a-z0-9-]+)\.digitaloceanspaces\.com\b"),
}


SEARCH_DIRS = ("jadx/sources", "smali", "hermes", "native")


def run(ctx: RunContext) -> dict:
    hits: dict[str, list[dict]] = {k: [] for k in PATTERNS}
    seen_values: dict[str, set] = {k: set() for k in PATTERNS}
    # Track gcp_service_account_json marker offsets per file for post-filter proximity check.
    gcp_marker_offsets: dict[str, list[int]] = {}
    file_texts: dict[str, str] = {}

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
            for name, rx in PATTERNS.items():
                for m in rx.finditer(txt):
                    val = m.group(0)
                    if name == "gcp_service_account_json":
                        # Dedupe by file (the marker is identical across files).
                        if rel in gcp_marker_offsets:
                            gcp_marker_offsets[rel].append(m.start())
                        else:
                            gcp_marker_offsets[rel] = [m.start()]
                            file_texts[rel] = txt
                        continue
                    if val in seen_values[name]:
                        continue
                    seen_values[name].add(val)
                    hits[name].append({"value": val, "file": rel})

    # Post-filter: only keep gcp_service_account_json hits where "private_key":
    # appears within ~500 chars of the marker in the same file.
    for rel, offsets in gcp_marker_offsets.items():
        txt = file_texts[rel]
        for off in offsets:
            window = txt[max(0, off - 500): off + 500]
            if '"private_key"' in window:
                hits["gcp_service_account_json"].append({"value": rel, "file": rel})
                break  # one finding per file is enough

    out = ctx.scan_dir / "secrets.json"
    out.write_text(json.dumps(hits, indent=2))
    for name, items in hits.items():
        if items:
            log.ok(f"  {name}: {len(items)} unique value(s)")
    return hits


def _iter_text_files(base: Path):
    """Yield text-ish files. Heuristic: skip binaries by extension, allow common code/text."""
    # Skip raw binaries — including .so libraries (we read their .strings.txt dumps instead).
    SKIP_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".m4a",
                ".bin", ".dex", ".odex", ".vdex", ".arsc", ".ttf", ".otf", ".woff",
                ".so"}
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in SKIP_EXT:
            continue
        # Skip very large files (>10 MB) to keep scan fast — except hermes/decompiled.js
        if p.stat().st_size > 10 * 1024 * 1024 and p.name != "decompiled.js":
            continue
        yield p
