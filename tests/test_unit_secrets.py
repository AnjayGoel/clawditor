"""Unit tests for the custom regex secrets scanner."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.scan.secrets import PATTERNS, run as run_secrets
from clawditor.config import RunContext


def test_patterns_match_known_values():
    assert PATTERNS["google_api_key"].search("AIzaSyEXAMPLE_FAKE_KEY_FOR_TESTS_ONLY99")
    assert PATTERNS["firebase_rtdb_url"].search("https://my-example-prod.firebaseio.com")
    assert PATTERNS["firebase_storage_bucket"].search("my-example-prod.appspot.com")
    assert PATTERNS["firebase_storage_bucket"].search("my-example-prod.firebasestorage.app")
    assert PATTERNS["google_oauth_client_id"].search("123456789012-examplefakeoauthclient0000000000.apps.googleusercontent.com")
    assert PATTERNS["aws_access_key_id"].search("AKIAIOSFODNN7EXAMPLE")
    assert PATTERNS["branch_key"].search("key_live_FAKEKEYFAKEKEYFAKEKEY99")
    assert PATTERNS["jwt"].search("eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YTBjMWRlYWEyN2JjNjMyNTUzYmM4MWEyMmQ4NzY1MWM3MTMyY2IiLCJ0eXAiOiJKV1QifQ.eyJwcm92aWRlcl9pZCI6ImFub255bW91cyJ9.aaaaaaaaaaaaaaaaaaaaaaaaaa")


def test_patterns_do_not_match_obvious_negatives():
    assert not PATTERNS["google_api_key"].search("AIzaSyTooShort")
    assert not PATTERNS["aws_access_key_id"].search("notakey")
    assert not PATTERNS["firebase_storage_bucket"].search("example.com")


def test_new_ai_and_infra_patterns_match():
    assert PATTERNS["openai_key"].search("sk-abcdefghijklmnopqrstuvwx")
    assert PATTERNS["openai_key"].search("sk-proj-abcdefghijklmnopqrstuvwxyz0123_-AB")
    assert PATTERNS["anthropic_key"].search(
        "sk-ant-api03-" + "A" * 95
    )
    assert PATTERNS["anthropic_key"].search(
        "sk-ant-admin01-" + "z" * 90
    )
    assert PATTERNS["xai_grok_key"].search("xai-" + "a" * 70)
    assert PATTERNS["huggingface_token"].search("hf_" + "a" * 35)
    assert PATTERNS["github_token"].search("ghp_" + "A" * 40)
    assert PATTERNS["github_token"].search("ghs_" + "x" * 36)
    # PEM regex requires actual base64 body — marker alone is rejected (false-positive guard
    # against PEM parser code containing string literals like `-----BEGIN PRIVATE KEY-----`).
    _b64 = "A" * 80
    assert PATTERNS["pem_private_key"].search(f"-----BEGIN PRIVATE KEY-----\n{_b64}\n-----END")
    assert PATTERNS["pem_private_key"].search(f"-----BEGIN RSA PRIVATE KEY-----\n{_b64}\n-----END")
    assert PATTERNS["pem_private_key"].search(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{_b64}\n-----END")
    # Marker alone (the false-positive shape) must NOT match.
    assert not PATTERNS["pem_private_key"].search("-----BEGIN PRIVATE KEY-----")
    assert PATTERNS["razorpay_key"].search("rzp_live_abcdefghij1234")
    assert PATTERNS["razorpay_key"].search("rzp_test_AbCdEfGhIjKlMn")
    assert PATTERNS["mapbox_token"].search("pk.eyJ" + "a" * 40 + ".xyz")
    assert PATTERNS["sentry_dsn"].search("https://" + "f" * 32 + "@o12345.ingest.sentry.io/678")
    assert PATTERNS["slack_webhook"].search(
        "https://hooks.slack.com/services/T0/B0/abcdefABCDEF"
    )
    assert PATTERNS["discord_webhook"].search(
        "https://discord.com/api/webhooks/123456789/abc_def-XYZ"
    )
    # The \b before " requires a preceding word character for the boundary to fire.
    assert PATTERNS["algolia_app_id_key"].search(
        'put"X-Algolia-API-Key": "' + "a" * 32 + '"'
    )
    assert PATTERNS["twilio_account_sid"].search("AC" + "0" * 32)
    assert PATTERNS["mailgun_key"].search("key-" + "a" * 32)
    assert PATTERNS["gcp_service_account_json"].search('"type": "service_account"')


def test_s3_and_cloud_storage_patterns_match():
    # Virtual-hosted-style S3 URLs (regional + classic)
    assert PATTERNS["s3_bucket_url"].search("https://my-bucket.s3.amazonaws.com")
    assert PATTERNS["s3_bucket_url"].search("https://uploads-cdn.s3.us-west-2.amazonaws.com")
    assert PATTERNS["s3_bucket_url"].search("http://acme.s3-us-east-1.amazonaws.com")
    # Path-style URLs
    assert PATTERNS["s3_virtual_path_url"].search("https://s3.amazonaws.com/my-bucket")
    assert PATTERNS["s3_virtual_path_url"].search(
        "https://s3.ap-south-1.amazonaws.com/india-bucket"
    )
    # CloudFront
    assert PATTERNS["cloudfront_url"].search("d111111abcdef8.cloudfront.net")
    assert PATTERNS["cloudfront_url"].search("see cdn-prod-7.cloudfront.net here")
    # AWS secret access key with adjacent context (exactly 40 chars after the marker)
    assert PATTERNS["aws_secret_access_key_context"].search(
        'aws_secret_access_key = "' + "A" * 40 + '"'
    )
    assert PATTERNS["aws_secret_access_key_context"].search(
        "AWS-Secret-Access-Key: " + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123"
    )
    # GCS (non-Firebase) bucket URLs
    assert PATTERNS["gcs_bucket_url"].search("https://storage.googleapis.com/some-bucket")
    assert PATTERNS["gcs_bucket_url"].search("https://storage.googleapis.com/proj.appspot.com")
    # Azure Blob
    assert PATTERNS["azure_blob_url"].search("https://acmeprod.blob.core.windows.net")
    # DigitalOcean Spaces
    assert PATTERNS["do_spaces_url"].search("https://acme-cdn.nyc3.digitaloceanspaces.com")
    assert PATTERNS["do_spaces_url"].search("http://media.sgp1.digitaloceanspaces.com")


def test_s3_and_cloud_storage_negatives():
    # Wrong host should not match the S3 pattern.
    assert not PATTERNS["s3_bucket_url"].search("https://my-bucket.s3.example.com")
    # cloudfront pattern requires a subdomain label.
    assert not PATTERNS["cloudfront_url"].search(".cloudfront.net")
    # azure_blob pattern requires the blob.core.windows.net host
    assert not PATTERNS["azure_blob_url"].search("https://x.file.core.windows.net")
    # aws secret key needs adjacent header + exactly 40 chars of base64
    assert not PATTERNS["aws_secret_access_key_context"].search(
        'aws_secret_access_key = "tooshort"'
    )


def test_new_patterns_negatives():
    assert not PATTERNS["openai_key"].search("sk-short")
    assert not PATTERNS["anthropic_key"].search("sk-ant-api03-short")
    assert not PATTERNS["github_token"].search("ghp_short")
    assert not PATTERNS["razorpay_key"].search("rzp_live_x")  # below 14
    assert not PATTERNS["mapbox_token"].search("pk.eyJabc")  # too short
    assert not PATTERNS["xai_grok_key"].search("xai-tooShort")
    # algolia pattern requires the header context
    assert not PATTERNS["algolia_app_id_key"].search('"someKey": "' + "a" * 32 + '"')


def test_gcp_service_account_requires_private_key_proximity(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    src = ctx.decompiled_dir / "jadx" / "sources"
    src.mkdir(parents=True)
    # Positive: marker + private_key within 500 chars
    (src / "creds.json").write_text(
        '{"type": "service_account", "project_id": "x", "private_key": "-----BEGIN..."}'
    )
    # Negative: marker but no private_key nearby
    (src / "schema.json").write_text(
        '{"type": "service_account"}\n' + ("// noise\n" * 200)
    )
    out = run_secrets(ctx)
    hits = out["gcp_service_account_json"]
    files = {h["file"] for h in hits}
    assert any("creds.json" in f for f in files)
    assert not any("schema.json" in f for f in files)


def test_run_finds_unique_values(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    src = ctx.decompiled_dir / "jadx" / "sources"
    src.mkdir(parents=True)
    (src / "fake.java").write_text("""
        public class X {
            String k1 = "AIzaSyEXAMPLE_FAKE_KEY_FOR_TESTS_ONLY99";
            String k1_dup = "AIzaSyEXAMPLE_FAKE_KEY_FOR_TESTS_ONLY99";
            String url = "https://my-example-prod.firebaseio.com/path";
        }
    """)
    out = run_secrets(ctx)
    assert len(out["google_api_key"]) == 1  # dedupes
    assert out["google_api_key"][0]["value"].startswith("AIzaSy")
    assert len(out["firebase_rtdb_url"]) == 1
