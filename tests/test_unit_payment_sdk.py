"""Unit tests for the payment SDK detection + key-extraction scanner."""
from __future__ import annotations

import json
from pathlib import Path

from clawditor.config import RunContext
from clawditor.scan.payment_sdk import run as run_payment


def _write(p: Path, txt: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt)


def test_razorpay_detected_with_live_key(tmp_run: RunContext):
    # Namespace marker satisfied via smali path; key embedded in resource xml.
    smali = tmp_run.smali_dir
    _write(smali / "smali" / "com" / "razorpay" / "Checkout.smali",
           ".class public Lcom/razorpay/Checkout;\n.super Ljava/lang/Object;\n")
    _write(smali / "root" / "res" / "values" / "strings.xml",
           '<resources><string name="rzp_key">rzp_live_ABCDEF1234567890</string></resources>')

    d = run_payment(tmp_run)
    by_name = {f["sdk"]: f for f in d["findings"]}
    assert "Razorpay" in by_name
    rz = by_name["Razorpay"]
    assert "rzp_live_ABCDEF1234567890" in rz["keys"]
    # Note flagged as production key
    assert any("production key" in n for n in rz["notes"])


def test_stripe_sk_live_detected_with_critical_note(tmp_run: RunContext):
    smali = tmp_run.smali_dir
    # Stripe is detectable via the marker "sk_live_" alone (literal marker)
    _write(smali / "smali" / "com" / "example" / "PaymentConfig.smali",
           'const-string v0, "sk_live_51HxYzABCDEFghijklmnopqrstuvwxyz012345"\n')

    d = run_payment(tmp_run)
    by_name = {f["sdk"]: f for f in d["findings"]}
    assert "Stripe" in by_name
    st = by_name["Stripe"]
    assert any(k.startswith("sk_live_") for k in st["keys"])
    assert any("CRITICAL" in n and "SECRET" in n for n in st["notes"])


def test_paytm_detected_with_merchant_id(tmp_run: RunContext):
    smali = tmp_run.smali_dir
    _write(smali / "smali" / "com" / "paytm" / "pgsdk" / "Init.smali",
           ".class public Lcom/paytm/pgsdk/Init;\n")
    # MID assignment patterns vary; use one the regex catches.
    _write(smali / "smali" / "com" / "example" / "PgConfig.smali",
           'const-string v1, "MID=MERCHID123XYZ"\n')

    d = run_payment(tmp_run)
    by_name = {f["sdk"]: f for f in d["findings"]}
    assert "Paytm" in by_name
    pt = by_name["Paytm"]
    assert "MERCHID123XYZ" in pt.get("keys", [])


def test_no_payment_sdk_yields_empty_findings(tmp_run: RunContext):
    smali = tmp_run.smali_dir
    _write(smali / "smali" / "com" / "example" / "Hello.smali",
           ".class public Lcom/example/Hello;\nconst-string v0, \"hello\"\n")

    d = run_payment(tmp_run)
    assert d["findings"] == []
    # File is still emitted, so the report phase can read it unconditionally
    out = json.loads((tmp_run.scan_dir / "payment_sdk.json").read_text())
    assert out == {"findings": []}


def test_google_play_billing_via_namespace(tmp_run: RunContext):
    smali = tmp_run.smali_dir
    _write(smali / "smali" / "com" / "android" / "billingclient" / "api" / "BillingClient.smali",
           ".class public Lcom/android/billingclient/api/BillingClient;\n")
    d = run_payment(tmp_run)
    by_name = {f["sdk"]: f for f in d["findings"]}
    assert "GooglePlayBilling" in by_name
    # No key pattern for billing -> notes empty, keys absent
    assert by_name["GooglePlayBilling"].get("keys", []) == []
