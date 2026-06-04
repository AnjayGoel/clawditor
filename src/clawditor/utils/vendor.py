"""Vendor namespace filter.

Many findings (especially regex-based ones) match string literals inside
well-known third-party SDK code, not the app's own code. Example:
`io/grpc/util/CertificateUtils.smali` contains the literal string
`-----BEGIN PRIVATE KEY-----` to PARSE PEM keys — there's no actual private
key shipped, but the secrets-scanner regex matches the marker.

`is_vendor(path)` returns True if a file path is inside a known third-party
SDK namespace. The findings collector uses this to demote-or-suppress
findings that originate from vendor code (configurable per-category).
"""
from __future__ import annotations


# Path fragments that identify third-party SDK namespaces. Tested via "in".
VENDOR_PREFIXES = (
    # Android / Google
    "androidx/", "android/support/", "com/google/", "com/android/",
    "kotlin/", "kotlinx/", "javax/", "java/",
    # gRPC / protobuf
    "io/grpc/", "com/google/protobuf/",
    # Networking
    "okhttp3/", "okio/", "retrofit2/", "com/squareup/okhttp",
    "io/netty/", "io/reactivex/", "rx/", "io/sentry/",
    # React Native / Flutter / others
    "com/facebook/react/", "com/facebook/yoga/", "com/facebook/soloader/",
    "io/flutter/", "io/dart/",
    # Image loaders
    "com/bumptech/glide/", "com/squareup/picasso/", "com/nostra13/universalimageloader/",
    # Crash reporting / analytics
    "com/crashlytics/", "io/branch/", "com/appsflyer/", "com/mixpanel/",
    "com/clevertap/", "com/segment/analytics/", "com/onesignal/",
    "com/moengage/", "com/amplitude/", "com/datadog/",
    # Payment SDKs
    "com/razorpay/", "in/juspay/", "com/paytm/", "com/phonepe/",
    "com/stripe/", "com/braintreepayments/",
    # Login / auth
    "com/google/android/gms/", "com/facebook/login/", "com/twitter/sdk/",
    "com/truecaller/", "com/otpless/",
    # Ad SDKs
    "com/google/ads/", "com/applovin/", "com/inmobi/", "com/vungle/",
    "com/unity3d/", "com/ironsource/", "com/chartboost/", "com/mopub/",
    # Utility libs
    "com/jakewharton/", "io/reactivex/rxjava2/", "io/reactivex/rxjava3/",
    "com/scottyab/rootbeer/", "com/scottyab/safetynet/",
    "com/airbnb/lottie/", "com/google/gson/", "com/fasterxml/jackson/",
    # Sentry / Bugsnag
    "io/sentry/", "com/bugsnag/",
    # Smali path equivalents (APKEditor's smali/smali/classesN/ folder)
    "smali/classes/io/grpc/", "smali/classes/com/google/",
    "smali/classes/androidx/", "smali/classes/kotlin/",
    "smali/classes/com/facebook/", "smali/classes/io/flutter/",
)


def is_vendor(path: str) -> bool:
    """True if `path` points inside a known third-party SDK namespace.

    Accepts both java-source (e.g. `jadx/sources/io/grpc/...`) and
    smali-decoded (`smali/smali/classesN/io/grpc/...`) layouts.
    """
    p = path.replace("\\", "/")
    return any(prefix in p for prefix in VENDOR_PREFIXES)


def first_app_owned(items: list[dict], file_key: str = "file") -> dict | None:
    """Return the first item whose `file` is NOT vendor, or None."""
    for it in items:
        if not is_vendor(it.get(file_key, "")):
            return it
    return None


def split_vendor(items: list[dict], file_key: str = "file") -> tuple[list[dict], list[dict]]:
    """Return (app_owned, vendor) partition."""
    app, vendor = [], []
    for it in items:
        (vendor if is_vendor(it.get(file_key, "")) else app).append(it)
    return app, vendor
