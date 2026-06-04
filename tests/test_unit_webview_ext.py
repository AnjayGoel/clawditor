"""Unit tests for the extended WebView misconfiguration patterns added to code_patterns.PATTERNS."""
from __future__ import annotations

import re

from clawditor.scan.code_patterns import PATTERNS


def _match(pat_name: str, text: str) -> bool:
    return re.search(PATTERNS[pat_name], text) is not None


# ----- webview_mixed_content_always_allow -----

def test_webview_mixed_content_always_allow_positive_qualified():
    src = "settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);"
    assert _match("webview_mixed_content_always_allow", src)


def test_webview_mixed_content_always_allow_positive_unqualified():
    src = "webSettings.setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)"
    assert _match("webview_mixed_content_always_allow", src)


def test_webview_mixed_content_always_allow_positive_kotlin_spacing():
    src = "settings.setMixedContentMode( WebSettings.MIXED_CONTENT_ALWAYS_ALLOW )"
    assert _match("webview_mixed_content_always_allow", src)


def test_webview_mixed_content_always_allow_negative_never_allow():
    src = "settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);"
    assert not _match("webview_mixed_content_always_allow", src)


def test_webview_mixed_content_always_allow_negative_compatibility():
    src = "settings.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);"
    assert not _match("webview_mixed_content_always_allow", src)


def test_webview_mixed_content_always_allow_negative_unrelated():
    src = "settings.setJavaScriptEnabled(true);"
    assert not _match("webview_mixed_content_always_allow", src)


# ----- webview_debugging_enabled -----

def test_webview_debugging_enabled_positive_basic():
    src = "WebView.setWebContentsDebuggingEnabled(true);"
    assert _match("webview_debugging_enabled", src)


def test_webview_debugging_enabled_positive_spacing():
    src = "WebView.setWebContentsDebuggingEnabled( true )"
    assert _match("webview_debugging_enabled", src)


def test_webview_debugging_enabled_positive_kotlin_no_semi():
    src = "WebView.setWebContentsDebuggingEnabled(true)"
    assert _match("webview_debugging_enabled", src)


def test_webview_debugging_enabled_negative_false():
    src = "WebView.setWebContentsDebuggingEnabled(false);"
    assert not _match("webview_debugging_enabled", src)


def test_webview_debugging_enabled_negative_unrelated():
    src = "WebView webView = new WebView(context);"
    assert not _match("webview_debugging_enabled", src)


def test_webview_debugging_enabled_negative_other_method():
    src = "webView.setWebChromeClient(new WebChromeClient());"
    assert not _match("webview_debugging_enabled", src)


# ----- webview_geolocation_always_allow -----

def test_webview_geolocation_always_allow_positive_inline():
    src = (
        "public void onGeolocationPermissionsShowPrompt(String origin, "
        "GeolocationPermissions.Callback callback) { callback.invoke(origin, true, false); }"
    )
    assert _match("webview_geolocation_always_allow", src)


def test_webview_geolocation_always_allow_positive_multiline():
    src = (
        "@Override\n"
        "public void onGeolocationPermissionsShowPrompt(String origin,\n"
        "        GeolocationPermissions.Callback callback) {\n"
        "    // grant by default\n"
        "    callback.invoke(origin, true, false);\n"
        "}\n"
    )
    assert _match("webview_geolocation_always_allow", src)


def test_webview_geolocation_always_allow_negative_denied():
    src = (
        "public void onGeolocationPermissionsShowPrompt(String origin, "
        "GeolocationPermissions.Callback callback) { callback.invoke(origin, false, false); }"
    )
    assert not _match("webview_geolocation_always_allow", src)


def test_webview_geolocation_always_allow_negative_no_callback():
    src = (
        "public void onGeolocationPermissionsShowPrompt(String origin, "
        "GeolocationPermissions.Callback callback) { /* TODO */ }"
    )
    assert not _match("webview_geolocation_always_allow", src)


def test_webview_geolocation_always_allow_negative_unrelated_invoke():
    src = "someCallback.invoke(origin, true, false);"
    assert not _match("webview_geolocation_always_allow", src)


# ----- webview_safe_browsing_disabled -----

def test_webview_safe_browsing_disabled_positive_basic():
    src = "settings.setSafeBrowsingEnabled(false);"
    assert _match("webview_safe_browsing_disabled", src)


def test_webview_safe_browsing_disabled_positive_spacing():
    src = "settings.setSafeBrowsingEnabled( false )"
    assert _match("webview_safe_browsing_disabled", src)


def test_webview_safe_browsing_disabled_positive_kotlin():
    src = "webView.settings.setSafeBrowsingEnabled(false)"
    assert _match("webview_safe_browsing_disabled", src)


def test_webview_safe_browsing_disabled_negative_true():
    src = "settings.setSafeBrowsingEnabled(true);"
    assert not _match("webview_safe_browsing_disabled", src)


def test_webview_safe_browsing_disabled_negative_unrelated():
    src = "settings.setJavaScriptEnabled(false);"
    assert not _match("webview_safe_browsing_disabled", src)


def test_webview_safe_browsing_disabled_negative_other_method():
    src = "settings.setSafeBrowsingWhitelist(list, callback);"
    assert not _match("webview_safe_browsing_disabled", src)
