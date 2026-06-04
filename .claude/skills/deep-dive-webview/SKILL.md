---
name: deep-dive-webview
description: Use when investigating WebView vulnerabilities in an audited Android app — JS bridges, file:// access, untrusted URL loading. Triggers when scan/code_patterns.json or findings.md mentions WebView, addJavascriptInterface, setAllowUniversalAccessFromFileURLs, loadDataWithBaseURL, or the user asks about deeplink/webview exploit chains.
---

# deep-dive-webview

WebView misconfigurations are the highest-impact class of mobile vulnerabilities after credential leaks. This skill walks through investigating a WebView finding to its true exploitability.

## Where to look

- `scan/code_patterns.json` — pattern hits (`webview_universal_file_access`, `webview_addjs_interface`, `webview_load_data_with_base_url`, etc.)
- `scan/manifest.json` — find every Activity that hosts a WebView and whether it's exported
- `decompiled/jadx/sources/` — the actual code
- `decompiled/smali/` — if jadx skipped (use `--no-jadx`), fall back to smali

## What makes WebView findings exploitable

A WebView is **dangerous when** all of:
1. `setJavaScriptEnabled(true)` AND
2. (`addJavascriptInterface` exposes anything OR `setAllowFileAccessFromFileURLs(true)` OR `setAllowUniversalAccessFromFileURLs(true)`) AND
3. The URL it loads can be influenced by an attacker (intent extra, server-pushed config, partner page, MITM-able fetch).

(3) is the linchpin. If the URL is hardcoded to a single trusted domain, the WebView is much harder to exploit. Trace where the URL comes from:

```bash
# Find the activity hosting the WebView
grep -rn 'addJavascriptInterface\|setAllowUniversalAccessFromFileURLs' decompiled/jadx/sources/

# Find what feeds its loadUrl()
grep -rn 'loadUrl\|loadDataWithBaseURL' <webview-activity>.java

# Find what passes the URL extra to the intent
grep -rn '<WebViewActivity-class-name>' decompiled/jadx/sources/ | head
grep -rn 'putExtra.*url\|putExtra.*webUrl\|putExtra.*browserurl' decompiled/jadx/sources/
```

## Patterns to check

| Pattern | Risk |
|---|---|
| `setAllowUniversalAccessFromFileURLs(true)` | Loaded `file://` content can read any origin's data via XHR |
| `setAllowFileAccessFromFileURLs(true)` | Loaded `file://` content can read other local files |
| `addJavascriptInterface(obj, "name")` + `@JavascriptInterface` methods | Any page in the WebView can call those methods. List every method on the interface; one bad method (URL navigation, file ops) = exploit |
| `loadDataWithBaseURL("http://...", ...)` | The base URL is the origin for SOP. If `http://`, any subsequent fetch is MITM-able |
| `WebChromeClient.onCreateWindow` not overridden | window.open allowed |
| `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` | HTTPS page can load HTTP subresources |
| URL prepend without scheme check | `if (!url.startsWith("http")) url = "http://" + url;` — MITM gold |

## What to report

For each WebView activity:
1. **Activity name** + whether exported (from `scan/manifest.json`).
2. **Config flags** that are dangerous (list of which dangerous methods are called).
3. **JS bridge inventory**: every `@JavascriptInterface` method on every bridge, and what each does. (Reach in via `grep` from the bridge class.)
4. **URL source**: hardcoded? intent extra? server config? Trace.
5. **Severity**: CRITICAL if URL is server-/intent-controlled AND JS bridge does anything sensitive (URL navigation, file ops, token access); HIGH otherwise.
6. **Fix**: remove the dangerous config; switch JS bridge to allow-list specific origins via `addWebMessageListener` if available.

## Reference patterns to look for

- A `WebViewActivity` exposing a `@JavascriptInterface` method that takes a URI from JS and navigates the app to it — opens cross-origin app navigation.
- A `WebViewActivity` that prepends `http://` to bare URLs (no scheme) before `loadUrl()` — MITM-exploitable for any extra-controlled URL.
- A `WebViewActivity` whose JS-bridge name is taken from a URL query param (e.g. `?interfaceName=…`) — lets the loaded page choose which native bridge to call.
- Bundled vendor SDKs (payment-gateway WebViews etc.) that do `loadDataWithBaseURL("http://…", …)` — vendor-bounded but inherits the risk to the host app.
