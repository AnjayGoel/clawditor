// Lite variant of trust-killer.js — drops the SSLContext.init hook to lower
// per-handshake overhead on chatty apps that flood logs / handshake often.
// Keeps TrustManagerImpl.checkServerTrusted, OkHttp CertificatePinner.check,
// and the default HostnameVerifier replacement. Use via `clawditor dynamic
// capture --fast`. Trade-off: apps that override SSLContext with a custom
// TrustManager (rare) may slip through; fall back to the full trust-killer.js.
'use strict';

Java.perform(() => {
    console.log('[trust-killer-lite] starting hooks');

    // 1. TrustManagerImpl.checkServerTrusted — return without throwing
    try {
        const TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
        ).implementation = function () { return; };
        // Newer overloads (Android 7+)
        try {
            TMImpl.checkServerTrusted.overload(
                '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'
            ).implementation = function () { return Java.use('java.util.ArrayList').$new(); };
        } catch (_) {}
        console.log('[trust-killer-lite] ✓ TrustManagerImpl.checkServerTrusted hooked');
    } catch (e) {
        console.log('[trust-killer-lite] TrustManagerImpl: ' + e);
    }

    // 2. OkHttp CertificatePinner.check
    for (const cls of ['okhttp3.CertificatePinner', 'com.squareup.okhttp.CertificatePinner']) {
        try {
            const CP = Java.use(cls);
            CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
            CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {};
            console.log('[trust-killer-lite] ✓ ' + cls + '.check hooked');
        } catch (_) {}
    }

    // 3. HostnameVerifier — verify() always returns true
    try {
        const HNV = Java.use('javax.net.ssl.HostnameVerifier');
        const Verified = Java.registerClass({
            name: 'org.clawditor.AllowAllHostnameVerifier',
            implements: [HNV],
            methods: { verify: function () { return true; } },
        });
        const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier(Verified.$new());
        console.log('[trust-killer-lite] ✓ default HostnameVerifier replaced');
    } catch (e) {
        console.log('[trust-killer-lite] HostnameVerifier: ' + e);
    }

    // (SSLContext.init hook intentionally omitted in lite variant.)

    console.log('[trust-killer-lite] all hooks installed');
});
