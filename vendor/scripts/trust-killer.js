// Generic Android TLS / pinning bypass — hooks TrustManagerImpl + OkHttp
// CertificatePinner + javax.net.ssl.HostnameVerifier. Sufficient for most
// non-Flutter, non-Conscrypt-overriding apps. Logs to console when each hook
// fires so we can confirm the bypass is engaging.
'use strict';

Java.perform(() => {
    console.log('[trust-killer] starting hooks');

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
        console.log('[trust-killer] ✓ TrustManagerImpl.checkServerTrusted hooked');
    } catch (e) {
        console.log('[trust-killer] TrustManagerImpl: ' + e);
    }

    // 2. OkHttp CertificatePinner.check
    for (const cls of ['okhttp3.CertificatePinner', 'com.squareup.okhttp.CertificatePinner']) {
        try {
            const CP = Java.use(cls);
            CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
            CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {};
            console.log('[trust-killer] ✓ ' + cls + '.check hooked');
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
        console.log('[trust-killer] ✓ default HostnameVerifier replaced');
    } catch (e) {
        console.log('[trust-killer] HostnameVerifier: ' + e);
    }

    // 4. SSLContext.init — replace TrustManagers with our AllowAll
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const AllowAll = Java.registerClass({
            name: 'org.clawditor.AllowAllTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; },
            },
        });
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        const init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        );
        init.implementation = function (km, tm, sr) {
            return init.call(this, km, [AllowAll.$new()], sr);
        };
        console.log('[trust-killer] ✓ SSLContext.init forced AllowAllTrustManager');
    } catch (e) {
        console.log('[trust-killer] SSLContext: ' + e);
    }

    console.log('[trust-killer] all hooks installed');
});
