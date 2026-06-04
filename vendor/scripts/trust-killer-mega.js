// Mega trust-killer: TLS bypass + GMS version-check bypass + Pairip license-check bypass.
// Sufficient for sideloaded apps that protect themselves with Pairip + a Google
// Play Services minimum-version gate, without an LSPosed module.
'use strict';

Java.perform(function () {
    console.log('[mega] starting');

    // ── 1. TLS trust-killer ──
    try {
        var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String')
            .implementation = function () { return; };
        try {
            TMImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String')
                .implementation = function () { return Java.use('java.util.ArrayList').$new(); };
        } catch (_) {}
        console.log('[mega] ✓ TrustManagerImpl hooked');
    } catch (e) { console.log('[mega] TM err: ' + e); }

    for (var cls of ['okhttp3.CertificatePinner','com.squareup.okhttp.CertificatePinner']) {
        try {
            var CP = Java.use(cls);
            CP.check.overload('java.lang.String','java.util.List').implementation = function(){};
            CP.check.overload('java.lang.String','[Ljava.security.cert.Certificate;').implementation = function(){};
            console.log('[mega] ✓ ' + cls + ' hooked');
        } catch(_) {}
    }

    try {
        var HNV = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAll = Java.registerClass({
            name: 'org.clawditor.AllowAllHNV3', implements: [HNV],
            methods: { verify: function(){ return true; } },
        });
        Java.use('javax.net.ssl.HttpsURLConnection').setDefaultHostnameVerifier(AllowAll.$new());
        console.log('[mega] ✓ HostnameVerifier replaced');
    } catch (e) { console.log('[mega] HNV err: ' + e); }

    // ── 2. GMS version-check bypass ──
    for (var cls of ['com.google.android.gms.common.GoogleApiAvailability',
                     'com.google.android.gms.common.GooglePlayServicesUtil']) {
        try {
            var GA = Java.use(cls);
            var m = GA.isGooglePlayServicesAvailable;
            for (var ov of m.overloads) { ov.implementation = function () { return 0; }; }
            console.log('[mega] ✓ ' + cls + '.isGooglePlayServicesAvailable → 0');
        } catch (_) {}
    }
    try {
        var GA = Java.use('com.google.android.gms.common.GoogleApiAvailability');
        for (var fn of ['showErrorDialogFragment','showErrorNotification','getErrorDialog',
                        'getErrorResolutionPendingIntent','isUserResolvableError']) {
            try {
                var m = GA[fn];
                for (var ov of m.overloads) {
                    var rt = ov.returnType.className;
                    ov.implementation = (rt === 'boolean') ? function(){ return false; } : function(){ return null; };
                }
            } catch (_) {}
        }
    } catch (_) {}
    try {
        var PI = Java.use('com.google.android.gms.security.ProviderInstaller');
        for (var fn of ['installIfNeeded','installIfNeededAsync']) {
            try { var m = PI[fn]; for (var ov of m.overloads) ov.implementation = function(){}; } catch (_) {}
        }
    } catch (_) {}

    // ── 3. Pairip license-check bypass ──
    var LC_METHODS = [
        'checkLicense', 'checkLicenseInternal', 'initializeLicenseCheck',
        'handleError', 'retryOrThrow',
        'scheduleAppShutdown', 'scheduleRepeatedLicenseCheck',
        'startErrorDialogActivity', 'startPaywallActivity',
        'connectToLicensingService', 'performLocalInstallerCheck',
        'reportSuccessfulLicenseCheck',
    ];
    try {
        var LC = Java.use('com.pairip.licensecheck.LicenseClient');
        for (var m of LC_METHODS) {
            try {
                if (typeof LC[m] === 'undefined') continue;
                for (var ov of LC[m].overloads) {
                    var rt = ov.returnType.className;
                    ov.implementation = (rt === 'boolean')
                        ? function(){ return true; }
                        : (rt === 'void' || rt === 'V') ? function(){} : function(){ return null; };
                }
            } catch(_) {}
        }
        console.log('[mega] ✓ Pairip LicenseClient neutered');
    } catch (_) {}

    try {
        var LA = Java.use('com.pairip.licensecheck.LicenseActivity');
        ['closeApp','exitApp','closeAllTasks','showErrorDialog','showPaywallAndCloseApp'].forEach(function(m){
            try { LA[m].overloads.forEach(function(ov){ ov.implementation = function(){}; }); } catch(_){}
        });
        try { LA.logAndShowErrorDialog.overloads.forEach(function(ov){ ov.implementation = function(){}; }); } catch(_){}
        try {
            LA.onStart.implementation = function(){
                console.log('[mega] LicenseActivity.onStart → finish() immediately');
                this.finish();
            };
        } catch(_){}
        console.log('[mega] ✓ Pairip LicenseActivity neutered');
    } catch (_) {}

    // Pairip's application bootstrap — call super.attachBaseContext to skip the check setup
    try {
        var App = Java.use('com.pairip.application.Application');
        if (App.attachBaseContext) {
            App.attachBaseContext.implementation = function(ctx){
                return Java.use('android.app.Application').attachBaseContext.call(this, ctx);
            };
            console.log('[mega] ✓ Pairip Application.attachBaseContext stubbed');
        }
    } catch(_){}

    // Native VM runner — likely no-op if libpairip.so not present
    try {
        var VM = Java.use('com.pairip.VMRunner');
        VM.executeVMs.implementation = function(){};
        console.log('[mega] ✓ Pairip VMRunner.executeVMs no-op');
    } catch(_){}

    console.log('[mega] all hooks installed');
});
