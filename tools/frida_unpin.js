/*
 * frida_unpin.js - defeat SSL/TLS certificate pinning in the FFRK JP Android
 * client (jp.mbga.a12019103) so mitmproxy can read the plaintext login flow.
 *
 * Goal (preservation): capture YOUR OWN account's real Mobage/Sakasho login
 * against the LIVE servers - the OAuth handshake and the `passphrase` your
 * account receives - so the PC loader can replay it (or so we can reproduce the
 * native Mobage login without AndApp). This only touches the one app on a device
 * you control; do not use it against anyone else's traffic.
 *
 * The FFRK client is a Mobage/ngCore title, so pinning can live in several
 * layers at once. This script neutralizes all of them it finds and logs which
 * ones fired, so the capture works whether pinning is Java-, Conscrypt-, or
 * native-BoringSSL-based.
 *
 * Usage (device rooted OR app re-packed with frida-gadget):
 *   frida -U -f jp.mbga.a12019103 -l frida_unpin.js --no-pause
 *   # already running:
 *   frida -U -n "FINAL FANTASY Record Keeper" -l frida_unpin.js
 *
 * Point the device's proxy at mitmproxy and install mitm's CA first (see
 * tools/README.md "Android MITM capture").
 */
'use strict';

function log(tag, msg) { console.log('[unpin] ' + tag + ': ' + msg); }

/* ---------------- Java / ART layer ---------------------------------------- */
function hookJava() {
  Java.perform(function () {
    // 1) Install an all-trusting SSLContext so default HttpsURLConnection /
    //    ngCore Java networking accepts the mitm cert.
    try {
      var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      var TrustManager = Java.registerClass({
        name: 'org.ffbepreservation.TrustAll',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function () {},
          checkServerTrusted: function () {},
          getAcceptedIssuers: function () { return []; },
        },
      });
      var tms = [TrustManager.$new()];
      var init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom');
      init.implementation = function (km, tm, sr) {
        log('SSLContext.init', 'replacing TrustManager array');
        init.call(this, km, tms, sr);
      };
      log('java', 'SSLContext TrustManager override installed');
    } catch (e) { log('java', 'SSLContext hook skipped: ' + e); }

    // 2) OkHttp3 CertificatePinner (Mobage SDK HTTP client may use OkHttp).
    try {
      var CertificatePinner = Java.use('okhttp3.CertificatePinner');
      CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function (host) {
          log('okhttp3', 'CertificatePinner.check bypassed for ' + host);
        };
      // older signature
      try {
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
          .implementation = function (host) {
            log('okhttp3', 'CertificatePinner.check(cert[]) bypassed for ' + host);
          };
      } catch (e2) {}
    } catch (e) { log('java', 'okhttp3 not present'); }

    // 3) Conscrypt TrustManagerImpl - the actual chain verifier on modern
    //    Android; return the chain unverified.
    try {
      var ArrayList = Java.use('java.util.ArrayList');
      var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      // verifyChain(List<X509Certificate>, ..., String host, ...)
      TMImpl.verifyChain.implementation = function (certs, kt, host, clientAuth, ocsp, tlsSct) {
        log('conscrypt', 'verifyChain bypassed for ' + host);
        return certs;
      };
      // checkTrustedRecursive on some ROMs
      try {
        TMImpl.checkTrustedRecursive.implementation = function () {
          return ArrayList.$new();
        };
      } catch (e3) {}
    } catch (e) { log('java', 'conscrypt TrustManagerImpl not present'); }

    // 4) WebView SSL errors (Mobage login is often a WebView). Proceed anyway.
    try {
      var WebViewClient = Java.use('android.webkit.WebViewClient');
      WebViewClient.onReceivedSslError.implementation = function (view, handler, err) {
        log('webview', 'onReceivedSslError -> proceed()');
        handler.proceed();
      };
    } catch (e) { log('java', 'WebViewClient hook skipped'); }

    // 5) TrustKit (DataTheorem) if the app bundles it.
    try {
      var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
      TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
        .implementation = function () { return true; };
      log('java', 'TrustKit verifier bypassed');
    } catch (e) {}

    // 6) HostnameVerifier used directly.
    try {
      var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
      var AllowAll = Java.registerClass({
        name: 'org.ffbepreservation.AllowAllHosts',
        implements: [Java.use('javax.net.ssl.HostnameVerifier')],
        methods: { verify: function () { return true; } },
      });
      HttpsURLConnection.setDefaultHostnameVerifier(AllowAll.$new());
      log('java', 'default HostnameVerifier set to allow-all');
    } catch (e) {}
  });
}

/* ---------------- Native BoringSSL layer ---------------------------------- */
/* ngCore ships its own native networking (libcurl/BoringSSL inside the .so).
 * Neutralize the native verify callbacks so the native stack also accepts the
 * mitm cert. We force the custom-verify callback result to ssl_verify_ok(0).  */
function hookNative() {
  var targets = ['libssl.so', 'libboringssl.so', 'libconscrypt_jni.so',
                 'libcronet.so', 'libflutter.so'];
  function tryHook(name, sym, makeImpl) {
    try {
      var p = Module.findExportByName(name, sym);
      if (!p) return false;
      Interceptor.replace(p, makeImpl(p, sym));
      log('native', 'hooked ' + sym + (name ? ' in ' + name : ''));
      return true;
    } catch (e) { return false; }
  }
  // SSL_CTX_set_custom_verify(ctx, mode, callback) - force callback to a stub
  // that returns 0 (ssl_verify_ok). We overwrite the callback pointer arg.
  function patchCustomVerify(sym) {
    var okCb = new NativeCallback(function () { return 0; }, 'int', ['pointer', 'pointer']);
    try {
      var p = Module.findExportByName(null, sym);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function (args) { args[2] = okCb; },
      });
      log('native', 'forced ok callback on ' + sym);
    } catch (e) {}
  }
  // SSL_get_verify_result -> X509_V_OK(0)
  tryHook(null, 'SSL_get_verify_result', function () {
    return new NativeCallback(function () { return 0; }, 'long', ['pointer']);
  });
  // SSL_set_verify / SSL_CTX_set_verify -> SSL_VERIFY_NONE(0), null cb
  tryHook(null, 'SSL_set_verify', function (orig) {
    var o = new NativeFunction(orig, 'void', ['pointer', 'int', 'pointer']);
    return new NativeCallback(function (ssl) { o(ssl, 0, NULL); }, 'void', ['pointer', 'int', 'pointer']);
  });
  tryHook(null, 'SSL_CTX_set_verify', function (orig) {
    var o = new NativeFunction(orig, 'void', ['pointer', 'int', 'pointer']);
    return new NativeCallback(function (ctx) { o(ctx, 0, NULL); }, 'void', ['pointer', 'int', 'pointer']);
  });
  patchCustomVerify('SSL_CTX_set_custom_verify');
  patchCustomVerify('SSL_set_custom_verify');
  // X509_verify_cert -> 1 (OpenSSL-style, if statically present as export)
  tryHook(null, 'X509_verify_cert', function () {
    return new NativeCallback(function () { return 1; }, 'int', ['pointer']);
  });
}

setImmediate(function () {
  try { hookJava(); } catch (e) { log('fatal', 'java: ' + e); }
  try { hookNative(); } catch (e) { log('fatal', 'native: ' + e); }
  log('ready', 'pinning bypass active - start the mitmproxy capture now');
});
