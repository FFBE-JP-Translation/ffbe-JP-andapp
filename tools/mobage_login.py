#!/usr/bin/env python3
"""
mobage_login.py - reproduce the FFRK Android -> Mobage/Sakasho session bootstrap
headlessly, without AndApp, for preservation of YOUR OWN account.

This replays the exact SP-SDK sequence captured from the Android client (see
docs/REVERSE_ENGINEERING.md 7a/7b): it signs the OAuth 1.0a HMAC-SHA1 calls and
drives phases 1-4 to obtain an authenticated Sakasho game session cookie
(`http_session_sid`) for `dff.sp.mbga.jp`.

Client constants (recovered from the APK, see 7b - no per-user secret):
  * The consumer key/secret are the client's own baked-in constants, read from
    `res/values/arrays.xml` (`consumerkey_product` array) by
    `com.mobage.android.sphybrid.AppConfig` and used by the SP SDK signer.
    They are embedded here as defaults; override with --consumer-secret.
  * --oauth-token / --oauth-token-secret : the phase-1 access token
    (`credentialsInfo.credentials` in the `_sdk_chk_and_auth`
    session_callback). NOTE: this is minted FRESH each launch (ephemeral),
    so either pass --mobage-cookie (the sp.mbga.jp WebView cookie jar of a
    logged-in device) and let phase 1 mint it, or re-capture it per session.
  * --session-sid     : a starting GUEST `http_session_sid` cookie for
    dff.sp.mbga.jp (the one phase 2 rides before the user is bound; phase 4
    issues the authenticated replacement).

  python mobage_login.py --verify-signer        # offline check vs captured signatures
  python mobage_login.py --selftest             # interactive signature check
  python mobage_login.py --mobage-cookie "SP_...=..." [--mobage-cookie ...] \
      --session-sid "...."                      # full headless phases 1-4
  python mobage_login.py --consumer-secret SECRET \
      --oauth-token "sdk_client_id:...." --oauth-token-secret "...." \
      --session-sid "...." --user-id 12345      # phases 2-4 with a fresh token

These are your own credentials against live servers, for preservation only.
Requires: pip install requests
"""
import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import string
import sys
import time
from urllib.parse import quote, parse_qsl

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

GAME_ID = "12019103"
PACKAGE = "jp.mbga.a12019103.lite"
CONSUMER_KEY = "sdk_app_id:" + GAME_ID
# Client constant recovered from res/values/arrays.xml -> consumerkey_product[1]
# (see docs/REVERSE_ENGINEERING.md 7b). Verified against the packet captures:
# `python mobage_login.py --verify-signer`.
CONSUMER_SECRET = "16e7347fd01e36f96454658df8e45142"
SDK_VERSION = "1.15.0"
UA_NATIVE = "nativesdk-android/" + SDK_VERSION
UA_HTTP = "android-async-http/1.4.1 (http://loopj.com/android-async-http)"
UA_WEBVIEW = ("Mozilla/5.0 (Linux; Android 12; SM-G977N Build/LMY48Z; wv) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
              "Chrome/95.0.4638.74 Mobile Safari/537.36")

HOST_SSL = "https://ssl.sp.mbga.jp"
HOST_PLATFORM = "https://ssl.sp.mbga-platform.jp"
HOST_DFF = "https://dff.sp.mbga.jp"
CHK_AUTH = HOST_SSL + "/_sdk_chk_and_auth"
JSONRPC = HOST_PLATFORM + "/social/api/jsonrpc/v2.03"


# ---- OAuth 1.0a HMAC-SHA1 ----------------------------------------------------
def _pe(s):
    """RFC 5849 percent-encoding."""
    return quote(str(s), safe="~")


def oauth_base_string(method, url, params):
    # params: dict of all oauth_* + query/body params that participate.
    norm = "&".join("%s=%s" % (_pe(k), _pe(v))
                    for k, v in sorted((str(k), str(v)) for k, v in params.items()))
    return "&".join([method.upper(), _pe(url), _pe(norm)])


def oauth_sign(method, url, params, consumer_secret, token_secret=""):
    base = oauth_base_string(method, url, params)
    key = "%s&%s" % (_pe(consumer_secret), _pe(token_secret))
    digest = hmac.new(key.encode(), base.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode(), base


def _nonce():
    # the SP SDK uses 6 chars of [A-Za-z0-9]
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(6))


def oauth_params(token="", extra=None):
    p = {
        "oauth_consumer_key": CONSUMER_KEY,
        "oauth_nonce": _nonce(),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_version": "1.0",
    }
    if token:
        p["oauth_token"] = token
    if extra:
        p.update(extra)
    return p


def body_hash(body_bytes):
    return base64.b64encode(hashlib.sha1(body_bytes).digest()).decode()


def auth_header(params):
    return "OAuth " + ",".join('%s="%s"' % (_pe(k), _pe(v))
                               for k, v in sorted(params.items()))


# ---- phase 1: SDK auth check (the WebView leg) --------------------------------
def phase1_chk_and_auth(sess, consumer_secret):
    """2-legged signed GET on ssl.sp.mbga.jp.

    Returns (oauth_token, oauth_token_secret, user_id). Requires the session
    to carry a logged-in Mobage-ID cookie jar for sp.mbga.jp (seed with
    --mobage-cookie); otherwise the endpoint answers `please_login=1`.
    """
    params = oauth_params(extra={
        "SP_SDK_BUNDLE_IDENTIFIER": PACKAGE,
        "SP_SDK_MOBAGE_BUNDLE_IDENTIFIER": PACKAGE,
        "SP_SDK_NOTIFICATION_TOKEN_TYPE": "FCM",
        "SP_SDK_TYPE": "native-android",
        "game_id": GAME_ID,
        "on_launch": "",
        "on_resume": "",
    })
    # 2-legged: oauth_token present but empty, and it participates in signing
    params["oauth_token"] = ""
    sig, _ = oauth_sign("GET", CHK_AUTH, params, consumer_secret, "")
    params["oauth_signature"] = sig
    r = sess.get(CHK_AUTH, params=params, headers={
        "User-Agent": UA_WEBVIEW, "Accept": "text/html,…", "X-Requested-With": PACKAGE,
    }, timeout=20)
    r.raise_for_status()
    m = re.search(r"ngcore:///session_callback#([^'\"]+)", r.text)
    if not m:
        raise RuntimeError("no session_callback in response: %r" % r.text[:200])
    frag = dict(parse_qsl(m.group(1), keep_blank_values=True))
    if frag.get("please_login") == "1" or "credentialsInfo" not in frag:
        raise RuntimeError("not logged in (please_login): seed --mobage-cookie "
                           "with the device's sp.mbga.jp cookie jar")
    creds = json.loads(frag["credentialsInfo"])["credentials"]
    return creds["oauth_token"], creds["oauth_token_secret"], frag.get("user_id", "")


# ---- phases 2-4 ----------------------------------------------------------------
def phase2_temp_credential(sess):
    r = sess.post(HOST_DFF + "/dff/_api_get_temporary_credential",
                  headers={"User-Agent": UA_HTTP,
                           "Content-Type": "application/x-www-form-urlencoded"},
                  data="", timeout=20)
    r.raise_for_status()
    j = r.json()
    return j["oauth_token"]


def phase3_authorize(sess, consumer_secret, user_token, user_token_secret,
                     temp_token, user_id):
    """social API accesstoken.authorizeToken -> verifier."""
    body = json.dumps({
        "jsonrpc": "2.0", "method": "accesstoken.authorizeToken",
        "id": str(int(time.time())), "params": {"token": temp_token},
    }, separators=(",", ":")).encode()  # compact, byte-exact like the client
    params = oauth_params(token=user_token, extra={
        "oauth_body_hash": body_hash(body),
        "xoauth_requestor_id": str(user_id),
    })
    sig, _ = oauth_sign("POST", JSONRPC, params, consumer_secret, user_token_secret)
    params["oauth_signature"] = sig
    r = sess.post(JSONRPC, data=body, headers={
        "Authorization": auth_header(params),
        "Content-type": "application/json; charset=utf-8",
        "Accept": "application/json", "User-Agent": UA_NATIVE,
    }, timeout=20)
    r.raise_for_status()
    return r.json()["result"]["verifier"]


def phase4_create_session(sess, verifier, temp_token):
    r = sess.post(HOST_DFF + "/dff/_api_create_session",
                  headers={"User-Agent": UA_HTTP,
                           "Content-Type": "application/x-www-form-urlencoded"},
                  data={"verifier": verifier, "oauth_token": temp_token},
                  timeout=20)
    r.raise_for_status()
    return r.json(), sess.cookies.get("http_session_sid")


def run(args):
    sess = requests.Session()
    consumer_secret = args.consumer_secret or CONSUMER_SECRET
    for c in args.mobage_cookie or []:
        if "=" not in c:
            ap_error = "bad --mobage-cookie (want NAME=VALUE): %r" % c
            raise SystemExit(ap_error)
        name, value = c.split("=", 1)
        sess.cookies.set(name, value, domain=".sp.mbga.jp")
    if args.session_sid:
        sess.cookies.set("http_session_sid", args.session_sid, domain="dff.sp.mbga.jp")

    oauth_token, token_secret, user_id = args.oauth_token, args.oauth_token_secret, args.user_id
    if not oauth_token and args.mobage_cookie:
        print("[1] _sdk_chk_and_auth ...")
        oauth_token, token_secret, user_id = phase1_chk_and_auth(sess, consumer_secret)
        print("    oauth_token   =", oauth_token)
        print("    user_id       =", user_id)
    if not oauth_token:
        raise SystemExit("no phase-1 token: pass --oauth-token/--oauth-token-secret "
                         "or --mobage-cookie cookies to mint one (see docstring)")
    if not user_id:
        raise SystemExit("need --user-id (xoauth_requestor_id) for phase 3")

    print("[2] get_temporary_credential ...")
    temp = phase2_temp_credential(sess)
    print("    temp_token =", temp)
    print("[3] accesstoken.authorizeToken ...")
    verifier = phase3_authorize(sess, consumer_secret, oauth_token,
                                token_secret, temp, user_id)
    print("    verifier   =", verifier)
    print("[4] create_session ...")
    profile, sid = phase4_create_session(sess, verifier, temp)
    print("    profile    =", json.dumps(profile, ensure_ascii=False))
    print("    http_session_sid =", sid)
    print("\nSakasho session established for id=%s. Use this cookie for /dff/."
          % profile.get("id"))
    return 0


# ---- offline verification against the repo's own captures ----------------------
# Vectors from packet-captures/after_login_http_toolkit_frida.txt (expired
# ephemeral values from the author's own account; used only as a signer oracle).
_ORACLE = [
    {
        "name": "phase 1 (_sdk_chk_and_auth, 2-legged)",
        "method": "GET", "url": CHK_AUTH,
        "params": {
            "SP_SDK_BUNDLE_IDENTIFIER": PACKAGE,
            "SP_SDK_MOBAGE_BUNDLE_IDENTIFIER": PACKAGE,
            "SP_SDK_NOTIFICATION_TOKEN_TYPE": "FCM",
            "SP_SDK_TYPE": "native-android",
            "game_id": GAME_ID,
            "oauth_consumer_key": CONSUMER_KEY,
            "oauth_nonce": "44St85",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": "1791458384",
            "oauth_token": "",
            "oauth_version": "1.0",
            "on_launch": "",
            "on_resume": "",
        },
        "token_secret": "",
        "expect": "2zypzbNCGWyISTkJ1xCB3jktVXY=",
    },
    {
        "name": "phase 3 (accesstoken.authorizeToken, 3-legged)",
        "method": "POST", "url": JSONRPC,
        "params": {
            "oauth_body_hash": "E73dwWhVCXqRNB21235hgjgf+p4=",
            "oauth_consumer_key": CONSUMER_KEY,
            "oauth_nonce": "aCXI8z",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": "1791458386",
            "oauth_token": "sdk_client_id:7ea15d1304f0e3800f9c3df977ff40155aa371ec",
            "oauth_version": "1.0",
            "xoauth_mobile_carrier": "Telstra+Corporation+Ltd.",
            "xoauth_requestor_id": "170082138",
        },
        "token_secret": "uYGpemMyiAaWgvGMooFxXtil39uEDh0w",
        "expect": "MI1BqjABHxp1H6NK6L2bkXlFGrw=",
    },
]


def verify_signer():
    """Offline unit test: consumer secret + signer against captured signatures."""
    ok = True
    for vec in _ORACLE:
        sig, _ = oauth_sign(vec["method"], vec["url"], vec["params"],
                            CONSUMER_SECRET, vec["token_secret"])
        match = sig == vec["expect"]
        ok &= match
        print("%-46s %s  (%s)" % (vec["name"], sig, "MATCH" if match else "NO MATCH"))
    body = ('{"jsonrpc":"2.0","method":"accesstoken.authorizeToken",'
            '"id":"1791458386","params":{"token":"temporary_credential:'
            '260dd6563dcda1cae72fc507d2321807e3a98cce"}}').encode()
    bh = body_hash(body)
    match = bh == "E73dwWhVCXqRNB21235hgjgf+p4="
    ok &= match
    print("%-46s %s  (%s)" % ("phase 3 oauth_body_hash (compact JSON)", bh,
                              "MATCH" if match else "NO MATCH"))
    print("\nconsumer secret %s" % ("VERIFIED" if ok else "FAILED"))
    return 0 if ok else 1


# ---- selftest: verify a consumer-secret guess against a captured request -----
def selftest():
    print("Paste a captured GET/POST you have the oauth_signature for.\n"
          "Example (phase 1, 2-legged): method=GET, url=%s/_sdk_chk_and_auth,\n"
          "token_secret empty.\n" % HOST_SSL)
    method = input("method [GET]: ").strip() or "GET"
    url = input("base url (no query): ").strip()
    print("paste the full query string OR the Authorization OAuth params, "
          "as key=value&key=value (include oauth_* EXCEPT oauth_signature):")
    raw = input("> ").strip()
    params = dict(parse_qsl(raw, keep_blank_values=True))
    params.pop("oauth_signature", None)
    secret = input("consumer_secret [%s]: ").strip() or CONSUMER_SECRET
    tsec = input("token_secret [empty]: ").strip()
    observed = input("observed oauth_signature (url-decoded): ").strip()
    sig, base = oauth_sign(method, url, params, secret, tsec)
    print("\nbase string:\n", base)
    print("\ncomputed signature:", sig)
    print("observed signature:", observed)
    print("MATCH" if sig == observed else "NO MATCH - wrong secret or missing param")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--verify-signer", action="store_true",
                    help="offline check of the embedded client constants against "
                         "the packet-capture oracle vectors")
    ap.add_argument("--consumer-secret",
                    help="override the recovered client constant")
    ap.add_argument("--mobage-cookie", action="append", metavar="NAME=VALUE",
                    help="sp.mbga.jp cookie for phase 1 (repeatable); "
                         "e.g. the device WebView jar after a Mobage-ID login")
    ap.add_argument("--oauth-token")
    ap.add_argument("--oauth-token-secret")
    ap.add_argument("--session-sid")
    ap.add_argument("--user-id")
    a = ap.parse_args(argv[1:])
    if a.verify_signer:
        return verify_signer()
    if a.selftest:
        return selftest()
    return run(a)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
