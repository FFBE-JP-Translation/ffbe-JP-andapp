#!/usr/bin/env python3
"""
mobage_login.py - reproduce the FFRK Android -> Mobage/Sakasho session bootstrap
headlessly, without AndApp, for preservation of YOUR OWN account.

This replays the exact SP-SDK sequence captured from the Android client (see
docs/REVERSE_ENGINEERING.md 7a): it signs the OAuth 1.0a HMAC-SHA1 calls and
drives phases 2-4 to obtain an authenticated Sakasho game session cookie
(`http_session_sid`) for `dff.sp.mbga.jp`.

What YOU supply (none of it is extracted or embedded here):
  * --consumer-secret : the HMAC secret for oauth_consumer_key
                        `sdk_app_id:12019103`. It is baked into the client's
                        native library; this tool does NOT pull it out of any
                        binary - provide it yourself if you have it.
  * --oauth-token / --oauth-token-secret : the phase-1 access token
                        (`credentialsInfo.credentials` in the `_sdk_chk_and_auth`
                        session_callback). NOTE: this is minted FRESH each launch
                        (ephemeral, like AndApp's ~1h JWTs), so re-capture it per
                        session via the real client's WebView login (HTTP Toolkit
                        + tools/frida_unpin.js), or re-mint it by reproducing
                        `_sdk_chk_and_auth` (needs the consumer secret + the
                        device's stored Mobage-ID cookies).
  * --session-sid     : a starting GUEST `http_session_sid` cookie for
                        dff.sp.mbga.jp (the one phase 2 rides before the user is
                        bound; phase 4 issues the authenticated replacement).

Use --selftest to verify a consumer-secret guess against a request you captured:
it recomputes the oauth_signature for a request you paste and compares it to the
observed one - the cheap way to confirm the secret without touching a binary.

These are your own credentials against live servers, for preservation only.
Requires: pip install requests

Usage:
  python mobage_login.py --consumer-secret SECRET \
      --oauth-token "sdk_client_id:...." --oauth-token-secret "...." \
      --session-sid "...."            # run phases 2-4, print the game session
  python mobage_login.py --selftest   # interactive signature check
"""
import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sys
import time
from urllib.parse import quote, urlencode, urlparse, parse_qsl

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

GAME_ID = "12019103"
CONSUMER_KEY = "sdk_app_id:" + GAME_ID
SDK_VERSION = "1.15.0"
UA_NATIVE = "nativesdk-android/" + SDK_VERSION
UA_HTTP = "android-async-http/1.4.1 (http://loopj.com/android-async-http)"

HOST_SSL = "https://ssl.sp.mbga.jp"
HOST_PLATFORM = "https://ssl.sp.mbga-platform.jp"
HOST_DFF = "https://dff.sp.mbga.jp"
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


def oauth_params(token="", extra=None):
    p = {
        "oauth_consumer_key": CONSUMER_KEY,
        "oauth_nonce": secrets.token_urlsafe(4)[:6],
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


# ---- phases ------------------------------------------------------------------
def phase3_authorize(sess, consumer_secret, user_token, user_token_secret,
                     temp_token, user_id):
    """social API accesstoken.authorizeToken -> verifier."""
    body = json.dumps({
        "jsonrpc": "2.0", "method": "accesstoken.authorizeToken",
        "id": str(int(time.time())), "params": {"token": temp_token},
    }, separators=(",", ":")).encode()
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


def phase2_temp_credential(sess):
    r = sess.post(HOST_DFF + "/dff/_api_get_temporary_credential",
                  headers={"User-Agent": UA_HTTP,
                           "Content-Type": "application/x-www-form-urlencoded"},
                  data="", timeout=20)
    r.raise_for_status()
    j = r.json()
    return j["oauth_token"]


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
    if args.session_sid:
        sess.cookies.set("http_session_sid", args.session_sid, domain="dff.sp.mbga.jp")
    print("[2] get_temporary_credential ...")
    temp = phase2_temp_credential(sess)
    print("    temp_token =", temp)
    print("[3] accesstoken.authorizeToken ...")
    verifier = phase3_authorize(sess, args.consumer_secret, args.oauth_token,
                                args.oauth_token_secret, temp, args.user_id)
    print("    verifier   =", verifier)
    print("[4] create_session ...")
    profile, sid = phase4_create_session(sess, verifier, temp)
    print("    profile    =", json.dumps(profile, ensure_ascii=False))
    print("    http_session_sid =", sid)
    print("\nSakasho session established for id=%s. Use this cookie for /dff/."
          % profile.get("id"))
    return 0


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
    secret = input("consumer_secret: ").strip()
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
    ap.add_argument("--consumer-secret")
    ap.add_argument("--oauth-token")
    ap.add_argument("--oauth-token-secret")
    ap.add_argument("--session-sid")
    ap.add_argument("--user-id")
    a = ap.parse_args(argv[1:])
    if a.selftest:
        return selftest()
    missing = [n for n in ("consumer_secret", "oauth_token", "oauth_token_secret")
               if not getattr(a, n)]
    if missing:
        ap.error("need --" + ", --".join(m.replace("_", "-") for m in missing)
                 + " (or --selftest). See the module docstring.")
    return run(a)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
