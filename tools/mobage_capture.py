#!/usr/bin/env python3
"""
mobage_capture.py - a mitmproxy addon that isolates the FFRK Android login flow
and pulls out the pieces we need to reproduce it without AndApp:

  * the Mobage OAuth 1.0a 3-legged handshake (request_token / authorize /
    access_token) against connect.mobage.jp / *.mbga.jp,
  * the Sakasho session bootstrap against dff.sp.mbga.jp / sp.mbga.jp, and
  * the `passphrase` your account receives (the same value live Sakasho
    validates when the PC build forwards it - see docs §5b).

It writes an annotated JSONL transcript (every relevant request/response, with
headers and bodies) plus a compact `mobage_creds.json` of the extracted fields,
so you can diff the Android flow against what AndApp's helper hands the PC build.

This is YOUR OWN account on a device YOU control, captured against the live
servers for preservation; the tokens/passphrase are sensitive - don't share the
output. Run under mitmproxy, with the device proxied through it, its CA trusted,
and tools/frida_unpin.js defeating the app's pinning.

Usage:
  mitmdump -s mobage_capture.py                 # headless, writes files in CWD
  mitmweb  -s mobage_capture.py                 # with the web UI
  mitmdump -s mobage_capture.py --set mobage_out=/path/prefix

Requires mitmproxy (pip install mitmproxy). Tested with mitmproxy 10/11.
"""
import json
import re
import time
from urllib.parse import parse_qsl, urlparse

from mitmproxy import ctx, http

# Hosts that make up the Mobage/Sakasho auth + game-data surface. Matched as
# suffixes so subdomains (dff.sp.mbga.jp, connect.mobage.jp, ...) are covered.
MOBAGE_HOSTS = (
    "mbga.jp",          # sp.mbga.jp, dff.sp.mbga.jp (Sakasho), connect.mbga.jp
    "mobage.jp",        # connect.mobage.jp (OAuth / login)
    "dena.com",         # occasional CDN / auth edges
    "sakasho",          # any sakasho-* vanity host
)

# URL path fragments that mark the OAuth 1.0a legs / session bootstrap.
OAUTH_MARKERS = ("request_token", "access_token", "authorize", "/login",
                 "/oauth", "idp", "federation")
SAKASHO_MARKERS = ("sakasho", "/sk/", "passphrase", "session", "player")

# Keys worth lifting out of bodies/headers wherever they appear.
WANTED_KEYS = ("passphrase", "oauth_token", "oauth_token_secret",
               "oauth_verifier", "oauth_consumer_key", "access_token",
               "id_token", "player_id", "user_id", "session", "sakasho_user_id",
               "sakasho_access_token", "device_id", "guid")


def _is_mobage(host: str) -> bool:
    host = (host or "").lower()
    return any(h in host for h in MOBAGE_HOSTS)


def _kind(url: str) -> str:
    low = url.lower()
    if any(m in low for m in OAUTH_MARKERS):
        return "oauth"
    if any(m in low for m in SAKASHO_MARKERS):
        return "sakasho"
    return "other"


def _auth_header_fields(value: str) -> dict:
    """Parse an `OAuth oauth_consumer_key="...", ...` Authorization header."""
    out = {}
    for m in re.finditer(r'(\w+)="([^"]*)"', value or ""):
        out[m.group(1)] = m.group(2)
    return out


def _lift(blob, found: dict):
    """Recursively pull WANTED_KEYS out of a dict/list, into `found`."""
    if isinstance(blob, dict):
        for k, v in blob.items():
            if k in WANTED_KEYS and not isinstance(v, (dict, list)):
                found.setdefault(k, v)
            _lift(v, found)
    elif isinstance(blob, list):
        for v in blob:
            _lift(v, found)


def _body_fields(text: str, content_type: str) -> dict:
    found = {}
    if not text:
        return found
    ct = (content_type or "").lower()
    # JSON
    if "json" in ct or text.lstrip()[:1] in "{[":
        try:
            _lift(json.loads(text), found)
            return found
        except Exception:
            pass
    # form-urlencoded (OAuth token responses are usually this)
    if "form-urlencoded" in ct or ("=" in text and "&" in text and "{" not in text):
        for k, v in parse_qsl(text):
            if k in WANTED_KEYS:
                found.setdefault(k, v)
        # also scan for oauth_* even if not in WANTED_KEYS
        for k, v in parse_qsl(text):
            if k.startswith("oauth_"):
                found.setdefault(k, v)
    return found


class MobageCapture:
    def __init__(self):
        self.creds = {}
        self.n = 0
        self.prefix = "mobage"

    def load(self, loader):
        loader.add_option("mobage_out", str, "mobage",
                          "output path prefix for the transcript + creds")

    def configure(self, updated):
        if "mobage_out" in updated:
            self.prefix = ctx.options.mobage_out

    def _jsonl(self):
        return self.prefix + "_transcript.jsonl"

    def _credsfile(self):
        return self.prefix + "_creds.json"

    def response(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if not _is_mobage(host):
            return
        self.n += 1
        url = flow.request.pretty_url
        kind = _kind(url)

        found = {}
        # Authorization: OAuth ... header on the request
        auth = flow.request.headers.get("Authorization", "")
        if auth.lower().startswith("oauth"):
            for k, v in _auth_header_fields(auth).items():
                if k.startswith("oauth_"):
                    found.setdefault(k, v)
        # query string
        for k, v in parse_qsl(urlparse(url).query):
            if k in WANTED_KEYS or k.startswith("oauth_"):
                found.setdefault(k, v)
        # request + response bodies
        try:
            found.update(_body_fields(flow.request.get_text(strict=False),
                                      flow.request.headers.get("Content-Type", "")))
        except Exception:
            pass
        try:
            found.update(_body_fields(flow.response.get_text(strict=False),
                                      flow.response.headers.get("Content-Type", "")))
        except Exception:
            pass

        # record everything (bodies capped so the transcript stays readable)
        def clip(t):
            return (t or "")[:8192]

        entry = {
            "i": self.n,
            "t": time.strftime("%H:%M:%S"),
            "kind": kind,
            "method": flow.request.method,
            "url": url,
            "status": flow.response.status_code,
            "req_headers": dict(flow.request.headers),
            "req_body": clip(flow.request.get_text(strict=False)),
            "resp_headers": dict(flow.response.headers),
            "resp_body": clip(flow.response.get_text(strict=False)),
            "extracted": found,
        }
        with open(self._jsonl(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        if found:
            self.creds.update(found)
            with open(self._credsfile(), "w", encoding="utf-8") as f:
                json.dump(self.creds, f, ensure_ascii=False, indent=2)
            flagged = ", ".join(sorted(found))
            ctx.log.alert("[mobage] %s %s  <-- %s" % (kind, host, flagged))
            if "passphrase" in found:
                ctx.log.alert("[mobage] *** PASSPHRASE captured -> %s ***"
                              % self._credsfile())
        else:
            ctx.log.info("[mobage] %s %s %s" % (kind, flow.request.method, host))


addons = [MobageCapture()]
