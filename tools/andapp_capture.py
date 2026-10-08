#!/usr/bin/env python3
"""
andapp_capture.py - Capture live AndApp auth credentials from the real local
AndAppHelper and write them into the game-dir andapp_loader.ini [helper] section,
so the winmm loader can replay them (needed for live-backend games like FFRK,
whose Sakasho backend rejects synthesized tokens).

It speaks the same loopback IPC the game SDK uses:
  * read the real helper's port from %APPDATA%\\AndApp\\AndAppHelper.cfg (JSON),
  * do the RSA/AES handshake AS A CLIENT (we generate the RSA key, the helper
    returns the AES key),
  * send initialize / get_id_token / get_in_app_user_id and decrypt the replies,
  * extract session.access_token / id_token / player_id, andapp_user_id,
    device_account_id, andapp_client_version, and the get_in_app_user_id
    passphrase + app id.

If andapphelper.exe is not running, it launches
%LOCALAPPDATA%\\AndApp\\AndAppNext.exe and waits for andapphelper.exe to appear.

These are YOUR OWN account's credentials, read locally; the tokens are sensitive
(and the JWTs expire ~1h) - don't share the resulting ini. Windows only (needs
the real AndApp). Requires: pip install pycryptodome

Usage:
  python andapp_capture.py --gamedir "T:\\...\\Payload" \
        --client-id 6481500049506304 --sdk-version 1.1.0-p2 --api-level 3
Defaults target FFRK; pass FFBE's values (--client-id 5701868182306816
--sdk-version 1.0.4 --api-level 1) to capture FFBE instead.
"""
import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5

CALG_RSA_KEYX, CALG_AES_256 = 0x0000A400, 0x00006610
OP_PUBKEY, OP_AESKEY, OP_HELLO, OP_ACK, OP_DATA = 1, 2, 3, 4, 0x10


# ---- CryptoAPI blob + AES (client side) -------------------------------------
def make_publickeyblob(pub):
    bl = (pub.n.bit_length() + 7) // 8 * 8
    return (bytes([6, 2, 0, 0]) + struct.pack("<I", CALG_RSA_KEYX) + b"RSA1" +
            struct.pack("<I", bl) + struct.pack("<I", pub.e) +
            pub.n.to_bytes(bl // 8, "little"))


def parse_simpleblob(blob, priv):
    key = PKCS1_v1_5.new(priv).decrypt(blob[12:][::-1], None)
    if not key:
        raise ValueError("AES key decrypt failed")
    return key


def aes_dec(k, ct):
    pt = AES.new(k, AES.MODE_CBC, iv=b"\0" * 16).decrypt(ct)
    return pt[:-pt[-1]] if pt else pt


def aes_enc(k, pt):
    pad = 16 - (len(pt) % 16)
    return AES.new(k, AES.MODE_CBC, iv=b"\0" * 16).encrypt(pt + bytes([pad]) * pad)


def send_frame(s, op, payload):
    s.sendall(struct.pack(">II", op, len(payload)) + payload)


def recv_all(s, n):
    b = b""
    while len(b) < n:
        r = s.recv(n - len(b))
        if not r:
            raise ConnectionError("helper closed the connection")
        b += r
    return b


def read_frame(s):
    op, ln = struct.unpack(">II", recv_all(s, 8))
    return op, (recv_all(s, ln) if ln else b"")


# ---- helper discovery / launch ----------------------------------------------
def helper_running():
    try:
        out = subprocess.check_output(["tasklist", "/fi", "imagename eq andapphelper.exe"],
                                      text=True, stderr=subprocess.DEVNULL)
        return "andapphelper.exe" in out.lower()
    except Exception:
        return False


def ensure_helper(cfg_path):
    if helper_running() and os.path.exists(cfg_path):
        return
    exe = os.path.join(os.environ.get("LOCALAPPDATA", ""), "AndApp", "AndAppNext.exe")
    if not os.path.exists(exe):
        sys.exit("andapphelper not running and AndAppNext.exe not found at %s" % exe)
    print("Launching", exe, "...")
    subprocess.Popen([exe])
    for _ in range(120):  # up to ~60s
        if helper_running() and os.path.exists(cfg_path):
            print("andapphelper.exe is up.")
            time.sleep(1.0)  # let it finish writing the cfg
            return
        time.sleep(0.5)
    sys.exit("timed out waiting for andapphelper.exe to start")


def read_command_port(cfg_path):
    cfg = json.load(open(cfg_path, encoding="utf-8"))
    return int(cfg["standard.tcp.command.ipv4.port"])


# ---- session ----------------------------------------------------------------
def capture(port, client_id, api_level, sdk_version, payload_id):
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    priv = RSA.generate(1024)
    send_frame(s, OP_PUBKEY, make_publickeyblob(priv.publickey()))
    op, blob = read_frame(s)
    key = parse_simpleblob(blob, priv)
    send_frame(s, OP_HELLO, json.dumps({"clientid": str(client_id)}).encode())
    read_frame(s)  # ack

    def cmd(obj):
        send_frame(s, OP_DATA, aes_enc(key, json.dumps(obj).encode()))
        op, ct = read_frame(s)
        return json.loads(aes_dec(key, ct).decode("utf-8", "replace"))

    init_cfg = {"clientId": str(client_id), "disableLogging": True}
    init_params = {"api_level": api_level, "config": init_cfg, "sdk_version": sdk_version}
    if payload_id:
        init_params["payload_id"] = str(payload_id)
    r_init = cmd({"initialize": init_params})
    r_tok = cmd({"get_id_token": {}})
    r_uid = cmd({"get_in_app_user_id": {}})
    s.close()
    if "error" in r_init and r_init["error"]:
        sys.exit("initialize failed: %s" % r_init["error"])

    sess = r_init.get("session", {}) or {}
    extras = (r_uid.get("extras") or {})
    return {
        "andapp_client_version": r_init.get("andapp_client_version", ""),
        "andapp_user_id": str(r_init.get("andapp_user_id", "")),
        "device_account_id": str(r_init.get("device_account_id", "")),
        "player_id": str(sess.get("player_id", "")),
        "access_token": sess.get("access_token", ""),
        "id_token": r_tok.get("id_token") or sess.get("id_token", ""),
        "app_id": str(r_uid.get("id", "")),
        "passphrase": extras.get("passphrase", ""),
    }, {"initialize": r_init, "get_id_token": r_tok, "get_in_app_user_id": r_uid}


# ---- write into andapp_loader.ini [helper] ----------------------------------
def set_ini(path, section, values):
    lines = open(path, encoding="utf-8").read().splitlines() if os.path.exists(path) else []
    out, in_sec, done = [], False, set()
    i = 0
    def emit_missing():
        for k, v in values.items():
            if k not in done:
                out.append("%s = %s" % (k, v)); done.add(k)
    while i < len(lines):
        ln = lines[i]
        st = ln.strip()
        if st.startswith("[") and st.endswith("]"):
            if in_sec:                      # leaving our section: add any missing keys
                emit_missing()
            in_sec = st[1:-1].strip().lower() == section
            out.append(ln); i += 1; continue
        if in_sec and "=" in st and not st.startswith("#") and not st.startswith(";"):
            k = st.split("=", 1)[0].strip().lower()
            if k in values:
                out.append("%s = %s" % (k, values[k])); done.add(k); i += 1; continue
        # replace a commented placeholder like "# passphrase ="
        if in_sec and (st.startswith("#") or st.startswith(";")) and "=" in st:
            k = st.lstrip("#; ").split("=", 1)[0].strip().lower()
            if k in values and k not in done:
                out.append("%s = %s" % (k, values[k])); done.add(k); i += 1; continue
        out.append(ln); i += 1
    if in_sec:
        emit_missing()
    if section not in [l.strip()[1:-1].strip().lower() for l in out
                       if l.strip().startswith("[") and l.strip().endswith("]")]:
        out.append(""); out.append("[%s]" % section); emit_missing()
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")


def main(argv):
    ap = argparse.ArgumentParser(description="Capture AndApp creds into andapp_loader.ini")
    ap.add_argument("--gamedir", default=".")
    ap.add_argument("--out", help="andapp_loader.ini path (default <gamedir>\\andapp_loader.ini)")
    ap.add_argument("--cfg", default=os.path.join(os.environ.get("APPDATA", ""),
                                                  "AndApp", "AndAppHelper.cfg"))
    ap.add_argument("--client-id", default="6481500049506304")
    ap.add_argument("--api-level", type=int, default=3)
    ap.add_argument("--sdk-version", default="1.1.0-p2")
    ap.add_argument("--payload-id", default="")
    ap.add_argument("--dump", action="store_true", help="also print raw responses")
    a = ap.parse_args(argv[1:])
    out = a.out or os.path.join(a.gamedir, "andapp_loader.ini")

    ensure_helper(a.cfg)
    port = read_command_port(a.cfg)
    print("Connecting to AndAppHelper on 127.0.0.1:%d ..." % port)
    creds, raw = capture(port, a.client_id, a.api_level, a.sdk_version, a.payload_id)
    if a.dump:
        print(json.dumps(raw, indent=2, ensure_ascii=False))
    print("Captured:")
    for k, v in creds.items():
        shown = v if k in ("andapp_client_version", "app_id", "player_id",
                           "andapp_user_id", "device_account_id") else (v[:24] + "..." if v else "")
        print("  %-22s %s" % (k, shown))
    # only write non-empty values
    set_ini(out, "helper", {k: v for k, v in creds.items() if v})
    print("Wrote [helper] credentials to", out)
    print("Note: id_token/access_token are JWTs (~1h expiry) - re-run before each session.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
