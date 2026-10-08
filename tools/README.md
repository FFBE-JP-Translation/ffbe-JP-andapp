# tools

Reverse-engineering / preservation utilities for the FFBE AndApp client.

## `cocos_ccz.py`
Decrypt, inspect, and re-pack cocos2d-x **CCZp** encrypted assets using the
XXTEA key recovered from `FF_EXVIUS.exe` (build 10.0.0).

```
python cocos_ccz.py info    VersionAndApp.xml      # header + preview
python cocos_ccz.py decrypt  in.ccz  out.xml       # decrypt + inflate
python cocos_ccz.py encrypt  in.xml  out.ccz       # re-pack (round-trippable)
python cocos_ccz.py keystream                       # show key parts / keystream
```
Key parts: `0x10872fa8, 0x12eb74c3, 0x4ada7aa3, 0xf4783fd9`. See
[`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md) §2.

## `patch_ssl.py`
Disable TLS certificate verification so the client accepts a self-signed /
renamed **preservation server** cert. Patches the OpenSSL/libcurl DLLs that ship
next to the game (`X509_verify_cert`→1, `SSL_get_verify_result`→0), with `.bak`
backups. Requires `pip install pefile`.

```
python patch_ssl.py  <game_dir>            # patch all OpenSSL/curl DLLs found
python patch_ssl.py  --restore <game_dir>  # revert from .bak
```
Prefer the **no-files-modified** alternative built into the loader
(`loader/ssl_hook` via `[ssl] bypass = true`) if you don't want to touch the
game's DLLs. Both do the same two no-ops.

> These only affect the local client you own; they are not for intercepting
> anyone else's traffic.

## `ipc_capture.py`
Capture the SDK↔AndAppHelper handshake by proxying loopback TCP and writing an
annotated hex dump of both directions — the input for completing the helper's
`SessionCrypto` (see [`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md) §5).

```
# Auto: read the real ports from the cfg, proxy in front of the real helper
python ipc_capture.py --cfg "%APPDATA%\AndApp\AndAppHelper.cfg" --out handshake.log
# Manual: fixed listen->target port
python ipc_capture.py --listen 52100 --target 51100 --tag cmd --out handshake.log
```
Start real AndApp first (so the helper + cfg exist), run this, then launch the
game. Ctrl-C restores the cfg. Stdlib only.

## `andapp_mitm.py`
**Decrypting** man-in-the-middle for the SDK↔helper IPC (`ipc_capture.py` is a
passive tee and can't decrypt — the AES key is RSA-sealed to the game). This runs
two handshakes (acts as the helper toward the game, as a client toward the real
helper), so it can log the **plaintext** request/response of a real session.
Since neither side authenticates its peer, it just works.

```
python andapp_mitm.py --selftest                                  # validate crypto
python andapp_mitm.py --cfg "%APPDATA%\AndApp\AndAppHelper.cfg" --out mitm.log
```
Start the real AndApp, run this, launch a game that still works (e.g. FFRK) to
capture the authoritative success responses for the shared SDK commands
(`initialize`, `get_id_token`, …) — the schema the replacement helper must match.
Requires `pip install pycryptodome`. Ctrl-C restores the cfg.

## `andapp_capture.py`
Capture **live** AndApp credentials from the real local `AndAppHelper` and write
them into the game-dir `andapp_loader.ini` `[helper]` section, so the loader can
replay them for live-backend games (e.g. FFRK/Sakasho, which reject synthesized
tokens). It connects as a client (same RSA/AES handshake), runs `initialize` /
`get_id_token` / `get_in_app_user_id`, and extracts `access_token` / `id_token` /
`player_id` / `andapp_user_id` / `device_account_id` / `andapp_client_version` /
`app_id` / `passphrase`. If `andapphelper.exe` isn't running it launches
`%LOCALAPPDATA%\AndApp\AndAppNext.exe` and waits for it.

```
python andapp_capture.py --gamedir "T:\...\Payload" \
    --client-id 6481500049506304 --sdk-version 1.1.0-p2 --api-level 3   # FFRK
```
Requires `pip install pycryptodome`, the real AndApp installed, and you logged in.
The captured JWTs are sensitive and expire (~1 h) — re-run before each session and
don't share the ini. Windows only.

## manifest.json / `signature` (no tool — by design)
`manifest.json`'s `signature[]` and the sibling `signature` file are 64-byte
**asymmetric** signatures (ECDSA-P256/Ed25519, DeNA private key) and **cannot be
regenerated** without that key. They are **only checked by AndApp, never by the
game**, so a direct launch does not need valid ones and no generator is shipped.
See [`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md) §6 for the
full analysis.

