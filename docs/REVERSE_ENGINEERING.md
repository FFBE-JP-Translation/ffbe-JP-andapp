# FFBE (AndApp) — reverse-engineering notes for preservation

Target: `FF_EXVIUS.exe`, the AndApp (DMM/DeNA PC platform) build of *Final
Fantasy Brave Exvius* JP. Everything here is for **interoperability and
preservation** of a client you own: running the game without the discontinued
AndApp desktop client, and pointing it at a community preservation server.

Reference binaries examined:
`FF_EXVIUS.exe`, `AndAppNextHelper.exe` (+ `.bak`), `AndAppNextBootHelper.exe`,
`AndAppNext.exe` (launcher), `roots.pem`, `VersionAndApp.xml`.

---

## 1. Executable overview

| Property | Value |
|---|---|
| Format | PE32 (x86, 32-bit), GUI |
| Engine | cocos2d-x (`libcocos2d.dll`), OpenGL/GLEW |
| Net/TLS | `libcurl.dll` → OpenSSL (`libcrypto-1_1.dll`, and libssl at runtime) |
| Crypto | OpenSSL EVP AES-128 CBC/ECB, MD5; Win32 CryptoAPI (RSA+AES) |
| AndApp SDK | DeNA "AndApp SDK End User Edition" v1.0.4 (`clientId ab6198d`) |

The AndApp integration is the statically-linked DeNA SDK, not game-specific
code. Relevant SDK source tags in the binary: `src/SDKImpl.cpp`,
`src/SessionManager.cpp`, `src/PaymentImpl.cpp`, `src/UserSessionImpl.cpp`,
`platform/win/ipc/src/DeNATCPClientImpl.cpp`, `DeNASessionImpl.cpp`.

---

## 2. cocos2d-x asset encryption (CCZp) — SOLVED

Encrypted assets use the cocos2d-x "CCZp" container. The XXTEA key is installed
by four calls near RVA `0x00750d2c`:

```
setPvrEncryptionKeyPart(0, 0x10872fa8)
setPvrEncryptionKeyPart(1, 0x12eb74c3)
setPvrEncryptionKeyPart(2, 0x4ada7aa3)
setPvrEncryptionKeyPart(3, 0xf4783fd9)
```

The same function immediately decrypts `VersionAndApp.xml`, confirming the key.

**Container layout** (16-byte big-endian header):

```
0  "CCZp"                 signature
4  uint16 compression      (0 = zlib)
6  uint16 version
8  uint32 reserved
12 uint32 len (BE)         uncompressed size   -- ENCRYPTED
16 zlib stream ...                              -- ENCRYPTED
```

**Algorithm**: a 1024-word keystream is expanded in place (from all-zeros) with
an XXTEA schedule (`DELTA = 0x9E3779B9`, 6 rounds) driven by the four key parts;
then payload words from offset 12 are XORed word-for-word with `keystream[i]`
(index-aligned). After decrypt, inflate the zlib stream at offset 16.

Implemented in [`tools/cocos_ccz.py`](../tools/cocos_ccz.py) (decrypt/encrypt/
info, round-trip verified). Result of decrypting the sample:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<application>
    <version name="10.0.0" build="10.0.0" />
</application>
```

(see [`docs/VersionAndApp.decrypted.xml`](VersionAndApp.decrypted.xml)) — this
is game build **10.0.0**.

---

## 3. AndApp helper IPC

### Roles of the three helper executables
* **AndAppNext.exe** — the launcher (Tauri/Rust). Reads a game `manifest.json`
  (`entryPointBaseName`, `versionCode`, `architecture`), writes AppData state
  (`andapp_config`, `andapphelper.pid`, `id_cache.json`, `roots.pem`,
  `boot_settings.json`), and launches the game with `--andapp-payload-id=<id>`.
* **AndAppNextHelper.exe** — the resident helper the SDK talks to. Envoy/gRPC-
  based local proxy; classes `SDKCommand@andapp`, `PortalAppCommand@andapp`,
  transports `PipeServer@dena` and `SocketImpl`/`TCPHandler`.
* **AndAppNextBootHelper.exe** — installer only
  (`AndApp-Portal-Next-win-installer`, `InstallerHelper.log`). **Not needed** to
  launch an already-installed game.

### Transport
The SDK is a TCP client to **127.0.0.1**. It discovers the ports from:

`%APPDATA%\AndApp\AndAppHelper.cfg` (roaming; or `\AndAppDev\AndAppDevHelper.cfg`).
The real file is a **single-line JSON object** (confirmed from a live cfg), with
**dynamic** ports chosen per launch and an optional **named-pipe** command channel:

```json
{"standard.command.pipe.name":"\\\\.\\pipe\\AndAppNextHelper-<40-hex>",
 "standard.tcp.command.ipv4.port":52903,"standard.tcp.command.ipv6.port":0,
 "standard.tcp.notification.ipv4.port":52904,"standard.tcp.notification.ipv6.port":0}
```

`ipv6.port` = 0 means "not listening". The SDK can use the named pipe or the TCP
command channel; our replacement writes JSON with **only** the TCP ports (pipe
name omitted) so the SDK uses TCP.

Path confirmed from both sides: the game reads it via `SHGetFolderPathW` with
`CSIDL_APPDATA` (`0x1a`, **roaming** `%APPDATA%`) at RVA `0x01052b4f`, and the
`AndAppNextHelper` resolves `%APPDATA%` too ("Could not get APPDATA environment
variable"). `CSIDL_LOCAL_APPDATA` (`0x1c`) is used only for bulk `GameData` /
`GameCache`, not the cfg.

Two channels: a **command** socket (request/response) and a **notification**
socket (server push). On failure the SDK logs `Could not connect to
AndAppHelper` / `Send TCP handshake request failed`.

**Observed live session** (from `AndAppHelperDebug.txt`). The helper's core is a
"HeadlessMaster" (HM — matching the game's `SessionManager get HM's response`
strings). It serves two command classes:
* **PortalApp** channel (AndApp itself, runs persistently): `initialize`,
  `get_andapp_client_access_token`, `update_andapp_user_access_token` (hourly
  token refresh) — the account/token plumbing.
* **SDK** channel (the game). A real FFBE launch logs exactly:
  ```
  Receive SDK 'initialize' command
  Receive SDK 'send_analytics_event' command
  Receive SDK 'get_id_token' command
  ```
  i.e. `initialize` → `send_analytics_event` → `get_id_token`. Our replacement
  helper answers all three (and returns billing-unsupported), so this sequence is
  covered once the session handshake (below) is in place. The debug log records
  only command *names*, not the encrypted payloads, so a byte capture (§5) is
  still needed for the handshake framing.

> **Why running `AndAppNextHelper.exe` by hand doesn't create the cfg.** The
> helper is normally spawned by the launcher (`AndAppNext.exe`) with arguments
> (`--appId=`, `--clientId=`, `--pipeConnectionRequest`, …); launched bare it
> doesn't open the listeners or write the cfg. It also embeds an RSA key pair +
> certificates (used for the session handshake / its local TLS) and keeps state
> in `%APPDATA%\AndApp\` as `andapphelper.pid` and `andapphelper_*.prefs`. To get
> a real cfg + capture, run the full AndApp client and launch FFBE through it —
> the cfg then appears under `%APPDATA%\AndApp\`.

> Note: the `\\.\pipe\crashpad_*` named pipe belongs to the bundled Crashpad
> crash handler, **not** the AndApp IPC.

> Note: the `\\.\pipe\crashpad_*` named pipe belongs to the bundled Crashpad
> crash handler, **not** the AndApp IPC.

### Message layer (JSON)
Commands carry an `action` and use DeNA's JSON. Verbs seen in both the SDK and
the helper:

| Verb | Purpose |
|---|---|
| `initialize` | handshake/init; carries `clientId`, `sdk_version`, `payload_id`, `app_version_*` |
| `get_id_token` | returns `id_token` / `public_user_id_token` / `player_id` |
| `is_billing_supported` | boolean |
| `get_products` | store catalog (`items`, `missingIds`) |
| `request_purchase` / `request_purchase_completion` / `get_request_purchase_info` | purchase flow |
| `consume_purchase` | consume |
| `get_purchases` | owned items |
| `send_analytics_event`, `open_app_page` | misc |

Notifications: `paymentSucceed`, `paymentFailed`, `application`/`active`,
`resume`.

### Session crypto (the one open item)
`DeNASessionImpl.cpp` wraps the raw TCP (`DeNATCPClientImpl.cpp`) with a crypto
session: Win32 CryptoAPI "Microsoft Enhanced RSA and AES Cryptographic
Provider", `CryptGenKey`/`CryptExportKey`/`CryptImportKey`, plus OpenSSL
AES-128-CBC. The SDK generates an AES session key and RSA-wraps it during the
handshake. **No RSA public key is embedded in the game**, which means the
helper's key is exchanged at handshake time — so a clean-room helper can present
its own RSA key rather than needing DeNA's private key.

The exact handshake framing could not be fully recovered from the 8 MB Envoy-
based official helper by static analysis alone. The replacement helper isolates
this in a single `SessionCrypto` seam
([`loader/helper_server.cpp`](../loader/helper_server.cpp)); confirm it against
one captured handshake (§5).

---

## 4. Payment stub (no piracy)

The replacement helper answers the billing verbs **safely**:
* `is_billing_supported` → `false` (store UI stays disabled)
* `get_products` / `get_purchases` → empty
* `request_purchase*` / `consume_purchase` → **decline** with an error

It **never** emits `paymentSucceed` and never fabricates entitlements or
receipts.

## 4a. TLS validation & pinning bypass (loader)

FFBE's HTTPS runs through libcurl → OpenSSL. Verification is neutralized in
memory at both layers so a recreated server's self-signed / mismatched cert is
accepted and any certificate pinning is defeated:

* OpenSSL: `X509_verify_cert`→1, `SSL_get_verify_result`→X509_V_OK, and
  `SSL_CTX_set_verify` / `SSL_set_verify` / `SSL_CTX_set_cert_verify_callback`
  made no-ops (leaves the default client `VERIFY_NONE`, and prevents a pinning
  callback from replacing the neutralized default check).
* libcurl (its own hostname match + pin live here, not in OpenSSL):
  `curl_easy_setopt` is filtered — `SSL_VERIFYPEER`/`VERIFYHOST`/`VERIFYSTATUS`
  forced to 0, `PINNEDPUBLICKEY` and `SSL_CTX_FUNCTION` dropped.

libcurl is imported by `libcocos2d.dll`, not by the exe, so the `curl_easy_setopt`
hook is installed across every loaded module (`hooks.cpp:iat_hook_all_modules`),
with a ~10 s retry for lazily-loaded OpenSSL/curl. See `loader/hooks.cpp`
`install_ssl_bypass()`.

### Different stacks per game (and the `[patch]` anchor patcher)

The SSL bypass above targets FFBE's **dynamic OpenSSL + libcurl**. Other AndApp
titles differ, so the bypass is per-stack:

* **FFBE (Windows/AndApp)** — ships `libssl-1_1.dll` / `libcrypto-1_1.dll` /
  `libcurl.dll`; the OpenSSL prologue patches + `curl_easy_setopt` hook cover it.
* **FFRK (Windows)** — ships **no** OpenSSL/curl DLLs: curl is **statically
  linked with the Schannel backend** (`secur32`/`crypt32`, `CALG_SCHANNEL_*`,
  `schannel:` strings) and uses **public-key pinning** (`CURLOPT_PINNEDPUBLICKEY`,
  string `"SSL public key does not match pinned public key"`). None of the
  dynamic hooks apply. Its webview traffic is CEF/BoringSSL (covered by the CEF
  switches); its game traffic needs the pin defeated.

For the static case there's nothing to IAT-hook, so the loader uses a
**string-anchored runtime patcher** (`[patch]` section, `install_anchor_patches`):
it finds the function in the main module that references an anchor string, walks
back to the entry via MSVC's `0xCC` inter-function padding, and forces it to
`return <value>`. For FFRK, `sha256// = 0` targets `Curl_pin_peer_pubkey` (which
references the `sha256//` pin prefix) and makes it return `CURLE_OK` — validated
against `FFRK.exe` at entry RVA `0x19030`. This is version-robust (the anchor is a
stable curl literal, not a byte signature) and needs no exe editing.

The companion **Schannel chain/hostname bypass** is part of `install_ssl_bypass`
(`[ssl] bypass`): it IAT-hooks crypt32 `CertGetCertificateChain` (clears
`TrustStatus.dwErrorStatus` to `CERT_TRUST_NO_ERROR` on the returned chain, every
sub-chain and element) and `CertVerifyCertificateChainPolicy` (forces
`dwError = 0`, returns TRUE). Together with the `[patch]` pin bypass that makes
FFRK's Schannel TLS accept a self-signed / mismatched preservation cert. (These
crypt32 hooks are inert for FFBE, which verifies via OpenSSL.)

### CEF (embedded Chromium) — separate network stack

The game bundles CEF (`libcef.dll`, `chrome_elf.dll`, `cef*.pak`, v8 snapshots,
`icudtl.dat`, `widevinecdmadapter.dll`, `locales/`), so login / portal / store
screens are almost certainly Chromium webviews. **CEF has its own network stack
and TLS (BoringSSL inside `libcef.dll`)** — the libcurl/OpenSSL bypass does not
touch it, and CEF runs networking in child processes that may not load our DLL.

CEF is instead relaxed with Chromium command-line switches
(`loader/cef_hook.cpp`), which must be present before `cef_initialize`:

* The loader inline-patches `GetCommandLineW` (synchronously in `DllMain`, before
  the exe entrypoint) to append:
  `--ignore-certificate-errors`, `--ignore-urlfetcher-cert-requests`,
  `--allow-running-insecure-content`, `--test-type`, optionally
  `--disable-web-security`, and
  `--host-resolver-rules="MAP <host> <ip>,…,EXCLUDE localhost"` built from the
  `[dns]` table. Because CEF reuses `FF_EXVIUS.exe` as its subprocess (no
  separate CEF helper exe ships), every CEF process loads our winmm.dll and gets
  the switches; a `CreateProcessW` hook re-appends them to any `--type=` child as
  a safeguard (dedup-guarded).
* Governed by the ini `[cef]` section; `[dns]` feeds both the winsock redirect
  and the Chromium host-resolver rules.

### Known FFBE JP (AndApp) endpoints

The client's server hostnames (found in the v11 exe), to point at a preservation
server via `[dns]`:

| Host | Role | Path base |
|---|---|---|
| `v53-ios.game.exvius.com`     | game API / session | `/lapis/app` |
| `v53-ios.purchase.exvius.com` | purchase / receipts | `/lapis/app` |
| `purchase.exvius.com`         | purchase (bare host) | |
| `cdn.resource.exvius.com`     | asset CDN (masters, images, …) | `/lapis/resource` |
| `v53.notice.exvius.com`       | notices / news (versioned) | `/content/…` |
| `v24.notice.exvius.com`       | notices / news (older, still referenced) | `/content/…` |
| `notice.exvius.com`           | notices / news (unversioned) | |

Notes:
* `v53` is the API version prefix; it advances with major game versions. The
  Windows/AndApp build uses the **`-ios`** platform suffix on the game/purchase
  hosts (`v53-ios.…`).
* There is **no separate auth/SSO hostname** in the client — the account token is
  obtained through the AndApp helper IPC (`get_id_token`), which the loader
  replaces, so nothing extra needs redirecting for login.
* Browser-opened links (not server traffic, no redirect needed):
  `www.jp.square-enix.com/FFBE/`, `play.google.com/store/…ffbejpn`,
  `sqex.to/qmr`, `sqex-bridge.jp`. The game also has server-side reverify flags (`ForcePurchaseReverify`,
`BUY_COIN_REVERIFY_*`), so spoofing a local success would fail reverification
anyway — declining is both the honest and the robust choice.

---

## 5. Session handshake & framing (recovered from a live capture)

A loopback capture ([`tools/ipc_capture.py`](../tools/ipc_capture.py)) of a real
SDK↔helper session revealed the full protocol, now **implemented** in
`loader/helper_server.cpp` (`SessionCrypto`).

**Framing.** Every message is `[4-byte BE opcode][4-byte BE length][payload]`.

**Handshake** (performed on *both* the command and notification sockets):

| Op | Dir | Payload |
|---|---|---|
| `1` | C→S | Client **RSA-1024 public key**, a CryptoAPI `PUBLICKEYBLOB` (`06 02 00 00` header, `aiKeyAlg=CALG_RSA_KEYX`, magic `RSA1`, `bitlen=0x400`, `exp=0x10001`, 128-byte modulus). |
| `2` | S→C | **AES-256 session key** as a CryptoAPI `SIMPLEBLOB` (`01 02 00 00` header, `aiKeyAlg=CALG_AES_256 0x6610`, key-exchange `CALG_RSA_KEYX`, 128-byte RSA-encrypted key). |
| `3` | C→S | Plaintext JSON `{"clientid":"<appId>"}`. |
| `4` | S→C | Single `0x00` byte (ack). |

**Application data.** Opcode `0x10` both ways; payload is **AES-256-CBC**
(IV = 0, PKCS7 padding, block-aligned, no prepended IV) ciphertext of the JSON
command/response. The command socket is strictly request/response; the
notification socket can be pushed to (we stay idle).

**Why no secret is needed.** The client sends *its* public key and trusts
whatever AES key comes back — the server is never authenticated. So the
replacement mints its own AES-256 key with CryptoAPI ("Microsoft Enhanced RSA and
AES Cryptographic Provider", matching the game) and returns it encrypted to the
client's key. Because the replacement holds the key, it **decrypts and logs every
request** (`andapp_loader.log`), which is how the exact request/response JSON
schema gets refined.

**Capturing more sessions.** `ipc_capture.py` (auto mode) reads the JSON cfg,
proxies in front of the real helper, and dumps both directions; note the
captured `0x10` payloads are encrypted to the *client's* private key, so they
can't be decrypted offline — read the loader's own decrypted log instead, use the
decrypting MITM (`tools/andapp_mitm.py`), or Wireshark for raw framing.

### §5a. Command/response schemas (from a real MITM capture)

Requests are `{"<command>":{...params...}}`; responses are flat objects, with a
top-level `{"error":{"code","message"}}` only on failure. Captured from a live
FFRK session (SDK 1.1.0; FFBE uses 1.0.4 with the same shapes, a subset):

| Command | Request params | Success response |
|---|---|---|
| `initialize` | `api_level, config:{clientId,disableLogging}, sdk_version` | `andapp_client_version`, `andapp_user_id`, `device_account_id`, `is_billing_supported`, **`session`:{`access_token`,`id_token`,`player_id`}** |
| `get_id_token` | `{}` | `id_token` |
| `get_in_app_user_id` | `{}` | `createdAt`, `updatedAt`, `id`, `extras`:{`passphrase`} (mirrors the id_token's `links.app`) |
| `get_products` | `product_ids:[...]` | `items`:[ {clientId, createdAt, description, id, language, prices:[{currency,taxRate,value}], state, title, type, updatedAt} ] |
| `get_purchases` | `{}` | `items:[]` |
| `send_analytics_event` | `action, event, sdk_type, sdk_version, ...` | `{}` |
| `send_message_to_frontend` | `payload:{args,operation}, request_id` | `request_id`, `result:{status:0}` (async result later on the **notification** channel: `{request_id, error:{code,message}}` or data) |

Key correction: **`session` is an object** (`access_token`/`id_token`/`player_id`
are JWTs), not a string. `id_token`/`access_token` are DeNA-signed JWTs the game
forwards to the game server; for preservation the server we redirect to decides
whether to accept them, so opaque tokens suffice client-side.

**`-21005` "Game with same clientId is already connected"** is the real helper's
one-instance-per-clientId guard (seen when launching a second copy). The
replacement helper does not enforce it, so relaunching is fine.

### §5b. Synthesized vs. real credentials (live-server games)

The `session.id_token`/`access_token` and the `get_in_app_user_id` `passphrase`
are **real per-user credentials** the genuine helper fetches from DeNA
(`connect.andapp.jp` / `api.andapp.jp`) for the logged-in AndApp account. What a
replacement can get away with depends on whose backend validates them:

* **Preservation games (own server), e.g. FFBE** — the game's servers
  (`*.exvius.com`) are redirected to your endpoint, which decides what to accept,
  so a synthesized placeholder token/passphrase works.
* **Live-backend games, e.g. FFRK (DeNA Sakasho)** — the game forwards the
  `passphrase` to **live Sakasho**, which rejects a fake value with
  `Sakasho error INVALID_PASSPHRASE` (`AndAppController.cpp`). Only the real
  captured values for *your own account* work, and the JWTs expire (~1 h).
  The loader accepts them via the `[helper]` `access_token` / `passphrase` /
  `app_id` / `andapp_user_id` / `device_account_id` keys (capture with
  `tools/andapp_mitm.py`). A synthesized helper cannot mint valid ones without
  reimplementing the AndApp↔DeNA token flow.

### Launch error codes ("ゲームを開始できませんでした。エラーコード N")

The startup dialog reports the SDK `initialize` failure. Observed:

| Code | When | Meaning |
|---|---|---|
| `-30005` | nothing running | SDK could not **connect to any AndAppHelper** (no listener on the loopback ports / no `AndAppHelper.cfg`). The "Could not connect to AndAppHelper" / "Send TCP handshake request failed" path. |
| `-21015` | AndApp running, exe launched directly | SDK reached the real helper, but `initialize` was **rejected** — the game wasn't launched *by* AndApp, so it had no `--andapp-payload-id` / valid session (the helper validates `'payload_id' must be positive number`). |

Both are computed at runtime (not stored constants). They confirm the stock exe
cannot start without a working AndApp `initialize`. Fixing them is the loader's
job: the helper replacement must (a) listen so connect succeeds (→ `-30005`) and
(b) complete the handshake + return a successful `initialize` (→ `-21015`). The
loader also injects `--andapp-payload-id` (`[launch]` section) since a direct
launch lacks the arg AndApp normally supplies.

---

## 6. `manifest.json` + `signature` file — AndApp integrity (not the game's)

`manifest.json` (v11 sample: `versionCode 124`, `versionName 11.0.0`,
`clientId 5701868182306816`, `entryPointBaseName FF_EXVIUS.exe`) is AndApp's file
inventory. Its `signature[]` array holds one entry per shipped file
(`bin/*.exe`, the root DLLs, and the exe): `{path, signature}`. The sibling
`signature` file is a single value covering `manifest.json` itself.

**Format.** Every signature (per-file and the top-level one) decodes to exactly
**64 bytes** — an **asymmetric signature** (ECDSA-P256 `r‖s`, or Ed25519), made
with DeNA's private key. Ruled out by testing against `zlib1.dll`: it is **not**
SHA-512/384/SHA3-512/BLAKE2b, and **not** HMAC-SHA512 over the file, path+file,
or the file's hash, across the obvious embedded keys (clientId, versionName,
"andapp", …). Being asymmetric, these **cannot be regenerated** without DeNA's
private key.

**Who verifies it.** Only the AndApp launcher / BootHelper (install + launch
integrity). The **game does not**:
* `FF_EXVIUS.exe` imports from `libcrypto-1_1.dll` are symmetric-only
  (AES-128 CBC/ECB, MD5) — **no** `ECDSA_verify` / `EVP_DigestVerify` / `EC_KEY`
  / `d2i_PUBKEY`, and no `CryptVerifySignature` from advapi32.
* The only game reference to `manifest.json` is in `SdkUtils.cpp`, which parses
  `versionCode` / `versionName` / `platform` / `architecture` /
  `entryPointBaseName` to populate the SDK's `initialize` payload — it never
  reads the `signature` array.

**Consequence for preservation.** Launched directly (our winmm loader replacing
AndApp), **nothing verifies these signatures**, so patched files — a modified
exe, patched OpenSSL DLLs, our `winmm.dll` — run fine. **No in-game
"ignore-signature" hook is needed.** (An integrity bypass would only matter if
you launched *through* AndApp, which this project avoids.)

**Tooling.** None is shipped: because the signatures are asymmetric and can't be
regenerated without DeNA's private key, and because the game never verifies them,
there is nothing to generate. If you ever need a manifest for your own tooling,
copy the shipped one and edit the version fields — the `signature` array is inert
for a direct (non-AndApp) launch.

> Versions: the CCZ key is **unchanged across v10 and v11** — the same four key
> parts decrypt both `VersionAndApp.xml` files (v10 → 10.0.0, v11 → 11.0.0), and
> the v11 `FF_EXVIUS.exe` sets them at RVA `0x00759022`. The `manifest.json`
> sample is v11 (`versionCode 124`). `clientId 5701868182306816` there is the
> AndApp *application* id, distinct from the SDK build id `ab6198d`.

---

## 7. FFRK Android — Mobage-direct login (the AndApp bypass)

The PC FFRK build authenticates in two stages: the AndApp SDK/helper hands it
real DeNA credentials (`id_token`/`access_token` JWTs + `passphrase`), then the
game calls `send_message_to_frontend{kind:login, provider:mobage,
operation:idp_federation}` — i.e. AndApp is an **identity provider federated
onto an underlying Mobage account**. Everything after that (Sakasho at
`dff.sp.mbga.jp`/`sp.mbga.jp`) is pure Mobage.

**Can AndApp be bypassed?** Two different things:

* **Forge** the AndApp token → **no**. `id_token`/`access_token` are JWTs signed
  by `connect.andapp.jp` (`jku` in the header) and validated **server-side** by
  Mobage during `idp_federation`; a synthesized value dies there, and the
  captured real ones expire (~1 h). A replacement helper cannot mint them.
* **Replace** the whole AndApp leg with a **native Mobage login** → **yes, in
  principle**. The FFRK **Android** client never touches AndApp; it logs into
  the same Mobage account directly (Mobage/ngCore OAuth 1.0a, 3-legged, via a
  `connect.mobage.jp` login webview). That login yields the same account's
  Sakasho session + `passphrase` the PC build ends up forwarding. So reproducing
  the Android login removes the AndApp dependency entirely — no helper, no
  expiring DeNA JWTs.

**Why we capture rather than guess.** Three unknowns block writing the login
blind: the Mobage **consumer key/secret** baked into the client, the exact
**OAuth endpoints**, and whether login requires the interactive **webview**
(username/password → `oauth_verifier`) or can be scripted. A live MITM of the
Android client answers all three and yields a reference transcript.

**Procedure** (own account, own device, live servers, preservation): mitmproxy
with its CA trusted as a **system** CA (user-store CAs are ignored on Android
7+), pinning defeated by `tools/frida_unpin.js` (covers Java `SSLContext`,
OkHttp `CertificatePinner`, Conscrypt `TrustManagerImpl`, WebView SSL errors,
and the native BoringSSL verify callbacks in the ngCore `.so`), and
`tools/mobage_capture.py` as a mitmproxy addon to isolate the `*.mbga.jp` /
`connect.mobage.jp` / Sakasho flows and extract `oauth_*` + `passphrase` +
session identity. See `tools/README.md` → "Android MITM capture".

**Expected outcome.** The Android transcript's `passphrase` + account identity
should match what `andapp_mitm.py` captured from the helper on PC (§5a/§5b). If
so, a native-Mobage login (future `tools/mobage_login.py`, fed the
consumer key/secret + endpoints the capture reveals) can produce a Sakasho
session for the PC build without AndApp in the loop at all.

### §7a. Observed FFRK Android → Mobage/Sakasho login (decoded capture)

A live MITM of the Android client (`jp.mbga.a12019103.lite`, SP SDK `1.15.0`,
`game_id 12019103`) captured the complete session bootstrap. It is **not** the
classic 3-legged webform every call — it is Mobage's **SP SDK** protocol: a
WebView does the one-time Mobage-ID login, after which the native SDK holds a
persistent user access token and signs API calls with OAuth 1.0a HMAC-SHA1.
All values below are placeholders; the real ones are per-user secrets.

**Phase 1 — SDK auth check (WebView, `ssl.sp.mbga.jp`).**
`GET /_sdk_chk_and_auth?...&oauth_consumer_key=sdk_app_id:12019103&
oauth_signature_method=HMAC-SHA1&oauth_token=&oauth_version=1.0&on_launch=&
on_resume=` — **2-legged** (empty `oauth_token`, signing key
`<consumer_secret>&`). When the device already has a Mobage session the HTML
response redirects to `ngcore:///session_callback#...` whose `credentialsInfo`
is URL-encoded JSON:
```
{"error":null,"credentials":{
   "oauth_token":"sdk_client_id:<40-hex>",
   "oauth_token_secret":"<32-char>"}}
```
plus `logged_in=1`, `user_id=<digits>`, `user_id_hash=<40-hex>`. These
**credentials are the persistent per-user access token** — the Mobage analogue
of AndApp's `passphrase`. (Pre-login, the same endpoint returns
`...&please_login=1` and the `_lg` login page instead.)

**Phase 2 — Sakasho temporary credential (`dff.sp.mbga.jp`).**
`POST /dff/_api_get_temporary_credential` (auth by the `http_session_sid`
cookie, `android-async-http` UA) → `{"success":true,
"oauth_token":"temporary_credential:<40-hex>","csrf_token":"<...>"}`.

**Phase 3 — authorize the temp credential (`ssl.sp.mbga-platform.jp`).**
`POST /social/api/jsonrpc/v2.03`, `{"jsonrpc":"2.0",
"method":"accesstoken.authorizeToken","params":{"token":"temporary_credential:<40-hex>"}}`.
**3-legged** OAuth in the `Authorization: OAuth ...` header: `oauth_consumer_key=
sdk_app_id:12019103`, `oauth_token=sdk_client_id:<40-hex>` (from phase 1),
`oauth_body_hash=base64(sha1(body))`, signing key
`<consumer_secret>&<oauth_token_secret>`, plus `xoauth_requestor_id=<user_id>`.
→ `{"result":{"verifier":"<64-hex>","token":"temporary_credential:<40-hex>"}}`.
(The SDK also calls `remotenotification.updateToken` here for FCM — not needed
for login.)

**Phase 4 — create the Sakasho game session (`dff.sp.mbga.jp`).**
`POST /dff/_api_create_session`, form body
`verifier=<64-hex>&oauth_token=temporary_credential:<40-hex>` → the player
profile `{"success":true,"nickname":...,"id":"<user_id>",...}` and
`Set-Cookie: http_session_sid=<new>` — the authenticated **game session**. The
rest of the client (`/dff/splash`, `/dff/`, `/dff/tutorial/`) rides that cookie.

**Consequences.**
* The whole flow is reproducible headlessly with: the **consumer secret** for
  `sdk_app_id:12019103` (baked into the native lib — not extracted here), the
  user's phase-1 `oauth_token`/`oauth_token_secret` (captured once via the
  WebView login), and a starting `http_session_sid`. `tools/mobage_login.py` is
  the signer + phase-2→4 driver skeleton for exactly this.
* Cert pinning mostly affects the WebView login *form*; the native
  `dff.sp.mbga.jp` / `mbga-platform.jp` calls were captured cleanly, so the
  important schema is complete. An iOS capture is unnecessary — same endpoints.
* This mirrors, on the Mobage side, what the PC build reaches via AndApp
  `idp_federation`: both terminate in a `dff.sp.mbga.jp` Sakasho session for the
  same account. Capturing the Android user token is the no-AndApp path to it.
