# AndApp preservation loader (`winmm.dll`)

A single drop-in `winmm.dll`, placed next to `FF_EXVIUS.exe`, that lets the
FFBE AndApp client run for **preservation** without the discontinued AndApp
desktop client — no extra programs to launch. It:

1. **Proxies `winmm.dll`** transparently to the real system winmm (audio/timers
   keep working), and uses `DllMain` as an injection point.
2. **Hosts the AndApp helper** on loopback TCP with the real RSA/AES handshake
   and JSON command protocol — **payments disabled** (never fakes a purchase).
   By default it keeps `AndAppHelper.cfg` **in the game folder** and hooks
   `CreateFileW` to redirect the game's read there, so the real AndApp's
   `%APPDATA%\AndApp\AndAppHelper.cfg` is never touched (`[helper] cfg_in_gamedir`;
   set false to use the real `%APPDATA%` location).
3. **Redirects game-server hostnames** to your preservation server, via a
   `[dns]` table in `andapp_loader.ini` (hooks `getaddrinfo`/`GetAddrInfoW`).
4. **Accepts any TLS certificate and defeats certificate pinning** so a
   self-signed / renamed preservation server works. In memory it forces
   `X509_verify_cert`→ok and `SSL_get_verify_result`→ok, no-ops
   `SSL_CTX_set_verify` / `SSL_set_verify` / `SSL_CTX_set_cert_verify_callback`
   (so the app can't install a pinning callback), and filters
   `curl_easy_setopt` to force `SSL_VERIFYPEER/HOST/STATUS`→0 and drop
   `PINNEDPUBLICKEY` / `SSL_CTX_FUNCTION`. Because libcurl is called by
   `libcocos2d.dll` (not the exe), the curl hook is applied across **all loaded
   modules**, with a short retry to catch lazily-loaded OpenSSL/curl. It also
   installs a **Schannel/crypt32** chain bypass (`CertGetCertificateChain` +
   `CertVerifyCertificateChainPolicy`) for Windows-native-TLS games (e.g. FFRK).
   Only this local client process is affected.
   - For **statically-linked public-key pinning** (no DLL to hook), the `[patch]`
     ini section force-returns the pin function located by a string anchor
     (e.g. FFRK: `sha256// = 0` → `Curl_pin_peer_pubkey` returns `CURLE_OK`).
5. **Neutralizes the single-instance mutex** so the game launches standalone.
6. **Relaxes the embedded Chromium (CEF)** used for login/portal/store webviews.
   CEF has its own network stack + TLS (BoringSSL), separate from libcurl/OpenSSL,
   so it needs Chromium switches: the loader inline-hooks `GetCommandLineW` (before
   `cef_initialize`) to append `--ignore-certificate-errors` (+ related) and
   `--host-resolver-rules="MAP host ip,…"` built from the `[dns]` table, and also
   appends them to CEF child processes via `CreateProcessW`. Configured under
   `[cef]`.

Everything is gated by `andapp_loader.ini`; delete or disable a section to turn
a feature off.

## Build (must be 32-bit — the game is x86)

**MSVC** — from an *x86 Native Tools Command Prompt*:
```
build.bat
```
**MinGW** (`i686-w64-mingw32-g++` on PATH):
```
build.bat mingw
```
**CMake**:
```
cmake -B build -A Win32           REM MSVC
cmake --build build --config Release
```
The MinGW target links the runtime statically, so the result imports only
`KERNEL32` / `msvcrt` / `WS2_32` — a clean drop-in.

## Install

Copy next to `FF_EXVIUS.exe`:
```
FF_EXVIUS.exe
winmm.dll            <- this loader
andapp_loader.ini    <- edit ports + [dns] redirects
```
Run the game normally. Check `andapp_loader.log` (same folder) for what the
loader did: real-winmm load, hooks installed, helper listening, DNS redirects,
SSL patches, and raw command bytes.

## Files
| File | Role |
|---|---|
| `winmm.cpp`, `winmm_exports.inc`, `winmm.def` | winmm proxy + DllMain |
| `util.cpp` | logging, `.ini` parsing, config |
| `hooks.cpp` | IAT hook, prologue patch, DNS / mutex / SSL hooks |
| `cef_hook.cpp` | CEF command-line injection (cert-ignore + host-resolver-rules) |
| `helper_server.cpp` | AndAppHelper TCP replacement (payments stubbed) |
| `andapp_loader.ini` | configuration |

## Status
The SDK↔helper **session handshake is implemented** (`SessionCrypto` in
`helper_server.cpp`): the recovered 8-byte framing, the CryptoAPI RSA/AES key
exchange (client sends its RSA public key, we return a minted AES-256 key), and
AES-256-CBC JSON commands — see
[`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md) §5. DNS, mutex,
SSL/pinning, CEF, and the payment stub are complete.

Remaining: the **response JSON schema** is a best effort. Because the helper holds
the session key it logs every *decrypted* request to `andapp_loader.log`, so run
the game once and read that log to refine the exact fields each verb must return.
