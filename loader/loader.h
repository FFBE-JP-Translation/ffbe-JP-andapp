// loader.h - shared declarations for the AndApp preservation loader (winmm proxy)
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <cstdint>

namespace loader {

// ---- logging -----------------------------------------------------------------
void log_init(const std::wstring& path, bool enabled);
void logf(const char* fmt, ...);

// ---- config (.ini) -----------------------------------------------------------
struct Config {
    bool   log_enabled          = true;
    std::wstring log_path;                       // default: <dll dir>\andapp_loader.log

    // AndAppHelper replacement (TCP)
    bool   helper_enabled       = true;
    int    command_port         = 51100;         // standard.tcp.command.ipv4.port
    int    notification_port    = 51101;         // standard.tcp.notification.ipv4.port
    bool   write_cfg            = true;          // write the AndAppHelper.cfg
    bool   cfg_in_gamedir       = true;          // keep cfg in the game folder and
                                                 // redirect the game's read there,
                                                 // so %APPDATA%\AndApp is untouched
    std::string player_id       = "1000000000000000";
    std::string id_token;                        // optional pre-baked token; else synthesized

    // Real credential values for games that authenticate against LIVE DeNA infra
    // (e.g. FFRK/Sakasho), captured from your own account via the MITM. When set,
    // the helper returns them verbatim instead of synthesized placeholders.
    // Preservation games (own redirected server) don't need these.
    std::string access_token;                    // session.access_token
    std::string passphrase;                      // get_in_app_user_id extras.passphrase
    std::string app_id;                          // get_in_app_user_id id (links.app.id)
    std::string andapp_user_id;
    std::string device_account_id;
    std::string andapp_client_version = "4.0.4";

    // SSL / cert verification bypass (runtime, in-memory)
    bool   ssl_bypass           = true;

    // Mutex neutralization (launch without the official AndApp installed)
    bool   mutex_fix            = true;

    // Standalone launch: AndApp normally passes --andapp-payload-id=<n> on the
    // command line. Launched directly, the SDK has none and initialize fails
    // (error -21015). Inject one so the SDK has a valid positive payload id.
    bool   inject_payload_id    = true;
    std::string andapp_payload_id = "1";

    // CEF (embedded Chromium) command-line injection for webview screens
    bool   cef_enabled          = true;   // inject switches into libcef
    bool   cef_ignore_cert      = true;   // --ignore-certificate-errors etc.
    bool   cef_disable_websec   = false;  // --disable-web-security
    bool   cef_host_rules       = true;   // build --host-resolver-rules from [dns]
    std::string cef_extra_switches;       // freeform, appended verbatim

    // DNS redirects: hostname (lower-case) -> IPv4 string
    std::map<std::string, std::string> dns;
};

Config& config();
bool load_config(const std::wstring& ini_path);
std::wstring dll_directory();

// True when this process is a CEF/Chromium child (command line has --type=),
// e.g. renderer/gpu/utility/network. Such children load our winmm.dll too (CEF
// reuses the game exe), but must NOT start the helper server or write the cfg.
bool is_cef_child();

// ---- hook installers ---------------------------------------------------------
// IAT hook helper: replace every import of (module, func) in the main image.
bool iat_hook(const char* import_dll, const char* func, void* replacement,
              void** original);

// IAT hook across every loaded module (returns how many modules were patched).
int iat_hook_all_modules(const char* import_dll, const char* func,
                         void* replacement, void** original);

// Force a function's prologue to `mov eax, ret_val; ret` (cdecl no-op).
bool force_return(void* func, uint32_t ret_val);

void install_dns_hooks();     // getaddrinfo / GetAddrInfoW / gethostbyname
void install_mutex_hooks();   // CreateMutexW / CreateMutexExW
void install_ssl_bypass();    // openssl X509_verify_cert / SSL_get_verify_result / libcurl
void install_cfg_redirect();  // CreateFileW: redirect AndAppHelper.cfg reads to game dir

// Absolute path where the AndAppHelper.cfg lives (game dir if cfg_in_gamedir,
// else %APPDATA%\AndApp\AndAppHelper.cfg). Shared by the writer and the redirect.
std::wstring cfg_target_path();

// Command-line injection: --andapp-payload-id (standalone launch) + CEF switches.
// Must run BEFORE cef_initialize / SDK init, so it is installed synchronously in
// DllMain via an inline hook on GetCommandLineW.
void install_cmdline_hook();       // inline-hook GetCommandLineW to append args
void install_process_hooks();      // CreateProcessW: propagate switches to CEF children
std::string cef_switch_string();   // the CEF switches we inject (for logging/reuse)

// ---- AndApp helper TCP server ------------------------------------------------
void start_helper_server();   // spawns listener threads; writes AndAppHelper.cfg

}  // namespace loader
