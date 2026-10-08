// util.cpp - logging, .ini parsing, config, path helpers.
#include "loader.h"
#include <cstdio>
#include <cstdarg>
#include <mutex>
#include <string>
#include <algorithm>

namespace loader {

static std::wstring g_log_path;
static bool g_log_enabled = true;
static std::mutex g_log_mtx;

bool is_cef_child() {
    LPCWSTR cl = GetCommandLineW();
    return cl && wcsstr(cl, L"--type=") != nullptr;
}

std::wstring dll_directory() {
    wchar_t buf[MAX_PATH]{};
    HMODULE h = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)&dll_directory, &h);
    GetModuleFileNameW(h, buf, MAX_PATH);
    std::wstring p(buf);
    size_t slash = p.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : p.substr(0, slash);
}

void log_init(const std::wstring& path, bool enabled) {
    g_log_path = path;
    g_log_enabled = enabled;
}

void logf(const char* fmt, ...) {
    if (!g_log_enabled || g_log_path.empty()) return;
    char msg[2048];
    va_list ap; va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    SYSTEMTIME st; GetLocalTime(&st);
    char line[2200];
    snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d] %s\r\n",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    std::lock_guard<std::mutex> lk(g_log_mtx);
    FILE* f = _wfopen(g_log_path.c_str(), L"ab");
    if (f) { fputs(line, f); fclose(f); }
    OutputDebugStringA(line);
}

// ---- config ------------------------------------------------------------------
static Config g_cfg;
Config& config() { return g_cfg; }

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}
static bool truthy(const std::string& v) {
    std::string s = lower(trim(v));
    return s == "1" || s == "true" || s == "yes" || s == "on";
}
static std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n ? n - 1 : 0, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

bool load_config(const std::wstring& ini_path) {
    FILE* in = _wfopen(ini_path.c_str(), L"rb");
    if (!in) return false;  // defaults are fine if there's no ini
    char raw[1024];
    std::string section;
    while (fgets(raw, sizeof(raw), in)) {
        std::string t = trim(raw);
        if (t.empty() || t[0] == '#' || t[0] == ';') continue;
        if (t[0] == '[') { section = lower(trim(t.substr(1, t.find(']') - 1))); continue; }
        size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string rawkey = trim(t.substr(0, eq));  // case preserved (anchors)
        std::string key = lower(rawkey);
        std::string val = t.substr(eq + 1);
        // Strip an inline comment: a ';' or '#' preceded by whitespace. (Our
        // values never contain those chars unescaped, so this is safe.)
        for (size_t i = 0; i < val.size(); ++i) {
            if ((val[i] == ';' || val[i] == '#') &&
                (i == 0 || val[i - 1] == ' ' || val[i - 1] == '\t')) {
                val = val.substr(0, i);
                break;
            }
        }
        val = trim(val);

        if (section == "loader") {
            if (key == "log")        g_cfg.log_enabled = truthy(val);
            else if (key == "logpath") g_cfg.log_path = widen(val);
        } else if (section == "helper") {
            if (key == "enabled")            g_cfg.helper_enabled = truthy(val);
            else if (key == "command_port")  g_cfg.command_port = atoi(val.c_str());
            else if (key == "notification_port") g_cfg.notification_port = atoi(val.c_str());
            else if (key == "write_cfg")     g_cfg.write_cfg = truthy(val);
            else if (key == "cfg_in_gamedir") g_cfg.cfg_in_gamedir = truthy(val);
            else if (key == "player_id")     g_cfg.player_id = val;
            else if (key == "id_token")      g_cfg.id_token = val;
            else if (key == "access_token")  g_cfg.access_token = val;
            else if (key == "passphrase")    g_cfg.passphrase = val;
            else if (key == "app_id")        g_cfg.app_id = val;
            else if (key == "andapp_user_id") g_cfg.andapp_user_id = val;
            else if (key == "device_account_id") g_cfg.device_account_id = val;
            else if (key == "andapp_client_version") g_cfg.andapp_client_version = val;
        } else if (section == "ssl") {
            if (key == "bypass") g_cfg.ssl_bypass = truthy(val);
        } else if (section == "mutex") {
            if (key == "fix") g_cfg.mutex_fix = truthy(val);
        } else if (section == "launch") {
            if (key == "inject_payload_id")   g_cfg.inject_payload_id = truthy(val);
            else if (key == "andapp_payload_id") g_cfg.andapp_payload_id = val;
        } else if (section == "cef") {
            if (key == "enabled")                        g_cfg.cef_enabled = truthy(val);
            else if (key == "ignore_certificate_errors") g_cfg.cef_ignore_cert = truthy(val);
            else if (key == "disable_web_security")      g_cfg.cef_disable_websec = truthy(val);
            else if (key == "host_resolver_rules")       g_cfg.cef_host_rules = truthy(val);
            else if (key == "extra_switches")            g_cfg.cef_extra_switches = val;
        } else if (section == "patch") {
            // anchor string (case-preserved) = return value (dec or 0x hex)
            uint32_t rv = (uint32_t)strtoul(val.c_str(), nullptr, 0);
            g_cfg.patches.emplace_back(rawkey, rv);
        } else if (section == "dns") {
            // key = hostname, val = ipv4  (e.g. api.example.jp = 127.0.0.1)
            g_cfg.dns[lower(key)] = val;
        }
    }
    fclose(in);
    return true;
}

}  // namespace loader
