// winmm.cpp - DLL entry point + transparent winmm.dll proxy.
//
// Place this compiled winmm.dll next to FF_EXVIUS.exe. Because the exe imports
// winmm by name from its own directory first, our DLL loads instead of the
// system one; we immediately load the real winmm from the system directory and
// forward every call to it via naked tail-jump stubs, so audio/timers keep
// working. On load we also start the AndApp helper replacement and install the
// DNS / mutex / SSL hooks per andapp_loader.ini.
//
// 32-bit build (the game is PE32 / x86). Build with MSVC or MinGW; see build.bat.

#include "loader.h"

using namespace loader;

// ---- real winmm function pointer table --------------------------------------
extern "C" {
#define WINMM_FN(name) void* g_real_##name = nullptr;
#include "winmm_exports.inc"
#undef WINMM_FN
}

static void load_real_winmm() {
    wchar_t sys[MAX_PATH];
    // On WOW64 this returns SysWOW64, i.e. the 32-bit winmm - exactly what we need.
    GetSystemDirectoryW(sys, MAX_PATH);
    std::wstring path = std::wstring(sys) + L"\\winmm.dll";
    HMODULE h = LoadLibraryW(path.c_str());
    if (!h) { logf("FATAL: cannot load real winmm from %ls", path.c_str()); return; }
#define WINMM_FN(name) g_real_##name = (void*)GetProcAddress(h, #name);
#include "winmm_exports.inc"
#undef WINMM_FN
    logf("real winmm loaded from %ls", path.c_str());
}

// ---- naked tail-jump stubs (one shape fits all calling conventions) ----------
// Each exported winmm_<name> jumps to g_real_<name>. If the real pointer is null
// (function absent on this OS) we just `ret` to avoid a crash.
#if defined(_MSC_VER)
#define WINMM_FN(name)                                   \
    extern "C" __declspec(naked) void name() {           \
        __asm { mov eax, g_real_##name }                 \
        __asm { test eax, eax }                          \
        __asm { jz  _ret_##name }                        \
        __asm { jmp eax }                                \
        __asm { _ret_##name: ret }                       \
    }
#include "winmm_exports.inc"
#undef WINMM_FN
#elif defined(__GNUC__)
#define WINMM_FN(name)                                          \
    extern "C" __attribute__((naked)) void name() {             \
        __asm__ __volatile__(                                   \
            "movl _g_real_" #name ", %eax\n\t"                  \
            "testl %eax, %eax\n\t"                              \
            "jz 1f\n\t"                                         \
            "jmp *%eax\n\t"                                     \
            "1: ret\n\t");                                      \
    }
#include "winmm_exports.inc"
#undef WINMM_FN
#endif

// ---- heavier initialization on a worker thread (off the loader lock) ---------
static DWORD WINAPI init_thread(LPVOID) {
    // SSL bypass is wanted in every process (CEF's network child does TLS too).
    if (config().ssl_bypass)  install_ssl_bypass();
    install_dns_hooks();        // no-op if the ini defines no redirects

    if (is_cef_child()) {
        // A CEF renderer/gpu/utility/network subprocess: it already inherited the
        // Chromium switches on its command line. It must NOT run the helper
        // server (would fight the main process for the loopback ports) or write
        // the cfg / touch the game mutex.
        logf("CEF child process (--type= present) - skipping helper/mutex/cfg");
        return 0;
    }
    logf("main process (no --type=) - starting helper");

    if (config().mutex_fix)   install_mutex_hooks();
    install_process_hooks();    // propagate CEF switches to child processes
    install_cfg_redirect();     // redirect the game's cfg read to the game folder
    install_anchor_patches();   // string-anchored force-return patches (pin bypass)
    if (config().helper_enabled) start_helper_server();

    logf("initialization complete");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        load_real_winmm();

        // Config + CEF command-line injection must happen BEFORE the game calls
        // cef_initialize, i.e. synchronously here (the exe entrypoint runs after
        // all DllMains). These are lightweight: a file read and a prologue patch.
        std::wstring ini = dll_directory() + L"\\andapp_loader.ini";
        load_config(ini);
        log_init(config().log_path.empty()
                     ? dll_directory() + L"\\andapp_loader.log"
                     : config().log_path,
                 config().log_enabled);
        logf("=== AndApp preservation loader (winmm proxy) ===");
        logf("ini: %ls", ini.c_str());
        install_cmdline_hook();

        // Everything else can run off the loader lock.
        CloseHandle(CreateThread(nullptr, 0, init_thread, nullptr, 0, nullptr));
    }
    return TRUE;
}
