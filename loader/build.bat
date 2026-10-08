@echo off
REM Build the 32-bit winmm.dll preservation loader.
REM The game is PE32 (x86), so the DLL MUST be 32-bit.
REM
REM Option A: MSVC (open an "x86 Native Tools Command Prompt for VS", then run this)
REM Option B: MinGW (i686-w64-mingw32-g++ on PATH); pass "mingw" as arg 1.

if /I "%1"=="mingw" goto mingw

:msvc
echo === Building with MSVC (x86) ===
cl /nologo /LD /O2 /EHsc /DWIN32 /D_WINDOWS ^
   winmm.cpp util.cpp hooks.cpp helper_server.cpp cef_hook.cpp ^
   /Fe:winmm.dll /link /DEF:winmm.def ws2_32.lib user32.lib advapi32.lib shell32.lib
if errorlevel 1 exit /b 1
echo Built winmm.dll
goto done

:mingw
echo === Building with MinGW (i686) ===
i686-w64-mingw32-g++ -shared -O2 -static -std=c++17 -DWIN32 ^
   winmm.cpp util.cpp hooks.cpp helper_server.cpp cef_hook.cpp winmm.def ^
   -o winmm.dll -lws2_32 -luser32 -ladvapi32 -lshell32 -Wl,--enable-stdcall-fixup
if errorlevel 1 exit /b 1
echo Built winmm.dll
goto done

:done
echo.
echo Place winmm.dll + andapp_loader.ini next to FF_EXVIUS.exe.

pause