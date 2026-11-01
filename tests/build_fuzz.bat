@echo off
rem Build the ExeIAS fuzz harness under %TEMP%\exeias_fuzz (never in build\).
rem Usage: tests\build_fuzz.bat [release^|asan^|debug^|all]   (default: all)
rem The harness links every top-level ExeIAS\*.cpp except main.cpp and console.cpp.
setlocal enabledelayedexpansion
set MODE=%~1
if "%MODE%"=="" set MODE=all
set ROOT=%~dp0..\ExeIAS
set OUT=%TEMP%\exeias_fuzz
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1

set SOURCES="%~dp0fuzz_analysis.cpp"
for %%f in ("%ROOT%\*.cpp") do (
    if /i not "%%~nxf"=="main.cpp" if /i not "%%~nxf"=="console.cpp" set SOURCES=!SOURCES! "%%~ff"
)
set COMMON=/nologo /utf-8 /EHsc /W3 /permissive- /std:c++20 /Zi /I"%ROOT%"

if /i "%MODE%"=="release" goto release
if /i "%MODE%"=="asan" goto asan
if /i "%MODE%"=="debug" goto debug

:release
if not exist "%OUT%\release" mkdir "%OUT%\release"
pushd "%OUT%\release"
rem Same optimisation flags as build.bat plus debug info for readable stacks
cl %COMMON% /O2 /sdl %SOURCES% /Fe:fuzz_analysis.exe /link /DEBUG /OPT:REF || (popd & exit /b 1)
popd
if /i "%MODE%"=="release" exit /b 0

:asan
if not exist "%OUT%\asan" mkdir "%OUT%\asan"
pushd "%OUT%\asan"
cl %COMMON% /O1 /sdl /fsanitize=address %SOURCES% /Fe:fuzz_analysis.exe /link /DEBUG || (popd & exit /b 1)
rem The ASan runtime DLL must be next to the executable
for /f "delims=" %%d in ('where clang_rt.asan_dynamic-x86_64.dll') do copy /y "%%d" . >nul
popd
if /i "%MODE%"=="asan" exit /b 0

:debug
if not exist "%OUT%\debug" mkdir "%OUT%\debug"
pushd "%OUT%\debug"
rem Debug CRT: checked iterators and operator[], heap checks, /RTC1
cl %COMMON% /Od /MTd /RTC1 /D_ITERATOR_DEBUG_LEVEL=2 %SOURCES% /Fe:fuzz_analysis.exe /link /DEBUG || (popd & exit /b 1)
popd
exit /b 0
