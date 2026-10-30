@echo off
rem Build ExeIAS.exe (MSVC) from all modules. Usage after build: build\ExeIAS.exe path\to\file.exe
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist "%~dp0build" mkdir "%~dp0build"
cd /d "%~dp0build"
cl /nologo /utf-8 /EHsc /O2 /W3 /sdl /permissive- /std:c++20 ..\ExeIAS\*.cpp /Fe:ExeIAS.exe || exit /b 1
del *.obj >nul 2>&1
