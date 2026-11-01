@echo off
rem Build ExeIAS.exe (console) and ExeIAS_GUI.exe (window) with MSVC. Usage after build: build\ExeIAS_GUI.exe
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist "%~dp0build" mkdir "%~dp0build"
cd /d "%~dp0build"
cl /nologo /utf-8 /EHsc /O2 /W3 /sdl /permissive- /std:c++20 ..\ExeIAS\*.cpp /Fe:ExeIAS.exe || exit /b 1
del main.obj console.obj >nul 2>&1
cl /nologo /utf-8 /EHsc /O2 /W3 /sdl /permissive- /std:c++20 ..\ExeIAS\gui\gui.cpp common.obj disasm.obj economics.obj fsanalysis.obj input.obj language.obj pe.obj pipeline.obj report.obj signatures.obj /Fe:ExeIAS_GUI.exe /link /SUBSYSTEM:WINDOWS || exit /b 1
del *.obj >nul 2>&1
