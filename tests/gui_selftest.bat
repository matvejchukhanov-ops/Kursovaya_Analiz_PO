@echo off
rem Самотест окна. Использование: tests\gui_selftest.bat путь_к_Whiter.a.rar
rem Сборка и журнал во временной папке, рабочие файлы проекта не меняются
setlocal
set OUT=%TEMP%\exeias_selftest
if not exist "%OUT%" mkdir "%OUT%"
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%OUT%"
cl /nologo /utf-8 /EHsc /O2 /W3 /sdl /permissive- /std:c++20 /DEXEIAS_SELFTEST "%~dp0..\ExeIAS\gui\gui.cpp" "%~dp0..\ExeIAS\common.cpp" "%~dp0..\ExeIAS\disasm.cpp" "%~dp0..\ExeIAS\economics.cpp" "%~dp0..\ExeIAS\fsanalysis.cpp" "%~dp0..\ExeIAS\input.cpp" "%~dp0..\ExeIAS\language.cpp" "%~dp0..\ExeIAS\pe.cpp" "%~dp0..\ExeIAS\pipeline.cpp" "%~dp0..\ExeIAS\report.cpp" "%~dp0..\ExeIAS\signatures.cpp" /Fe:gui_selftest.exe /link /SUBSYSTEM:WINDOWS || exit /b 100
"%OUT%\gui_selftest.exe" "%OUT%\selftest.log" %1 "%OUT%\tmp"
set RESULT=%ERRORLEVEL%
type "%OUT%\selftest.log"
exit /b %RESULT%
