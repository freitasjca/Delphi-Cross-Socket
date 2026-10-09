@echo off
setlocal enabledelayedexpansion
REM ===========================================================================
REM  build-dcc.bat - build and run CnPackHashTests with dcc64 (Windows/Delphi).
REM
REM  Usage:   tests\CnPackHashTests\build-dcc.bat
REM  Exit:    0 = all checks passed, N = N failed, 90 = build failed.
REM
REM  -B on purpose: a .dcu built from the OLD CnPack is not invalidated by
REM  the new source unless timestamps say so, and a stale unit would make a
REM  before/after comparison meaningless.
REM
REM  No parenthesised blocks: Delphi lives under "Program Files (x86)", and
REM  cmd matches parentheses before expanding variables.
REM ===========================================================================

cd /d "%~dp0"
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"

set "DCC="
if not "%DELPHI_ROOT%"=="" if exist "%DELPHI_ROOT%\bin\dcc64.exe" set "DCC=%DELPHI_ROOT%\bin\dcc64.exe"
if not "%BDS%"=="" if exist "%BDS%\bin\dcc64.exe" set "DCC=%BDS%\bin\dcc64.exe"
if not defined DCC for /f "delims=" %%I in ('where dcc64.exe 2^>nul') do if not defined DCC set "DCC=%%I"
if not defined DCC goto :no_dcc

set "UP=!ROOT!\Net;!ROOT!\Utils;!ROOT!\CnPack\Common;!ROOT!\CnPack\Crypto;!ROOT!\DelphiToFPC"
set "IP=!ROOT!;!ROOT!\CnPack\Common"
set "NS=System;Xml;Data;Datasnap;Web;Soap;Winapi;System.Win;Data.Win;Web.Win;Xml.Win"
if not exist "%~dp0bin\dcu" mkdir "%~dp0bin\dcu"

echo dcc64:  !DCC!
echo DCS:    !ROOT!
echo.
"!DCC!" -B -Q -U"!UP!" -I"!IP!" -NS"!NS!" -E"%~dp0bin" -NU"%~dp0bin\dcu" CnPackHashTests.dpr > "%~dp0bin\build.log" 2>&1
if errorlevel 1 goto :build_failed
echo build ok
echo.
"%~dp0bin\CnPackHashTests.exe"
exit /b %ERRORLEVEL%

:build_failed
type "%~dp0bin\build.log"
echo.
echo BUILD FAILED - see above. Nothing was tested.
exit /b 90

:no_dcc
echo ERROR: dcc64.exe not found. Set DELPHI_ROOT or run from a RAD Studio command prompt.
exit /b 90
