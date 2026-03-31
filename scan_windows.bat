@echo off
REM axios-supply-chain-scanner — Windows (detection only)
REM This script ONLY detects and reports. It does NOT modify, delete, or kill anything.
REM
REM Reference: https://socket.dev/blog/axios-npm-package-compromised
REM            https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
REM Date: 2026-03-31

setlocal EnableDelayedExpansion
set "COMPROMISED=0"
set "FINDING_COUNT=0"

echo ========================================
echo  axios supply chain scanner — Windows
echo  (detection only — no changes will be made)
echo ========================================
echo.

REM -- 1. Global npm: axios version --
echo === 1. Global npm — axios version ===
set "AXIOS_FOUND="
for /f "delims=" %%i in ('npm list -g --depth=0 2^>nul ^| findstr /R "axios@1\.14\.1 axios@0\.30\.4"') do (
  set "AXIOS_FOUND=%%i"
)
if defined AXIOS_FOUND (
  echo [!] AFFECTED: !AXIOS_FOUND!
  set "COMPROMISED=1"
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=Malicious axios globally: !AXIOS_FOUND!"
) else (
  echo [OK] Clean
)
echo.

REM -- 2. Global npm: plain-crypto-js --
echo === 2. Global npm — plain-crypto-js ===
set "PCJ_FOUND="
for /f "delims=" %%i in ('npm list -g --depth=0 2^>nul ^| findstr "plain-crypto-js"') do (
  set "PCJ_FOUND=%%i"
)
if defined PCJ_FOUND (
  echo [!] AFFECTED: !PCJ_FOUND!
  set "COMPROMISED=1"
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=Malicious plain-crypto-js globally: !PCJ_FOUND!"
) else (
  echo [OK] Clean
)
echo.

REM -- 3. RAT artifact: %PROGRAMDATA%\wt.exe --
echo === 3. RAT artifact — %%PROGRAMDATA%%\wt.exe ===
if exist "%PROGRAMDATA%\wt.exe" (
  echo [!!!] COMPROMISED: %PROGRAMDATA%\wt.exe
  dir "%PROGRAMDATA%\wt.exe"
  set "COMPROMISED=1"
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=Windows RAT binary: %PROGRAMDATA%\wt.exe"
) else (
  echo [OK] Clean
)
echo.

REM -- 4. RAT artifact: %TEMP%\6202033.ps1 --
echo === 4. RAT artifact — %%TEMP%%\6202033.ps1 ===
if exist "%TEMP%\6202033.ps1" (
  echo [!!!] COMPROMISED: %TEMP%\6202033.ps1
  dir "%TEMP%\6202033.ps1"
  set "COMPROMISED=1"
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=PowerShell payload: %TEMP%\6202033.ps1"
) else (
  echo [OK] Clean
)
echo.

REM -- 5. RAT artifact: %TEMP%\6202033.vbs --
echo === 5. RAT artifact — %%TEMP%%\6202033.vbs ===
if exist "%TEMP%\6202033.vbs" (
  echo [!!!] COMPROMISED: %TEMP%\6202033.vbs
  dir "%TEMP%\6202033.vbs"
  set "COMPROMISED=1"
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=VBScript launcher: %TEMP%\6202033.vbs"
) else (
  echo [OK] Clean
)
echo.

REM -- 6. RAT staging directory --
echo === 6. RAT staging — %%TEMP%%\6202033 ===
if exist "%TEMP%\6202033" (
  echo [!!!] COMPROMISED: %TEMP%\6202033
  dir "%TEMP%\6202033"
  set "COMPROMISED=1"
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=RAT staging directory: %TEMP%\6202033"
) else (
  echo [OK] Clean
)
echo.

REM -- 7. npm global modules: plain-crypto-js --
echo === 7. npm global modules — plain-crypto-js ===
if exist "%APPDATA%\npm\node_modules\plain-crypto-js" (
  echo [!] AFFECTED: %APPDATA%\npm\node_modules\plain-crypto-js
  set "COMPROMISED=1"
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=npm global: %APPDATA%\npm\node_modules\plain-crypto-js"
) else (
  echo [OK] Clean
)
echo.

REM -- 8. Scan common project directories --
echo === 8. Project scan — plain-crypto-js in node_modules ===
set "PROJECT_HIT=0"
for %%D in ("%USERPROFILE%\Projects" "%USERPROFILE%\Documents" "%USERPROFILE%\Desktop" "%USERPROFILE%\repos" "%USERPROFILE%\dev" "%USERPROFILE%\src" "%USERPROFILE%\work") do (
  if exist "%%~D" (
    for /f "delims=" %%f in ('dir /s /b "%%~D\plain-crypto-js" 2^>nul') do (
      echo [!] FOUND: %%f
      set "PROJECT_HIT=1"
      set "COMPROMISED=1"
      set /a "FINDING_COUNT+=1"
      set "FINDING_!FINDING_COUNT!=Project plain-crypto-js: %%f"
    )
  )
)
if "!PROJECT_HIT!"=="0" (
  echo [OK] Clean
)
echo.

REM -- 9. Network: C2 domain check --
echo === 9. Network — C2 domain check ===
nslookup sfrclak.com >nul 2>&1
if !errorlevel! equ 0 (
  echo [!] WARNING: C2 domain sfrclak.com resolves
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=C2 domain sfrclak.com resolves"
) else (
  echo [OK] C2 domain does not resolve
)
echo.

REM -- 10. Network: active connections to C2 --
echo === 10. Network — active C2 connections ===
set "C2_CONN="
for /f "delims=" %%i in ('netstat -n 2^>nul ^| findstr "142.11.206.73"') do (
  set "C2_CONN=%%i"
)
if defined C2_CONN (
  echo [!!!] COMPROMISED — active C2 connection:
  netstat -n | findstr "142.11.206.73"
  set "COMPROMISED=1"
  set /a "FINDING_COUNT+=1"
  set "FINDING_!FINDING_COUNT!=Active C2 connection to 142.11.206.73"
) else (
  echo [OK] No active C2 connections
)
echo.

REM -- Summary --
echo ========================================
if "!COMPROMISED!"=="1" (
  echo [RESULT] POTENTIAL COMPROMISE DETECTED
  echo.
  echo Detected items:
  for /L %%i in (1,1,!FINDING_COUNT!) do (
    echo   - !FINDING_%%i!
  )
  echo.
  echo Related IOC:
  echo   C2 domain  : sfrclak[.]com
  echo   C2 IP      : 142.11.206.73
  echo   C2 port    : 8000
  echo   Campaign ID: 6202033
  echo.
  echo See README.md for remediation guidance.
) else (
  echo [RESULT] CLEAN — No indicators of compromise found
)
echo ========================================

endlocal
pause
