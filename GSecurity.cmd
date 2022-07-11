@echo off
title GSecurity & color 0b
CLS
ECHO.
ECHO =============================
ECHO Running Admin shell
ECHO =============================

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
ECHO.
ECHO **************************************
ECHO Invoking UAC for Privilege Escalation
ECHO **************************************

ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
ECHO args = "ELEV " >> "%vbsGetPrivileges%"
ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
ECHO Next >> "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

:: Set permissions to deny everyone access to drives except to user running this script
c:
cd\
takeown /f a:
icacls a: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls a: /inheritance:e /grant:r System:(OI)(CI)F
icacls a: /remove "Authenticated Users"
icacls a: /remove "Everyone"

takeown /f b:
icacls b: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls b: /inheritance:e /grant:r System:(OI)(CI)F
icacls b: /remove "Authenticated Users"
icacls b: /remove "Everyone"

takeown /f c:
icacls c: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls c: /inheritance:e /grant:r System:(OI)(CI)F
icacls c: /remove "Everyone"

takeown /f d:
icacls d: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls d: /inheritance:e /grant:r System:(OI)(CI)F
icacls d: /remove "Authenticated Users"
icacls d: /remove "Everyone"

takeown /f e:
icacls e: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls e: /inheritance:e /grant:r System:(OI)(CI)F
icacls e: /remove "Authenticated Users"
icacls e: /remove "Everyone"

takeown /f f:
icacls f: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls f: /inheritance:e /grant:r System:(OI)(CI)F
icacls f: /remove "Authenticated Users"
icacls f: /remove "Everyone"

takeown /f g:
icacls g: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls g: /inheritance:e /grant:r System:(OI)(CI)F
icacls g: /remove "Authenticated Users"
icacls g: /remove "Everyone"

takeown /f h:
icacls h: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls h: /inheritance:e /grant:r System:(OI)(CI)F
icacls h: /remove "Authenticated Users"
icacls h: /remove "Everyone"

takeown /f i:
icacls i: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls i: /inheritance:e /grant:r System:(OI)(CI)F
icacls i: /remove "Authenticated Users"
icacls i: /remove "Everyone"

takeown /f j:
icacls j: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls j: /inheritance:e /grant:r System:(OI)(CI)F
icacls j: /remove "Authenticated Users"
icacls j: /remove "Everyone"

takeown /f k:
icacls k: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls k: /inheritance:e /grant:r System:(OI)(CI)F
icacls k: /remove "Authenticated Users"
icacls k: /remove "Everyone"

takeown /f l:
icacls l: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls l: /inheritance:e /grant:r System:(OI)(CI)F
icacls l: /remove "Authenticated Users"
icacls l: /remove "Everyone"

takeown /f m:
icacls m: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls m: /inheritance:e /grant:r System:(OI)(CI)F
icacls m: /remove "Authenticated Users"
icacls m: /remove "Everyone"

takeown /f n:
icacls n: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls n: /inheritance:e /grant:r System:(OI)(CI)F
icacls n: /remove "Authenticated Users"
icacls n: /remove "Everyone"

takeown /f o:
icacls o: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls o: /inheritance:e /grant:r System:(OI)(CI)F
icacls o: /remove "Authenticated Users"
icacls o: /remove "Everyone"

takeown /f p:
icacls p: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls p: /inheritance:e /grant:r System:(OI)(CI)F
icacls p: /remove "Authenticated Users"
icacls p: /remove "Everyone"

takeown /f q:
icacls q: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls q: /inheritance:e /grant:r System:(OI)(CI)F
icacls q: /remove "Authenticated Users"
icacls q: /remove "Everyone"

takeown /f r:
icacls r: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls r: /inheritance:e /grant:r System:(OI)(CI)F
icacls r: /remove "Authenticated Users"
icacls r: /remove "Everyone"

takeown /f s:
icacls s: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls s: /inheritance:e /grant:r System:(OI)(CI)F
icacls s: /remove "Authenticated Users"
icacls s: /remove "Everyone"

takeown /f t:
icacls t: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls t: /inheritance:e /grant:r System:(OI)(CI)F
icacls t: /remove "Authenticated Users"
icacls t: /remove "Everyone"

takeown /f u:
icacls u: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls u: /inheritance:e /grant:r System:(OI)(CI)F
icacls u: /remove "Authenticated Users"
icacls u: /remove "Everyone"

takeown /f v:
icacls v: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls v: /inheritance:e /grant:r System:(OI)(CI)F
icacls v: /remove "Authenticated Users"
icacls v: /remove "Everyone"

takeown /f w:
icacls w: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls w: /inheritance:e /grant:r System:(OI)(CI)F
icacls w: /remove "Authenticated Users"
icacls w: /remove "Everyone"

takeown /f x:
icacls x: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls x: /inheritance:e /grant:r System:(OI)(CI)F
icacls x: /remove "Authenticated Users"
icacls x: /remove "Everyone"

takeown /f y:
icacls y: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls y: /inheritance:e /grant:r System:(OI)(CI)F
icacls y: /remove "Authenticated Users"
icacls y: /remove "Everyone"

takeown /f z:
icacls z: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls z: /inheritance:e /grant:r System:(OI)(CI)F
icacls z: /remove "Authenticated Users"
icacls z: /remove "Everyone"

:: Terminal Services
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "AllowSignedFiles" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "AllowUnsignedFiles" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "DisablePasswordSaving" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fAllowUnsolicited" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fDisableCdm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fDisableCpm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fEncryptRPCTraffic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fPromptForPassword" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "MinEncryptionLevel" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "PromptForCredsOnClient" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "UseUniversalPrinterDriverFirst" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fSingleSessionPerUser" /t REG_DWORD /d "1" /f

:: Remote Shell
Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f

:: Services
sc stop LanmanWorkstation
timeout 5
sc config LanmanWorkstation start= disabled
sc stop seclogon
timeout 5
sc config seclogon start= disabled

:: exit
exit