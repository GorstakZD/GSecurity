@echo off
title GSecurity & color 0b

REM ; elevation
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

REM ; Protect logon
takeown /s %computername% /u %username% /f "%SystemDrive%\Windows\System32\winlogon.exe" /r /d y
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /remove "ALL APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /remove "ALL RESTRICTED APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /remove "Users"
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /remove "TrustedInstaller"
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /deny "NETWORK":(OI)(CI)F /t /l /q /c

takeown /s %computername% /u %username% /f "%SystemDrive%\Windows\System32\logonui.exe" /r /d y
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /remove "ALL APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /remove "ALL RESTRICTED APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /remove "Users"
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /remove "TrustedInstaller"
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /deny "NETWORK":(OI)(CI)F /t /l /q /c

REM ; Registry
Reg.exe import %~dp0GSecurity.reg

REM ; Exit
popd
exit