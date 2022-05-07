@echo off
title GSecurity & color 0b

:: Elevate
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

:: Set scriptdir as active
pushd %~dp0

:: Logon Protection
takeown /f %SystemDrive%\Windows\System32\winlogon.exe
icacls %SystemDrive%\Windows\System32\winlogon.exe /remove "ALL APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\winlogon.exe /remove "ALL RESTRICTED APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\winlogon.exe /remove Users
icacls %SystemDrive%\Windows\System32\winlogon.exe /deny NETWORK:(OI)(CI)F
takeown /f %SystemDrive%\Windows\System32\logonui.exe
icacls %SystemDrive%\Windows\System32\logonui.exe /remove "ALL APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\logonui.exe /remove "ALL RESTRICTED APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\logonui.exe /remove Users
icacls %SystemDrive%\Windows\System32\logonui.exe /deny NETWORK:(OI)(CI)F

:: Take ownership of Desktop
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Powershell
Powershell.exe [Environment]::SetEnvironmentVariable(‘__PSLockdownPolicy‘, ‘4’, ‘Machine‘)

:: Registry
Reg.exe import GSecurity.reg

:: Exit
popd
shutdown -r -t 0
