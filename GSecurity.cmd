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

:: Powershell
Powershell.exe [Environment]::SetEnvironmentVariable(‘__PSLockdownPolicy‘, ‘4’, ‘Machine‘)

:: Registry
Reg.exe import BFE.reg
Reg.exe import Defender.reg
Reg.exe import Firewall.reg
Reg.exe import Ifeo.reg
Reg.exe import Immunity.reg
Reg.exe import IPSec.reg
Reg.exe import Performance.reg
Reg.exe import Privacy.reg
Reg.exe import Routes.reg
Reg.exe import Scheduler.reg
Reg.exe import TerminalServices.reg
Reg.exe import Safer.reg

:: Exit
popd
shutdown -r -t 0
