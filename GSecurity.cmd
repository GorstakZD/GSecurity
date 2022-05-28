@cls
@echo off
>nul chcp 437
setlocal enabledelayedexpansion
title GSecurity & color 0b

:: Run as administrator, AveYo: ps\VBS version
>nul fltmc || ( set "_=call "%~dpfx0" %*"
	powershell -nop -c start cmd -args '/d/x/r',$env:_ -verb runas || (
	mshta vbscript:execute^("createobject(""shell.application"").shellexecute(""cmd"",""/d/x/r "" &createobject(""WScript.Shell"").Environment(""PROCESS"")(""_""),,""runas"",1)(window.close)"^))|| (
	cls & echo:& echo Script elavation failed& pause)
	exit )
	
:: Powershell
>nul 2>&1 Powershell.exe [Environment]::SetEnvironmentVariable(‘__PSLockdownPolicy‘, ‘4’, ‘Machine‘)

:: Logon Protection
>nul 2>&1 takeown /f %SystemDrive%\Windows\System32\winlogon.exe
>nul 2>&1 icacls %SystemDrive%\Windows\System32\winlogon.exe /remove "ALL APPLICATION PACKAGES"
>nul 2>&1 icacls %SystemDrive%\Windows\System32\winlogon.exe /remove "ALL RESTRICTED APPLICATION PACKAGES"
>nul 2>&1 icacls %SystemDrive%\Windows\System32\winlogon.exe /remove Users
>nul 2>&1 icacls %SystemDrive%\Windows\System32\winlogon.exe /deny NETWORK:(OI)(CI)F
>nul 2>&1 takeown /f %SystemDrive%\Windows\System32\logonui.exe
>nul 2>&1 icacls %SystemDrive%\Windows\System32\logonui.exe /remove "ALL APPLICATION PACKAGES"
>nul 2>&1 icacls %SystemDrive%\Windows\System32\logonui.exe /remove "ALL RESTRICTED APPLICATION PACKAGES"
>nul 2>&1 icacls %SystemDrive%\Windows\System32\logonui.exe /remove Users
>nul 2>&1 icacls %SystemDrive%\Windows\System32\logonui.exe /deny NETWORK:(OI)(CI)F

:: Take ownership of Desktop
>nul 2>&1 takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
>nul 2>&1 icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
>nul 2>&1 icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
>nul 2>&1 takeown /f "%USERPROFILE%\Desktop" /r /d y
>nul 2>&1 icacls "%USERPROFILE%\Desktop" /inheritance:r
>nul 2>&1 icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Smartscreen
>nul 2>&1 reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
>nul 2>&1 reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
>nul 2>&1 reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d "0" /f
>nul 2>&1 reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t "REG_DWORD" /d "0" /f
>nul 2>&1 reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
>nul 2>&1 reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t "REG_DWORD" /d "0" /f
>nul 2>&1 takeown /f "%WinDir%\System32\smartscreen.exe"
>nul 2>&1 icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
>nul 2>&1 taskkill /im smartscreen.exe /f
>nul 2>&1 del "%WinDir%\System32\smartscreen.exe" /s /f /q

:: Compattelrunner
>nul 2>&1 takeown /f "%WinDir%\System32\compattelrunner.exe"
>nul 2>&1 icacls "%WinDir%\System32\compattelrunner.exe" /grant:r %username%:F
>nul 2>&1 taskkill /im compattelrunner.exe /f
>nul 2>&1 del "%WinDir%\System32\compattelrunner.exe" /s /f /q

:: Set scriptdir as active
pushd %~dp0

:: Registry
>nul 2>&1 Reg.exe import BFE.reg
>nul 2>&1 Reg.exe import Defender.reg
>nul 2>&1 Reg.exe import Ifeo.reg
>nul 2>&1 Reg.exe import Immunity.reg
>nul 2>&1 Reg.exe import Ipsec.reg
>nul 2>&1 Reg.exe import MachinePolicy.reg
>nul 2>&1 Reg.exe import Override.reg
>nul 2>&1 Reg.exe import Performance.reg
>nul 2>&1 Reg.exe import Privacy.reg
>nul 2>&1 Reg.exe import Routes.reg
>nul 2>&1 Reg.exe import Scheduler.reg
>nul 2>&1 Reg.exe import Services.reg
>nul 2>&1 Reg.exe import TerminalServices.reg
>nul 2>&1 Reg.exe import UserPolicy.reg
>nul 2>&1 Reg.exe import Users.reg

:: Disable Administrative shares
>nul 2>&1 reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /f /v "AutoShareWks" /t reg_DWORD /d 0
>nul 2>&1 reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /f /v "AutoShareServer" /t reg_DWORD /d 0
>nul 2>&1 net share * /delete
