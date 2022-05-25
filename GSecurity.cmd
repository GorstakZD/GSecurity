@echo off
title GSecurity & color 0b

:: Run as administrator, AveYo: ps\VBS version
>nul fltmc || ( set "_=call "%~dpfx0" %*"
	powershell -nop -c start cmd -args '/d/x/r',$env:_ -verb runas || (
	mshta vbscript:execute^("createobject(""shell.application"").shellexecute(""cmd"",""/d/x/r "" &createobject(""WScript.Shell"").Environment(""PROCESS"")(""_""),,""runas"",1)(window.close)"^))|| (
	cls & echo:& echo Script elavation failed& pause)
	exit )

:: Smartscreen
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t "REG_DWORD" /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t "REG_DWORD" /d "0" /f
takeown /f "%WinDir%\System32\smartscreen.exe"
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
taskkill /im smartscreen.exe /f
del "%WinDir%\System32\smartscreen.exe" /s /f /q

:: Compattelrunner
takeown /f "%WinDir%\System32\compattelrunner.exe"
icacls "%WinDir%\System32\compattelrunner.exe" /grant:r %username%:F
taskkill /im compattelrunner.exe /f
del "%WinDir%\System32\compattelrunner.exe" /s /f /q

:: Registry
Reg.exe import BFE.reg
Reg.exe import Defender.reg
Reg.exe import Ifeo.reg
Reg.exe import Immunity.reg
Reg.exe import Ipsec.reg
Reg.exe import MachinePolicy.reg
Reg.exe import Override.reg
Reg.exe import Performance.reg
Reg.exe import Privacy.reg
Reg.exe import Routes.reg
Reg.exe import Scheduler.reg
Reg.exe import Services.reg
Reg.exe import TerminalServices.reg
Reg.exe import UserPolicy.reg
Reg.exe import Users.reg

:: Exit
Exit
