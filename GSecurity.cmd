<!-- : Begin batch script
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

bcdedit /set hypervisorlaunchtype off
net user administrator /active:yes
sc delete SessionEnv
sc stop SessionEnv
sc delete TermService
sc stop TermService
sc delete UmRdpService
sc stop UmRdpService
sc delete RemoteRegistry
sc stop RemoteRegistry
sc delete Rasman
sc stop Rasman
sc delete RasAuto
sc delete RmSvc
takeown /f C:\Windows\System32\termsrv.dll
cacls termsrv.dll /E /P %username%:F
del C:\Windows\System32\termsrv.dll
takeown /f C:\Windows\System32\termmgr.dll
cacls termmgr.dll /E /P %username%:F
del C:\Windows\System32\termmgr.dll
sc delete CDPSvc
sc stop CDPSvc
sc delete CDPUserSvc
sc stop CDPUsersvc
sc delete DiagTrack
sc stop DiagTrack
sc delete PimIndexMaintenanceSvc
sc stop PimIndexMaintenanceSvc
sc config DPS start= disabled
sc stop DPS
sc config WdiServiceHost start= disabled
sc stop WdiServiceHost
sc config WdiSystemHost start= disabled
sc stop WdiSystemHost
sc config NlaSvc start= disabled
sc config netprofm start= disabled
sc config AppVClient start= disabled
sc config Wecsvc start= disabled
sc config WerSvc start= disabled
sc config EventLog start= disabled
sc delete RdpVideoMiniport
sc delete tsusbflt
sc delete tsusbhub 
sc delete TsUsbGD
sc delete RDPDR
sc delete rdpbus
sc start rdpbus
sc stop rdpbus
sc delete RasPppoe
sc delete NdisWan
sc delete NdisTapi
sc delete ndiswanlegacy
sc delete wanarpv6
sc delete wanarp
sc delete RasAcd
takeown /f C:\Windows\System32\drivers\rdpbus.sys
cacls C:\Windows\System32\drivers\rdpbus.sys /E /P %username%:F
del C:\Windows\System32\drivers\rdpbus.sys
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "4" /f
shutdown -r -t 0