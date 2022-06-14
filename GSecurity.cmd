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

:: Hypervisor off
bcdedit /set hypervisorlaunchtype off

:: Repair
netsh winsock reset
netsh int ip reset
netsh advfirewall reset
netsh advfirewall set allprofiles state ON
bitsadmin /reset /allusers

:: Firewall
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3105}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\explorer.exe|Name=explorer|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3173}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ntoskrnl.exe|Name=Kernel|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{1E78ACD0-2EB2-4C5B-BE1E-C3AF5786D813}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=TCP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{7647502E-A6B0-4DCD-BD65-6B0E48EEFDF7}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=UDP|EmbedCtxt=GSecurity|" /f

:: Spectre and Meltdown protection off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "4" /f

:: Disable point of entry for Spectre and Meltdown
Dism /online /Disable-Feature /FeatureName:"SMB1Protocol"
Dism /online /Disable-Feature /FeatureName:"SMB1Protocol-Client"
Dism /online /Disable-Feature /FeatureName:"SMB1Protocol-Server"

:: Server
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "EnableAuthenticateUserSharing" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "NullSessionPipes" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "%%SystemRoot%%\system32\srvsvc.dll" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "enableforcedlogoff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "enablesecuritysignature" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "restrictnullsessaccess" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "SMB2" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "SMB3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters\FsctlAllowlist" /f

:: Block logons
takeown /f %SystemDrive%\Windows\System32\winlogon.exe
icacls %SystemDrive%\Windows\System32\winlogon.exe /remove "All Application Packages"
icacls %SystemDrive%\Windows\System32\winlogon.exe /remove "All Restricted Application Packages"
icacls %SystemDrive%\Windows\System32\winlogon.exe /remove "Authenticated Users"
icacls %SystemDrive%\Windows\System32\winlogon.exe /remove Users
icacls %SystemDrive%\Windows\System32\winlogon.exe /remove TrustedInstaller
icacls %SystemDrive%\Windows\System32\winlogon.exe /deny Network:F
takeown /f %SystemDrive%\Windows\System32\logonui.exe
icacls %SystemDrive%\Windows\System32\logonui.exe /remove "All Application Packages"
icacls %SystemDrive%\Windows\System32\logonui.exe /remove "All Restricted Application Packages"
icacls %SystemDrive%\Windows\System32\logonui.exe /remove "Authenticated Users"
icacls %SystemDrive%\Windows\System32\logonui.exe /remove Users
icacls %SystemDrive%\Windows\System32\logonui.exe /remove TrustedInstaller
icacls %SystemDrive%\Windows\System32\logonui.exe /deny Network:F

:: Exit
shutdown -r -t 0