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

:: Powershell
Powershell.exe [Environment]::SetEnvironmentVariable(‘__PSLockdownPolicy‘, ‘4’, ‘Machine‘)

:: Firewall
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "PolicyVersion" /t REG_DWORD /d "543" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "IPSecExempt" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3105}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\explorer.exe|Name=explorer|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3173}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ntoskrnl.exe|Name=Kernel|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{1E78ACD0-2EB2-4C5B-BE1E-C3AF5786D813}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=TCP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{7647502E-A6B0-4DCD-BD65-6B0E48EEFDF7}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=UDP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3105}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\explorer.exe|Name=explorer|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3173}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ntoskrnl.exe|Name=Kernel|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{1E78ACD0-2EB2-4C5B-BE1E-C3AF5786D813}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=TCP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{7647502E-A6B0-4DCD-BD65-6B0E48EEFDF7}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=UDP|EmbedCtxt=GSecurity|" /f

:: Software Restriction Policy
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v "DefaultLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v "TransparentEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v "PolicyScope" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v "ExecutableTypes" /t REG_MULTI_SZ /d "ADE\0ADP\0BAS\0BAT\0CHM\0CMD\0COM\0CPL\0CRT\0EXE\0HLP\0HTA\0INF\0INS\0ISP\0LNK\0MDB\0MDE\0MSC\0MSI\0MSP\0MST\0OCX\0PCD\0PIF\0REG\0SCR\0SHS\0URL\0VB\0WSC" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{a5258ff7-27f6-4877-a457-dc596c887b22}" /v "Description" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{a5258ff7-27f6-4877-a457-dc596c887b22}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{a5258ff7-27f6-4877-a457-dc596c887b22}" /v "ItemData" /t REG_SZ /d "smb*" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{17418e05-efed-437b-951c-a9265b95b621}" /v "Description" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{17418e05-efed-437b-951c-a9265b95b621}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{17418e05-efed-437b-951c-a9265b95b621}" /v "ItemData" /t REG_SZ /d "E:\*" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{9dfbf5eb-4077-44c8-b574-5e7f22afa8bc}" /v "Description" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{9dfbf5eb-4077-44c8-b574-5e7f22afa8bc}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{9dfbf5eb-4077-44c8-b574-5e7f22afa8bc}" /v "ItemData" /t REG_SZ /d "D:\*" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{aceaf38b-7dbe-43ba-9a65-49b54c6b09af}" /v "Description" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{aceaf38b-7dbe-43ba-9a65-49b54c6b09af}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{aceaf38b-7dbe-43ba-9a65-49b54c6b09af}" /v "ItemData" /t REG_SZ /d "C:\*" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{b062012e-0ca9-4ba9-88c6-337a9cb362d5}" /v "Description" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{b062012e-0ca9-4ba9-88c6-337a9cb362d5}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\{b062012e-0ca9-4ba9-88c6-337a9cb362d5}" /v "ItemData" /t REG_SZ /d "F:\*" /f

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

:: Consent
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "dontdisplaylastusername" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f

:: Ads block
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /t REG_SZ /d "https://raw.githubusercontent.com/GorstakZD/Pac/main/GSecurity.pac" /f

:: Exit
shutdown -r -t 0