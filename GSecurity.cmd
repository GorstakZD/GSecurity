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

:: Override
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "4" /f

:: Permissions
c:
cd\
takeown /f c: /r /d y
icacls c: /inheritance:r
icacls c: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls c: /remove "Users"
icacls c: /remove "Administrators"
icacls c: /remove "System"

takeown /f a: /r /d y
icacls a: /inheritance:r
icacls a: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls a: /remove "Users"
icacls a: /remove "Administrators"
icacls a: /remove "System"

takeown /f b: /r /d y
icacls b: /inheritance:r
icacls b: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls b: /remove "Users"
icacls b: /remove "Administrators"
icacls b: /remove "System"

takeown /f d: /r /d y
icacls d: /inheritance:r
icacls d: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls d: /remove "Users"
icacls d: /remove "Administrators"
icacls d: /remove "System"

takeown /f e: /r /d y
icacls e: /inheritance:r
icacls e: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls e: /remove "Users"
icacls e: /remove "Administrators"
icacls e: /remove "System"

takeown /f f: /r /d y
icacls f: /inheritance:r
icacls f: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls f: /remove "Users"
icacls f: /remove "Administrators"
icacls f: /remove "System"

takeown /f g: /r /d y
icacls g: /inheritance:r
icacls g: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls g: /remove "Users"
icacls g: /remove "Administrators"
icacls g: /remove "System"

takeown /f h: /r /d y
icacls h: /inheritance:r
icacls h: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls h: /remove "Users"
icacls h: /remove "Administrators"
icacls h: /remove "System"

takeown /f i: /r /d y
icacls i: /inheritance:r
icacls i: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls i: /remove "Users"
icacls i: /remove "Administrators"
icacls i: /remove "System"

takeown /f j: /r /d y
icacls j: /inheritance:r
icacls j: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls j: /remove "Users"
icacls j: /remove "Administrators"
icacls j: /remove "System"

takeown /f k: /r /d y
icacls k: /inheritance:r
icacls k: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls k: /remove "Users"
icacls k: /remove "Administrators"
icacls k: /remove "System"

takeown /f l: /r /d y
icacls l: /inheritance:r
icacls l: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls l: /remove "Users"
icacls l: /remove "Administrators"
icacls l: /remove "System"

takeown /f m: /r /d y
icacls m: /inheritance:r
icacls m: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls m: /remove "Users"
icacls m: /remove "Administrators"
icacls m: /remove "System"

takeown /f n: /r /d y
icacls n: /inheritance:r
icacls n: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls n: /remove "Users"
icacls n: /remove "Administrators"
icacls n: /remove "System"

takeown /f o: /r /d y
icacls o: /inheritance:r
icacls o: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls o: /remove "Users"
icacls o: /remove "Administrators"
icacls o: /remove "System"

takeown /f p: /r /d y
icacls p: /inheritance:r
icacls p: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls p: /remove "Users"
icacls p: /remove "Administrators"
icacls p: /remove "System"

takeown /f q: /r /d y
icacls q: /inheritance:r
icacls q: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls q: /remove "Users"
icacls q: /remove "Administrators"
icacls q: /remove "System"

takeown /f r: /r /d y
icacls r: /inheritance:r
icacls r: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls r: /remove "Users"
icacls r: /remove "Administrators"
icacls r: /remove "System"

takeown /f s: /r /d y
icacls s: /inheritance:r
icacls s: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls s: /remove "Users"
icacls s: /remove "Administrators"
icacls s: /remove "System"

takeown /f t: /r /d y
icacls t: /inheritance:r
icacls t: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls t: /remove "Users"
icacls t: /remove "Administrators"
icacls t: /remove "System"

takeown /f u: /r /d y
icacls u: /inheritance:r
icacls u: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls u: /remove "Users"
icacls u: /remove "Administrators"
icacls u: /remove "System"

takeown /f v: /r /d y
icacls v: /inheritance:r
icacls v: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls v: /remove "Users"
icacls v: /remove "Administrators"
icacls v: /remove "System"

takeown /f w: /r /d y
icacls w: /inheritance:r
icacls w: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls w: /remove "Users"
icacls w: /remove "Administrators"
icacls w: /remove "System"

takeown /f x: /r /d y
icacls x: /inheritance:r
icacls x: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls x: /remove "Users"
icacls x: /remove "Administrators"
icacls x: /remove "System"

takeown /f y: /r /d y
icacls y: /inheritance:r
icacls y: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls y: /remove "Users"
icacls y: /remove "Administrators"
icacls y: /remove "System"

takeown /f z: /r /d y
icacls z: /inheritance:r
icacls z: /inheritance:e /grant:r "Authenticated Users":(OI)(CI)F /t /l /q /c
icacls z: /remove "Users"
icacls z: /remove "Administrators"
icacls z: /remove "System"

:: Exit
Exit