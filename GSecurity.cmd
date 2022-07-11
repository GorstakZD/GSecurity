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
icacls a: /remove "Users"
icacls a: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f b:
icacls b: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls b: /inheritance:e /grant:r System:(OI)(CI)F
icacls b: /remove "Authenticated Users"
icacls b: /remove "Everyone"
icacls b: /remove "Users"
icacls b: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f c:
icacls c: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls c: /inheritance:e /grant:r System:(OI)(CI)F
icacls c: /remove "Everyone"
icacls c: /remove "Users"
icacls c: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f d:
icacls d: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls d: /inheritance:e /grant:r System:(OI)(CI)F
icacls d: /remove "Authenticated Users"
icacls d: /remove "Everyone"
icacls d: /remove "Users"
icacls d: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f e:
icacls e: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls e: /inheritance:e /grant:r System:(OI)(CI)F
icacls e: /remove "Authenticated Users"
icacls e: /remove "Everyone"
icacls e: /remove "Users"
icacls e: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f f:
icacls f: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls f: /inheritance:e /grant:r System:(OI)(CI)F
icacls f: /remove "Authenticated Users"
icacls f: /remove "Everyone"
icacls f: /remove "Users"
icacls f: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f g:
icacls g: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls g: /inheritance:e /grant:r System:(OI)(CI)F
icacls g: /remove "Authenticated Users"
icacls g: /remove "Everyone"
icacls g: /remove "Users"
icacls g: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f h:
icacls h: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls h: /inheritance:e /grant:r System:(OI)(CI)F
icacls h: /remove "Authenticated Users"
icacls h: /remove "Everyone"
icacls h: /remove "Users"
icacls h: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f i:
icacls i: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls i: /inheritance:e /grant:r System:(OI)(CI)F
icacls i: /remove "Authenticated Users"
icacls i: /remove "Everyone"
icacls i: /remove "Users"
icacls i: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f j:
icacls j: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls j: /inheritance:e /grant:r System:(OI)(CI)F
icacls j: /remove "Authenticated Users"
icacls j: /remove "Everyone"
icacls j: /remove "Users"
icacls j: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f k:
icacls k: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls k: /inheritance:e /grant:r System:(OI)(CI)F
icacls k: /remove "Authenticated Users"
icacls k: /remove "Everyone"
icacls k: /remove "Users"
icacls k: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f l:
icacls l: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls l: /inheritance:e /grant:r System:(OI)(CI)F
icacls l: /remove "Authenticated Users"
icacls l: /remove "Everyone"
icacls l: /remove "Users"
icacls l: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f m:
icacls m: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls m: /inheritance:e /grant:r System:(OI)(CI)F
icacls m: /remove "Authenticated Users"
icacls m: /remove "Everyone"
icacls m: /remove "Users"
icacls m: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f n:
icacls n: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls n: /inheritance:e /grant:r System:(OI)(CI)F
icacls n: /remove "Authenticated Users"
icacls n: /remove "Everyone"
icacls n: /remove "Users"
icacls n: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f o:
icacls o: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls o: /inheritance:e /grant:r System:(OI)(CI)F
icacls o: /remove "Authenticated Users"
icacls o: /remove "Everyone"
icacls o: /remove "Users"
icacls o: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f p:
icacls p: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls p: /inheritance:e /grant:r System:(OI)(CI)F
icacls p: /remove "Authenticated Users"
icacls p: /remove "Everyone"
icacls p: /remove "Users"
icacls p: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f q:
icacls q: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls q: /inheritance:e /grant:r System:(OI)(CI)F
icacls q: /remove "Authenticated Users"
icacls q: /remove "Everyone"
icacls q: /remove "Users"
icacls q: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f r:
icacls r: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls r: /inheritance:e /grant:r System:(OI)(CI)F
icacls r: /remove "Authenticated Users"
icacls r: /remove "Everyone"
icacls r: /remove "Users"
icacls r: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f s:
icacls s: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls s: /inheritance:e /grant:r System:(OI)(CI)F
icacls s: /remove "Authenticated Users"
icacls s: /remove "Everyone"
icacls s: /remove "Users"
icacls s: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f t:
icacls t: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls t: /inheritance:e /grant:r System:(OI)(CI)F
icacls t: /remove "Authenticated Users"
icacls t: /remove "Everyone"
icacls t: /remove "Users"
icacls t: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f u:
icacls u: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls u: /inheritance:e /grant:r System:(OI)(CI)F
icacls u: /remove "Authenticated Users"
icacls u: /remove "Everyone"
icacls u: /remove "Users"
icacls u: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f v:
icacls v: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls v: /inheritance:e /grant:r System:(OI)(CI)F
icacls v: /remove "Authenticated Users"
icacls v: /remove "Everyone"
icacls v: /remove "Users"
icacls v: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f w:
icacls w: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls w: /inheritance:e /grant:r System:(OI)(CI)F
icacls w: /remove "Authenticated Users"
icacls w: /remove "Everyone"
icacls w: /remove "Users"
icacls w: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f x:
icacls x: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls x: /inheritance:e /grant:r System:(OI)(CI)F
icacls x: /remove "Authenticated Users"
icacls x: /remove "Everyone"
icacls x: /remove "Users"
icacls x: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f y:
icacls y: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls y: /inheritance:e /grant:r System:(OI)(CI)F
icacls y: /remove "Authenticated Users"
icacls y: /remove "Everyone"
icacls y: /remove "Users"
icacls y: /inheritance:e /grant:r Users:(OI)(CI)R

takeown /f z:
icacls z: /inheritance:e /grant:r Administrators:(OI)(CI)F
icacls z: /inheritance:e /grant:r System:(OI)(CI)F
icacls z: /remove "Authenticated Users"
icacls z: /remove "Everyone"
icacls z: /remove "Users"
icacls z: /inheritance:e /grant:r Users:(OI)(CI)R

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

:: Firewall
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "PolicyVersion" /t REG_DWORD /d "543" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "IPSecExempt" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
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

:: exit
exit