@echo off
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

:: Title
title GSecurity & color 0b

:: PatchMyPC
curl -# https://patchmypc.com/freeupdater/PatchMyPC.exe -o %userprofile%\Desktop\PatchMyPC.exe

:: Services
sc stop LanmanWorkstation
sc stop LanmanServer
sc stop RemoteRegistry
sc stop SecondaryLogon
sc stop SharedAccess
sc stop Spooler
sc stop Schedule
sc config LanmanWorkstation start= disabled
sc config LanmanServer start= disabled
sc config SecondaryLogon Start= disabled
sc config SharedAccess Start= disabled
sc config Spooler Start= disabled
sc config Schedule Start= disabled
sc config RemoteRegistry Start= disabled

:: Shares
net share * /DELETE

:: Tasks
schtasks /delete /tn * /f

:: Remote Shell
Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f

:: Terminal Services
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "DenyTSConnections" /t REG_DWORD /d "1" /f

:: Firewall (Use port 55555 if you need anything to bind to a port, like your torrent client)
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "PolicyVersion" /t REG_DWORD /d "543" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "IPSecExempt" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{ED04FABD-4E60-4D4F-8C72-54D8F32A211D}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Name=Block inbound|LUAuth=O:LSD:(D;;CC;;;NS)(A;;CC;;;S-1-2-1)|Platform=2:6:2|Platform2=GTEQ|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{CA5154A7-8D22-4E9B-A0C8-59EDD6D455C8}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Name=Block outbound|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|Platform=2:6:2|Platform2=GTEQ|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{C9B41299-7C2C-46EB-8BE5-C448864E7F42}" /t REG_SZ /d "v2.30|Action=Allow|Active=TRUE|Dir=In|Name=Allow inbound|LUAuth=O:LSD:(A;;CC;;;NS)|Platform=2:6:2|Platform2=GTEQ|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{C3C53FFF-0B0A-46C1-88D3-8FF5D05E57DC}" /t REG_SZ /d "v2.30|Action=Allow|Active=TRUE|Dir=Out|Name=Allow outbound|LUAuth=O:LSD:(A;;CC;;;S-1-2-1)|Platform=2:6:2|Platform2=GTEQ|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{1E7BFD4C-BCC0-43E1-984F-5C845CB1D66A}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|LA4=0.0.0.0|Name=0.0.0.0|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{394F2EBB-EC53-4332-B0B9-009BD016ACF8}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=135|LPort2_10=137-139|Name=TCP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{5F113304-2628-4D70-B5F3-842263DA9259}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=135|LPort2_10=137-139|Name=UDP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{C2BE25BD-F8D8-4855-B5A1-D5A84493A41F}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|LA4=0.0.0.0|Name=0.0.0.0|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{9CEA5326-11AF-4539-93EB-609809B3385D}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=6|LPort=135|LPort2_10=137-139|Name=TCP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{D321AC1A-79F3-4F4D-ACDA-CC7DAE034B1A}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=17|LPort=135|LPort2_10=137-139|Name=UDP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{72B3A63D-B506-4914-BBBD-E6ACED2D63D7}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|App=%%SystemRoot%%\System32\ntoskrnl.exe|Name=ntoskrnl.exe|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{891933B0-9E7A-4CDA-A0E3-CA8D3DCF5C0E}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|App=%%SystemRoot%%\explorer.exe|Name=explorer.exe|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{050CD76F-8213-4FF4-A025-695F1076BD1C}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|App=%%SystemRoot%%\explorer.exe|Name=explorer.exe|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{15474752-2345-4B78-AC86-1420571F2553}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|App=%%SystemRoot%%\System32\ntoskrnl.exe|Name=ntoskrnl.exe|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{1E78ACD0-2EB2-4C5B-BE1E-C3AF5786D813}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=TCP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{7647502E-A6B0-4DCD-BD65-6B0E48EEFDF7}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=UDP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{1328DBFE-5C4D-45C0-A1DC-E8C4ACA191F1}" /t REG_SZ /d "v2.29|Action=Allow|Active=TRUE|Dir=Out|Name=Allow outgoing|LUAuth=O:LSD:(A;;CC;;;S-1-2-1)|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{2FE0B25C-3959-48DD-8A30-044DEC9D2D21}" /t REG_SZ /d "v2.29|Action=Allow|Active=TRUE|Dir=In|Name=Allow inbound|LUAuth=O:LSD:(A;;CC;;;S-1-2-1)|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{B2BFE478-9FAB-4F16-B788-3EB1362244F0}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=In|Name=Block inbound|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{4EC2F4B0-25C5-4B77-AA18-D63616EEC2B1}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|Name=Block outbound|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f

:: Performance
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "67108864" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_DWORD /d "4096" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\F15576E8-98B7-4186-B944-EAFA664402D9" /v "Attributes" /t REG_DWORD /d "2" /f

:: Take ownership of Desktop
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Remove Pester
takeown /f "%ProgramFiles%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles%\WindowsPowerShell" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles%\WindowsPowerShell" /s /q
takeown /f "%ProgramFiles(x86)%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles(x86)%\WindowsPowerShell" /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles(x86)%\WindowsPowerShell" /s /q

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

:: Install Sandbox, Hyper-V
Dism /Online /Enable-Feature /All /Quiet /NoRestart /FeatureName:Microsoft-Hyper-V
Dism /Online /Enable-Feature /All /Quiet /NoRestart /FeatureName:Containers-DisposableClientVM

:: Disable point of entry for Spectre and Meltdown
Dism /online /Disable-Feature /All /Quiet /NoRestart /FeatureName:"SMB1Protocol"
Dism /online /Disable-Feature /All /Quiet /NoRestart /FeatureName:"SMB1Protocol-Client"
Dism /online /Disable-Feature /All /Quiet /NoRestart /FeatureName:"SMB1Protocol-Server"

:: Pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True

:: Hosts
(
echo # Steven Black suggested
echo 127.0.0.1 localhost
echo 127.0.0.1 localhost.localdomain
echo 127.0.0.1 local
echo 255.255.255.255 broadcasthost
echo ::1 localhost
echo ::1 ip6-localhost
echo ::1 ip6-loopback
echo fe80::1%lo0 localhost
echo ff00::0 ip6-localnet
echo ff00::0 ip6-mcastprefix
echo ff02::1 ip6-allnodes
echo ff02::2 ip6-allrouters
echo ff02::3 ip6-allhosts
echo 0.0.0.0 0.0.0.0
echo 
echo # this is a list of the most popular ads companies blocked
echo 0.0.0.0 adtago.s3.amazonaws.com
echo 0.0.0.0 analyticsengine.s3.amazonaws.com
echo 0.0.0.0 advice-ads.s3.amazonaws.com
echo 0.0.0.0 affiliationjs.s3.amazonaws.com
echo 0.0.0.0 advertising-api-eu.amazon.com
echo 0.0.0.0 ssl.google-analytics.com
echo 0.0.0.0 fastclick.com
echo 0.0.0.0 fastclick.net
echo 0.0.0.0 media.fastclick.net
echo 0.0.0.0 cdn.fastclick.net
echo 0.0.0.0 analytics.yahoo.com
echo 0.0.0.0 global.adserver.yahoo.com
echo 0.0.0.0 ads.yap.yahoo.com
echo 0.0.0.0 appmetrica.yandex.com
echo 0.0.0.0 yandexadexchange.net
echo 0.0.0.0 analytics.mobile.yandex.net
echo 0.0.0.0 extmaps-api.yandex.net
echo 0.0.0.0 adsdk.yandex.ru
echo 0.0.0.0 appmetrica.yandex.com
echo 0.0.0.0 hotjar.com
echo 0.0.0.0 static.hotjar.com
echo 0.0.0.0 api-hotjar.com
echo 0.0.0.0 jotjar-analytics.com
echo 0.0.0.0 mouseflow.com
echo 0.0.0.0 freshmarketer.com
echo 0.0.0.0 luckyorange.com
echo 0.0.0.0 cdn.luckyorange.com
echo 0.0.0.0 w1.luckyorange.com
echo 0.0.0.0 upload.luckyorange.com
echo 0.0.0.0 cs.luckyorange.com
echo 0.0.0.0 settings.luckyorange.com
echo 0.0.0.0 stats.wp.com
echo 0.0.0.0 app.bugsnag.com
echo 0.0.0.0 api.bugsnag.com
echo 0.0.0.0 notify.bugsnag.com
echo 0.0.0.0 sessions.bugsnag.com
echo 0.0.0.0 browser.sentry-cdn.com
echo 0.0.0.0 app.getsentry.com
echo 0.0.0.0 amazonaws.com
echo 0.0.0.0 amazonaax.com
echo 0.0.0.0 amazonclix.com
echo 0.0.0.0 assoc-amazon.com
echo 0.0.0.0 ads.google.com
echo 0.0.0.0 pagead2.googlesyndication.com
echo 0.0.0.0 pagead2.googleadservices.com
echo # 0.0.0.0 facebook.com
echo 0.0.0.0 amazon-adsystem.com
echo 0.0.0.0 googleadservices.com
echo 0.0.0.0 doubleclick.net
echo 0.0.0.0 ad.doubleclick.net
echo 0.0.0.0 static.doubleclick.net
echo 0.0.0.0 m.doubleclick.net
echo 0.0.0.0 mediavisor.doubleclick.net
echo 0.0.0.0 googleads.g.doubleclick.net
echo 0.0.0.0 adclick.g.doubleclick.net
echo 0.0.0.0 carbonads.net
echo 0.0.0.0 advertising.amazon.com
echo 0.0.0.0 advertising.amazon.ca
echo 0.0.0.0 google-analytics.com
echo 0.0.0.0 doubleclick.net
echo 0.0.0.0 doubleclick.com
echo 0.0.0.0 doubleclick.de
echo 0.0.0.0 partner.googleadservices.com
echo 0.0.0.0 googlesyndication.com
echo 0.0.0.0 google-analytics.com
echo 0.0.0.0 zedo.com
echo 0.0.0.0 amazon.ae
echo 0.0.0.0 amazon.cn
echo 0.0.0.0 advertising.amazon.co.jp
echo 0.0.0.0 amazon.co.uk
echo 0.0.0.0 advertising.amazon.com.au
echo 0.0.0.0 advertising.amazon.com.mx
echo 0.0.0.0 advertising.amazon.de
echo 0.0.0.0 advertising.amazon.es
echo 0.0.0.0 advertising.amazon.fr
echo 0.0.0.0 advertising.amazon.in
echo 0.0.0.0 advertising.amazon.it
echo 0.0.0.0 advertising.amazon.sa
echo 0.0.0.0 bingads.microsoft.com
echo 0.0.0.0 adcash.com
echo 0.0.0.0 taboola.com
echo 0.0.0.0 outbrain.com
echo 0.0.0.0 smartyads.com
echo 0.0.0.0 popads.net
echo 0.0.0.0 adpushup.com
echo 0.0.0.0 trafficforce.com
echo 0.0.0.0 adsterra.com
echo 0.0.0.0 creative.ak.fbcdn.net
echo 0.0.0.0 adbrite.com
echo 0.0.0.0 exponential.com
echo 0.0.0.0 quantserve.com
echo 0.0.0.0 scorecardresearch.com
echo 0.0.0.0 propellerads.com
echo 0.0.0.0 admedia.net
echo 0.0.0.0 admedia.com
echo 0.0.0.0 bidvertiser.com
echo 0.0.0.0 undertone.com
echo 0.0.0.0 web.adblade.com
echo 0.0.0.0 revenuehits.com
echo 0.0.0.0 infolinks.com
echo 0.0.0.0 vibrantmedia.com
echo 0.0.0.0 ads.yahoosmallbusiness.com
echo 0.0.0.0 ads.yahoo.com
echo 0.0.0.0 hilltopads.net
echo 0.0.0.0 clickadu.com
echo 0.0.0.0 citysex.com
echo 0.0.0.0 ad-maven.com
echo 0.0.0.0 propelmedia.com
echo 0.0.0.0 enginemediaexchange.com
echo 0.0.0.0 advertisers.adversense.com
echo 0.0.0.0 a.adtng.com
echo 0.0.0.0 ads.facebook.com
echo 0.0.0.0 an.facebook.com
echo 0.0.0.0 analytics.facebook.com
echo 0.0.0.0 pixel.facebook.com
echo 0.0.0.0 ads.youtube.com
echo 0.0.0.0 youtube.cleverads.vn
echo 0.0.0.0 ads-twitter.com
echo 0.0.0.0 ads-api.twitter.com
echo 0.0.0.0 advertising.twitter.com
echo 0.0.0.0 ads.linkedin.com
echo 0.0.0.0 analytics.pointdrive.linkedin.com
echo 0.0.0.0 ads.reddit.com
echo 0.0.0.0 d.reddit.com
echo 0.0.0.0 rereddit.com
echo 0.0.0.0 events.redditmedia.com
echo 0.0.0.0 analytics.tiktok.com
echo 0.0.0.0 ads.tiktok.com
echo 0.0.0.0 analytics-sg.tiktok.com
echo 0.0.0.0 ads-sg.tiktok.com
)>"%systemdrive%\Windows\System32\Drivers\Etc\hosts"

:: Exit
shutdown /r /t 0