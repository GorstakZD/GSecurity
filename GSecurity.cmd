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

:: Firewall
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3100}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=bitsadmin.exe (ExploitProtection)|Name=H_C rule for: |EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3101}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Program Files (x86)\Internet Explorer\ExtExport.exe|Name=H_C rule for: ExtExport.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3102}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Program Files (x86)\windows nt\accessories\wordpad.exe|Name=H_C rule for: wordpad.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3103}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Program Files\Internet Explorer\ExtExport.exe|Name=H_C rule for: ExtExport.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3104}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Program Files\windows nt\accessories\wordpad.exe|Name=H_C rule for: wordpad.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3105}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\explorer.exe|Name=H_C rule for: explorer.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3106}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\hh.exe|Name=H_C rule for: hh.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3107}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v2.0.50727\Dfsvc.exe|Name=H_C rule for: Dfsvc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3108}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe|Name=H_C rule for: ieexec.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3109}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe|Name=H_C rule for: InstallUtil.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3110}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v2.0.50727\Msbuild.exe|Name=H_C rule for: Msbuild.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3111}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe|Name=H_C rule for: regasm.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3112}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe|Name=H_C rule for: regsvcs.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3113}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v3.5\Msbuild.exe|Name=H_C rule for: Msbuild.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3114}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\caspol.exe|Name=H_C rule for: caspol.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3115}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe|Name=H_C rule for: csc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3116}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe|Name=H_C rule for: cvtres.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3117}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\Dfsvc.exe|Name=H_C rule for: Dfsvc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3118}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe|Name=H_C rule for: ilasm.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3119}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe|Name=H_C rule for: InstallUtil.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3120}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe|Name=H_C rule for: jsc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3121}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe|Name=H_C rule for: Microsoft.Workflow.Compiler.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3122}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\Msbuild.exe|Name=H_C rule for: Msbuild.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3123}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe|Name=H_C rule for: mscorsvw.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3124}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe|Name=H_C rule for: ngen.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3125}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngentask.exe|Name=H_C rule for: ngentask.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3126}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe|Name=H_C rule for: regasm.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3127}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe|Name=H_C rule for: regsvcs.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3128}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework\v4.0.30319\vbc.exe|Name=H_C rule for: vbc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3129}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Dfsvc.exe|Name=H_C rule for: Dfsvc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3130}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ieexec.exe|Name=H_C rule for: ieexec.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3131}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v2.0.50727\InstallUtil.exe|Name=H_C rule for: InstallUtil.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3132}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Msbuild.exe|Name=H_C rule for: Msbuild.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3133}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe|Name=H_C rule for: regasm.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3134}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe|Name=H_C rule for: regsvcs.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3135}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v3.5\Msbuild.exe|Name=H_C rule for: Msbuild.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3136}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe|Name=H_C rule for: caspol.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3137}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe|Name=H_C rule for: csc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3138}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe|Name=H_C rule for: cvtres.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3139}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Dfsvc.exe|Name=H_C rule for: Dfsvc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3140}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe|Name=H_C rule for: ilasm.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3141}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe|Name=H_C rule for: InstallUtil.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3142}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe|Name=H_C rule for: jsc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3143}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe|Name=H_C rule for: Microsoft.Workflow.Compiler.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3144}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Msbuild.exe|Name=H_C rule for: Msbuild.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3145}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe|Name=H_C rule for: mscorsvw.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3146}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe|Name=H_C rule for: ngen.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3147}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe|Name=H_C rule for: ngentask.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3148}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe|Name=H_C rule for: regasm.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3149}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe|Name=H_C rule for: regsvcs.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3150}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe|Name=H_C rule for: vbc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3151}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\notepad.exe|Name=H_C rule for: notepad.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3152}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\Atbroker.exe|Name=H_C rule for: Atbroker.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3153}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\Attrib.exe|Name=H_C rule for: Attrib.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3154}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\bash.exe|Name=H_C rule for: bash.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3155}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\calc.exe|Name=H_C rule for: calc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3156}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\certoc.exe|Name=H_C rule for: certoc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3157}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\certreq.exe|Name=H_C rule for: certreq.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3158}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\Certutil.exe|Name=H_C rule for: Certutil.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3159}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\cmd.exe|Name=H_C rule for: cmd.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3160}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\Cmstp.exe|Name=H_C rule for: Cmstp.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3161}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\CompatTelRunner.exe|Name=H_C rule for: CompatTelRunner.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3162}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\control.exe|Name=H_C rule for: control.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3163}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\cscript.exe|Name=H_C rule for: cscript.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3164}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ctfmon.exe|Name=H_C rule for: ctfmon.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3165}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\curl.exe|Name=H_C rule for: curl.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3166}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\desktopimgdownldr.exe|Name=H_C rule for: desktopimgdownldr.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3167}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\DeviceDisplayObjectProvider.exe|Name=H_C rule for: DeviceDisplayObjectProvider.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3168}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\dllhost.exe|Name=H_C rule for: dllhost.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3169}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\Dnscmd.exe|Name=H_C rule for: Dnscmd.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3170}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\dwm.exe|Name=H_C rule for: dwm.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3171}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\esentutl.exe|Name=H_C rule for: esentutl.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3172}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\eventvwr.exe|Name=H_C rule for: eventvwr.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3173}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ntoskrnl.exe|Name=Kernel|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3174}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\explorer.exe|Name=H_C rule for: explorer.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3175}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\extrac32.exe|Name=H_C rule for: extrac32.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3176}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\findstr.exe|Name=H_C rule for: findstr.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3177}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\finger.exe|Name=H_C rule for: finger.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3178}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ftp.exe|Name=H_C rule for: ftp.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3179}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\hh.exe|Name=H_C rule for: hh.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3180}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ie4uinit.exe|Name=H_C rule for: ie4uinit.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3181}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ieexec.exe|Name=H_C rule for: ieexec.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3182}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\infdefaultinstall.exe|Name=H_C rule for: infdefaultinstall.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3183}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\lsass.exe|Name=H_C rule for: lsass.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3184}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\makecab.exe|Name=H_C rule for: makecab.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3185}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\mmc.exe|Name=H_C rule for: mmc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3186}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\mshta.exe|Name=H_C rule for: mshta.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3187}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\msiexec.exe|Name=H_C rule for: msiexec.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3188}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\notepad.exe|Name=H_C rule for: notepad.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3189}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\odbcconf.exe|Name=H_C rule for: odbcconf.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3190}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\pcalua.exe|Name=H_C rule for: pcalua.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3191}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\pktmon.exe|Name=H_C rule for: pktmon.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3192}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\PresentationHost.exe|Name=H_C rule for: PresentationHost.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3193}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\print.exe|Name=H_C rule for: print.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3194}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\Register-cimprovider.exe|Name=H_C rule for: Register-cimprovider.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3195}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\regsvr32.exe|Name=H_C rule for: regsvr32.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3196}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\replace.exe|Name=H_C rule for: replace.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3197}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\rundll32.exe|Name=H_C rule for: rundll32.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3198}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\ScriptRunner.exe|Name=H_C rule for: ScriptRunner.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3199}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\services.exe|Name=H_C rule for: services.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3200}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\SyncAppvPublishingServer.exe|Name=H_C rule for: SyncAppvPublishingServer.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3201}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\telnet.exe|Name=H_C rule for: telnet.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3202}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\tftp.exe|Name=H_C rule for: tftp.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3203}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\verclsid.exe|Name=H_C rule for: verclsid.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3204}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\wbem\scrcons.exe|Name=H_C rule for: scrcons.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3205}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\wbem\wmic.exe|Name=H_C rule for: wmic.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3206}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe|Name=H_C rule for: powershell.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3207}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\WindowsPowerShell\v1.0\powershell_ise.exe|Name=H_C rule for: powershell_ise.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3208}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\wininit.exe|Name=H_C rule for: wininit.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3209}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\winlogon.exe|Name=H_C rule for: winlogon.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3210}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\wscript.exe|Name=H_C rule for: wscript.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3211}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\wsl.exe|Name=H_C rule for: wsl.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3212}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\explorer.exe|Name=Explorer|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3213}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\wuauclt.exe|Name=H_C rule for: wuauclt.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3214}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\system32\xwizard.exe|Name=H_C rule for: xwizard.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3215}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\Atbroker.exe|Name=H_C rule for: Atbroker.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3216}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\Attrib.exe|Name=H_C rule for: Attrib.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3217}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\calc.exe|Name=H_C rule for: calc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3218}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\certoc.exe|Name=H_C rule for: certoc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3219}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\certreq.exe|Name=H_C rule for: certreq.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3220}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\Certutil.exe|Name=H_C rule for: Certutil.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3221}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\cmd.exe|Name=H_C rule for: cmd.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3222}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\Cmstp.exe|Name=H_C rule for: Cmstp.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3223}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\control.exe|Name=H_C rule for: control.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3224}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\cscript.exe|Name=H_C rule for: cscript.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3225}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\ctfmon.exe|Name=H_C rule for: ctfmon.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3226}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\curl.exe|Name=H_C rule for: curl.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3227}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\dllhost.exe|Name=H_C rule for: dllhost.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3228}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\Dnscmd.exe|Name=H_C rule for: Dnscmd.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3229}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\dwm.exe|Name=H_C rule for: dwm.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3230}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\esentutl.exe|Name=H_C rule for: esentutl.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3231}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\eventvwr.exe|Name=H_C rule for: eventvwr.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3232}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\expand.exe|Name=H_C rule for: expand.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3233}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\explorer.exe|Name=H_C rule for: explorer.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3234}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\extrac32.exe|Name=H_C rule for: extrac32.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3235}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\findstr.exe|Name=H_C rule for: findstr.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3236}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\finger.exe|Name=H_C rule for: finger.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3237}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\ftp.exe|Name=H_C rule for: ftp.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3238}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\hh.exe|Name=H_C rule for: hh.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3239}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\Ie4uinit.exe|Name=H_C rule for: Ie4uinit.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3240}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\ieexec.exe|Name=H_C rule for: ieexec.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3241}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\Infdefaultinstall.exe|Name=H_C rule for: Infdefaultinstall.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3242}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\makecab.exe|Name=H_C rule for: makecab.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3243}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\mmc.exe|Name=H_C rule for: mmc.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3244}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\mshta.exe|Name=H_C rule for: mshta.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3245}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\msiexec.exe|Name=H_C rule for: msiexec.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3246}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\notepad.exe|Name=H_C rule for: notepad.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3247}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\odbcconf.exe|Name=H_C rule for: odbcconf.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3248}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\PresentationHost.exe|Name=H_C rule for: PresentationHost.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3249}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\print.exe|Name=H_C rule for: print.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3250}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\Register-cimprovider.exe|Name=H_C rule for: Register-cimprovider.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3251}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\regsvr32.exe|Name=H_C rule for: regsvr32.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3252}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\replace.exe|Name=H_C rule for: replace.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3253}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\rundll32.exe|Name=H_C rule for: rundll32.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3254}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\ScriptRunner.exe|Name=H_C rule for: ScriptRunner.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3255}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\SyncAppvPublishingServer.exe|Name=H_C rule for: SyncAppvPublishingServer.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3256}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\telnet.exe|Name=H_C rule for: telnet.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3257}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\tftp.exe|Name=H_C rule for: tftp.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3258}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\verclsid.exe|Name=H_C rule for: verclsid.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3259}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\wbem\wmic.exe|Name=H_C rule for: wmic.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3260}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe|Name=H_C rule for: powershell.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3261}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe|Name=H_C rule for: powershell_ise.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3262}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\wscript.exe|Name=H_C rule for: wscript.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3263}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\wsmprovhost.exe|Name=H_C rule for: wsmprovhost.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3264}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\wuauclt.exe|Name=H_C rule for: wuauclt.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{f016bbe0-a716-428b-822e-5E544B6A3265}" /t REG_SZ /d "v2.29|Action=Block|Active=TRUE|Dir=Out|App=C:\Windows\SysWOW64\xwizard.exe|Name=H_C rule for: xwizard.exe|EmbedCtxt=H_C Firewall Rules|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{1E78ACD0-2EB2-4C5B-BE1E-C3AF5786D813}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=TCP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{7647502E-A6B0-4DCD-BD65-6B0E48EEFDF7}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55556-65535|Name=UDP|EmbedCtxt=GSecurity|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d "0" /f

:: Software restriction policy
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "DefaultLevel" /t REG_DWORD /d "262144" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "TransparentEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "PolicyScope" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "ExecutableTypes" /t REG_MULTI_SZ /d "ADE\0ADP\0BAS\0BAT\0CHM\0CMD\0COM\0CPL\0CRT\0EXE\0HLP\0HTA\0INF\0INS\0ISP\0LNK\0MDB\0MDE\0MSC\0MSI\0MSP\0MST\0OCX\0PCD\0PIF\0REG\0SCR\0SHS\0URL\0VB\0WSC" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{3913d719-a28e-4fd6-9d9c-1de7499244f5}" /v "Description" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{3913d719-a28e-4fd6-9d9c-1de7499244f5}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{3913d719-a28e-4fd6-9d9c-1de7499244f5}" /v "ItemData" /t REG_SZ /d "smb*" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths" /f

:: Disable mitigations
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 4 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 4 /f

:: RunOnce
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\" /v Start /t REG_DWORD /f /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v "ShutdownWithoutLogon" /t REG_DWORD /f /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v "DontDisplayLastUserName" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass\" /v "UserAuthPolicy" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass\" /v "BluetoothPolicy" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\.DEFAULT\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32\" /v "\" /t REG_SZ /f /d "\" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\" /v "AppsUseLightTheme" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\" /v "SystemUsesLightTheme" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" /v "GlobalUserDisabled" /t REG_DWORD /f /d "1" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\International\User Profile\" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /f /d "1" /f
Reg.exe add "HKU\S-1-5-18\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32\" /v "\" /t REG_SZ /f /d "\" /f
Reg.exe add "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\" /v "AppsUseLightTheme" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\" /v "SystemUsesLightTheme" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" /v "GlobalUserDisabled" /t REG_DWORD /f /d "1" /f
Reg.exe add "HKU\S-1-5-18\Control Panel\International\User Profile\" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /f /d "1" /f
Reg.exe add "HKU\S-1-5-19\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32\" /v "\" /t REG_SZ /f /d "\" /f
Reg.exe add "HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\" /v "AppsUseLightTheme" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\" /v "SystemUsesLightTheme" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" /v "GlobalUserDisabled" /t REG_DWORD /f /d "1" /f
Reg.exe add "HKU\S-1-5-19\Control Panel\International\User Profile\" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /f /d "1" /f
Reg.exe add "HKU\S-1-5-20\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32\" /v "\" /t REG_SZ /f /d "\" /f
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\" /v "AppsUseLightTheme" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\" /v "SystemUsesLightTheme" /t REG_DWORD /f /d "0" /f
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" /v "GlobalUserDisabled" /t REG_DWORD /f /d "1" /f
Reg.exe add "HKU\S-1-5-20\Control Panel\International\User Profile\" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /f /d "1" /f

:: Ifeo
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" /v "MitigationOptions" /t REG_QWORD /d "0x0000000000000100" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fontview.exe" /v "MitigationOptions" /t REG_QWORD /d "0x0000000000000100" /f

:: Scheduler
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Task Scheduler5.0" /v "Task Creation" /t REG_DWORD /d "0" /f

:: Terminal services
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fallowfullcontrol" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fallowunsolicitedfullcontrol" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fusemailto" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "maxticketexpiry" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "maxticketexpiryunits" /f
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
Reg.exe delete "HKLM\software\policies\microsoft\windows nt\terminal services\client" /v "fusbredirectionenablemode" /f
Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services\client" /f

:: Performance
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

:: Ads block
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /t REG_SZ /d "https://raw.githubusercontent.com/GorstakZD/Pac/main/GSecurity.pac" /f

:: Exit
popd
shutdown -r -t 0
