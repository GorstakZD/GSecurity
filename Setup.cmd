@echo off
title GSecurity & color 0b

:: elevation
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

:: perms
c:
cd\
takeown /f c:
icacls c: /inheritance:e /grant:r %username%:(OI)(CI)F
icacls c: /inheritance:e /remove "CREATOR OWNER"
icacls c: /inheritance:e /remove "*S-1-15-2-1"
icacls c: /inheritance:e /remove "*S-1-15-2-2"

:: recycle bin
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume" /f
regini GSecurity.txt
rd "A:\$Recycle.bin" /s /q
rd "B:\$Recycle.bin" /s /q
rd "C:\$Recycle.bin" /s /q
rd "D:\$Recycle.bin" /s /q
rd "E:\$Recycle.bin" /s /q
rd "F:\$Recycle.bin" /s /q
rd "G:\$Recycle.bin" /s /q
rd "H:\$Recycle.bin" /s /q
rd "I:\$Recycle.bin" /s /q
rd "J:\$Recycle.bin" /s /q
rd "K:\$Recycle.bin" /s /q
rd "L:\$Recycle.bin" /s /q
rd "M:\$Recycle.bin" /s /q
rd "N:\$Recycle.bin" /s /q
rd "O:\$Recycle.bin" /s /q
rd "P:\$Recycle.bin" /s /q
rd "Q:\$Recycle.bin" /s /q
rd "R:\$Recycle.bin" /s /q
rd "S:\$Recycle.bin" /s /q
rd "T:\$Recycle.bin" /s /q
rd "U:\$Recycle.bin" /s /q
rd "V:\$Recycle.bin" /s /q
rd "W:\$Recycle.bin" /s /q
rd "X:\$Recycle.bin" /s /q
rd "Y:\$Recycle.bin" /s /q
rd "Z:\$Recycle.bin" /s /q

:: Take ownership of Desktop
takeown /s %computername% /u %username% /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /s %computername% /u %username% /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Protect logon
takeown /s %computername% /u %username% /f "%SystemDrive%\Windows\System32\winlogon.exe" /r /d y
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /remove "ALL APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /remove "ALL RESTRICTED APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /remove "Users"
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /remove "TrustedInstaller"
icacls %SystemDrive%\Windows\System32\winlogon.exe /inheritance:e /deny "NETWORK":(OI)(CI)F /t /l /q /c

takeown /s %computername% /u %username% /f "%SystemDrive%\Windows\System32\logonui.exe" /r /d y
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /remove "ALL APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /remove "ALL RESTRICTED APPLICATION PACKAGES"
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /remove "Users"
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /remove "TrustedInstaller"
icacls %SystemDrive%\Windows\System32\logonui.exe /inheritance:e /deny "NETWORK":(OI)(CI)F /t /l /q /c

:: Flush DNS Cache
ipconfig /flushdns

:: Remove default user
net user defaultuser0 /delete

:: Remove random files/folders
del "%AppData%\Microsoft\Windows\Recent\*" /s /f /q
del "%LocalAppData%\Microsoft\Windows\ActionCenterCache" /s /f /q
del "%SystemDrive%\AMFTrace.log" /s /f /q
del "%WINDIR%\System32\sru\*" /s /f /q
rd "%SystemDrive%\AMD" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q
rd "%SystemDrive%\PerfLogs" /s /q
rd "%SystemDrive%\Recovery" /s /q
rd "%ProgramData%\Microsoft\Diagnosis" /s /q
rd "%ProgramData%\Microsoft\DiagnosticLogCSP" /s /q
rd "%ProgramData%\Microsoft\Network" /s /q
rd "%ProgramData%\Microsoft\Search" /s /q
rd "%ProgramData%\Microsoft\SmsRouter" /s /q
rd "%AppData%\AMD" /s /q
rd "%AppData%\ArtifexMundi\SparkPromo" /s /q
rd "%LocalAppData%\Microsoft\Internet Explorer" /s /q
rd "%LocalAppData%\Microsoft\Windows\AppCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\History" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatUaCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCookies" /s /q
rd "%LocalAppData%\Microsoft\Windows\WebCache" /s /q
rd "%LocalAppData%\Steam\htmlcache" /s /q
rd "%LocalAppData%\Temp" /s /q
rd "C:\Users\Tairi\3D Objects" /s /q
rd "C:\Users\Tairi\Favorites" /s /q
rd "C:\Users\Tairi\Links" /s /q
rd "C:\Users\Tairi\Music" /s /q
rd "C:\Users\Tairi\Searches" /s /q
rd "D:\OneDriveTemp" /s /q

:: Remove/Rebuild Font Cache
del "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*FontCache*"/s /f /q
del "%WinDir%\System32\FNTCACHE.DAT" /s /f /q

:: Remove terminal
powershell -command "Remove-appxpackage Microsoft.WindowsTerminal -allusers"
powershell -command "Remove-provisionedappxpackage Microsoft.WindowsTerminal -online"

:: Remove group policy
FOR %%F IN ("%SystemDrive%\Windows\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (DISM /Online /NoRestart /Remove-Package:"%F")
FOR %%F IN ("%SystemDrive%\Windows\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (DISM /Online /NoRestart /Remove-Package:"%F")

:: Remove random reg keys (Startup/Privacy/Policies/Malware related)
reg delete "HKCU\Software\Classes\ms-settings\shell\open" /f
reg delete "HKCU\Software\Microsoft\Command Processor" /v "AutoRun" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "Load" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKCU\Software\Policies" /f
reg delete "HKLM\Software\Microsoft\Command Processor" /v "AutoRun" /f
reg delete "HKLM\Software\Microsoft\Policies" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
reg delete "HKLM\Software\Policies" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Policies" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
reg delete "HKLM\Software\WOW6432Node\Policies" /f
reg delete "HKLM\System\CurrentControlSet\Control\Keyboard "Layout" /v "Scancode Map" /f
reg delete "HKLM\System\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /f
reg delete "HKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "Execute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /f
reg delete "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /v "StartupPrograms" /f

:: Restore essential startup entries
bcdedit /deletevalue safeboot
bcdedit /deletevalue safebootalternateshell
bcdedit /deletevalue removememory
bcdedit /deletevalue truncatememory
bcdedit /deletevalue useplatformclock
bcdedit /set hypervisorlaunchtype off
Bcdedit /set flightsigning off
bcdedit /set {bootmgr} displaybootmenu no
Bcdedit /set {bootmgr} flightsigning off
bcdedit /set advancedoptions false
bcdedit /set bootems no
bcdedit /set bootmenupolicy legacy
bcdedit /set bootstatuspolicy IgnoreAllFailures
bcdedit /set disabledynamictick yes
bcdedit /set lastknowngood yes
bcdedit /set recoveryenabled no
bcdedit /set quietboot yes
bcdedit /set useplatformtick yes
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Discord" /t REG_SZ /d "%LocalAppData%\Discord\app-1.0.9004\Discord.exe --start-minimized" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Process Hacker" /t REG_SZ /d "%ProgramFiles%\Process Hacker\ProcessHacker.exe -hide" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Steam" /t REG_SZ /d "D:\Steam\steam.exe -silent"
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /t REG_SZ /d "\"%ProgramFiles%\Microsoft OneDrive\OneDrive.exe\" /background" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Malwarebytes Windows Firewall Control" /t REG_SZ /d "\"%ProgramFiles%\Malwarebytes\Windows Firewall Control\wfc.exe"\" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\System32\userinit.exe," /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /t REG_MULTI_SZ /d "" /f

:: block ads
wmic nicconfig where DHCPEnabled=TRUE call SetDNSServerSearchOrder ("45.90.28.223","76.76.19.19","94.140.14.14")

:: turn off network discovery
netsh advfirewall firewall set rule group="Network Discovery" new enable=No

:: registry
reg import %~dp0GSecurity.reg

:: security policy
secedit.exe /configure /db %windir%\security\local.sdb /cfg %~dp0GSecurity.inf

:: exit
popd
exit