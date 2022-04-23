@echo off
title GSecurity & color 0b

:: Elevate
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

:: Set scriptdir as active
pushd %~dp0

:: Remove random reg keys (Startup/Privacy/Policies/Malware related)
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Command Processor" /v "AutoRun" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "Load" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
Reg.exe delete "HKEY_CURRENT_USER\Software\Policies" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Command Processor" /v "AutoRun" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Policies" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Tracing" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Policies" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Policies" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Tracing" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Policies" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\winreg" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "Execute" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /v "StartupPrograms" /f

:: Remove random files/folders
del "%AppData%\Microsoft\Windows\Recent\*" /s /f /q
del "%WINDIR%\System32\sru\*" /s /f /q
rd "%SystemDrive%\AMD" /s /q
rd "%SystemDrive%\PerfLogs" /s /q
rd "%SystemDrive%\Recovery" /s /q
rd "%ProgramData%\Microsoft\Diagnosis" /s /q
rd "%ProgramData%\Microsoft\Search" /s /q
rd "%ProgramData%\Microsoft\Windows Security Health" /s /q
rd "%AppData%\ArtifexMundi\SparkPromo" /s /q
rd "%LocalAppData%\MicrosoftEdge" /s /q
rd "%LocalAppData%\Microsoft\Internet Explorer" /s /q
rd "%LocalAppData%\Microsoft\Windows\AppCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\History" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatUaCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCookies" /s /q
rd "%LocalAppData%\Microsoft\Windows\WebCache" /s /q
rd "%LocalAppData%\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AppData\Indexed DB" /s /q

:: Restore essential startup entries
bcdedit /deletevalue {current} safeboot
bcdedit /deletevalue {current} safebootalternateshell
bcdedit /deletevalue {current} removememory
bcdedit /deletevalue {current} truncatememory
bcdedit /deletevalue {current} useplatformclock
bcdedit /deletevalue {default} safeboot
bcdedit /deletevalue {default} safebootalternateshell
bcdedit /deletevalue {default} removememory
bcdedit /deletevalue {default} truncatememory
bcdedit /deletevalue {default} useplatformclock
bcdedit /set {bootmgr} displaybootmenu no
bcdedit /set {bootmgr} flightsigning off
bcdedit /set {current} advancedoptions false
bcdedit /set {current} bootems no
bcdedit /set {current} bootmenupolicy legacy
bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
bcdedit /set {current} disabledynamictick no
bcdedit /set {current} recoveryenabled no
bcdedit /set {current} advancedoptions false
bcdedit /set {current} bootems no
bcdedit /set {current} bootmenupolicy legacy
bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
bcdedit /set {current} useplatformtick no
bcdedit /set {current} useplatformclock yes
bcdedit /set {current} recoveryenabled no
bcdedit /set {current} hypervisorlaunchtype off
bcdedit /set {current} lastknowngood yes
bcdedit /set {current} quietboot yes
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\System32\userinit.exe," /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /t REG_MULTI_SZ /d "" /f

:: Remove user account
net user defaultuser0 /delete

:: Prevent files from being run/altered/recreated
takeown /f "%WINDIR%\System32\sethc.exe" /a
icacls "%WINDIR%\System32\sethc.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\SysWOW64\sethc.exe" /a
icacls "%WINDIR%\SysWOW64\sethc.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\System32\utilman.exe" /a
icacls "%WINDIR%\System32\utilman.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\SysWOW64\utilman.exe" /a
icacls "%WINDIR%\SysWOW64\utilman.exe" /remove "Administrators" "Authenticated Users" "Users" "System"

:: 0 - Use Autoplay for all media and devices
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "0" /f 

:: Disable AutoRun
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f

:: Diagnostic and usage data - Select how much data you send to Microsoft / 0 - Security (Not aplicable on Home/Pro, it resets to Basic) / 1 - Basic / 2 - Enhanced (Hidden) / 3 - Full
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f

:: 1 - Let Microsoft provide more tailored experiences with relevant tips and recommendations by using your diagnostic data
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f

:: Feedback Frequency - Windows should ask for my feedback: 0 - Never / Removed - Automatically
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f

:: 2 - Enable Num Lock on Sign-in Screen / 2147483648 - Disable
Reg.exe add "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Input" /v "InputServiceEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Input" /v "InputServiceEnabledForCCI" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f

:: Autocorrect misspelled words (Privacy)
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f

:: Highlight misspelled words (Privacy)
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f

:: Show text suggestions as I type on the software keyboard (Privacy)
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f

:: Add a space after I choose a text suggestion (Privacy)
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f

:: Add a period after I double-tap the Spacebar (Privacy)
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f

:: Show recommended app suggestions (Privacy)
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f

:: Sticky Keys / 26 - Disable All / 511 - Default
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "26" /f

:: Let apps control radios / 0 - Default / 1 - Enabled / 2 - Disabled
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d "2" /f

:: Networking Tweaks
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f

:: n - Disable Background disk defragmentation / y - Enable How long in milliseconds you want to have for a startup delay time for desktop apps that run at startup to load
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "n" /f

:: 0 - Disable Background auto-layout / Disable Optimize Hard Disk when idle
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\OptimalLayout" /v "EnableAutoLayout" /t REG_DWORD /d "0" /f

:: Disable Automatic Maintenance / Scheduled System Maintenance
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f

:: 0 - Enables 8dot3 name creation for all volumes on the system / 1 - Disables 8dot3 name creation for all volumes on the system / 2 - Sets 8dot3 name creation on a per volume basis / 3 - Disables 8dot3 name creation for all volumes except the system volume
:: fsutil 8dot3name scan c:\
fsutil behavior set disable8dot3 1

:: 1 - Disable the Encrypting File System (EFS)
fsutil behavior set disableencryption 1

:: 1 - When listing directories, NTFS does not update the last-access timestamp, and it does not record time stamp updates in the NTFS log
fsutil behavior set disablelastaccess 0

:: 5 - 5 secs / Delay Chkdsk startup time at OS Boot
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "AutoChkTimeout" /t REG_DWORD /d "0" /f

:: 0 - Establishes a standard size file-system cache of approximately 8 MB / 1 - Establishes a large system cache working set that can expand to physical memory, minus 4 MB, if needed
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f

:: 0 - Drivers and the kernel can be paged to disk as needed / 1 - Drivers and the kernel must remain in physical memory
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "0" /f

:: 0 - Disable Prefetch / 1 - Enable Prefetch when the application starts / 2 - Enable Prefetch when the device starts up / 3 - Enable Prefetch when the application or device starts up
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "3" /f

:: 0 - Disable SuperFetch / 1 - Enable SuperFetch when the application starts up / 2 - Enable SuperFetch when the device starts up / 3 - Enable SuperFetch when the application or device starts up
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "3" /f

:: 0 - Disable It / 1 - Default
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f

:: 0 - Disable Fast Startup for a Full Shutdown / 1 - Enable Fast Startup (Hybrid Boot) for a Hybrid Shutdown
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsAllowExtendedCharacter8dot3Rename" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ExistingPageFiles" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "y" /f

:: Block all inbound network traffic and all outbound except allowed apps
netsh advfirewall set DomainProfile firewallpolicy blockinboundalways,blockoutbound
netsh advfirewall set PrivateProfile firewallpolicy blockinboundalways,blockoutbound
netsh advfirewall set PublicProfile firewallpolicy blockinbound,allowoutbound

:: Remove All Windows Firewall Rules
netsh advfirewall firewall delete rule name=all

:: Logging
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\CShellCircular" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" /v "Start" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\FaceRecoTel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\FaceUnlock" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\NetCore" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f

:: Disable Microsoft Support Diagnostic Tool MSDT
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f

:: Disable System Debugger (Dr. Watson)
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f

:: 1 - Disable Windows Error Reporting (WER)
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f

:: DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f

:: 1 - Disable WER sending second-level data
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f

:: 1 - Disable WER crash dialogs, popups
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f

:: 1 - Disable WER logging
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

:: Windows Error Reporting Service
sc config WerSvc start= disabled

:: Remove Windows Errror Reporting (to restore run "sfc /scannow")
takeown /f "%WinDir%\System32\WerFault.exe" /a
icacls "%WinDir%\System32\WerFault.exe" /grant:r Administrators:F /c
taskkill /im WerFault.exe /f
del "%WinDir%\System32\WerFault.exe" /s /f /q

:: 1 - Show hidden files, folders and drives
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f

:: 0 - Show extensions for known file types
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f

:: 0 - Hide protected operating system files 
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f

:: 1 - Launch folder windows in a separate process
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "1" /f

:: 1 - Show Sync Provider Notifications in Windows Explorer (ADs)
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f

:: 1 - Use Sharing Wizard
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0" /f

:: Navigation pane - 1 - Expand to open folder
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneExpandToCurrentFolder" /t REG_DWORD /d "0" /f

:: 0 - All of the components of Windows Explorer run a single process / 1 - All instances of Windows Explorer run in one process and the Desktop and Taskbar run in a separate process
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f

:: Yes - Use Inline AutoComplete in File Explorer and Run Dialog / No
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_SZ /d "No" /f

:: 0 - Do this for all current items checkbox / 1 - Disabled
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "ConfirmationCheckBoxDoForAll" /t REG_DWORD /d "0" /f

:: 1 - Always show more details in copy dialog
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "1" /f

:: 1 - Display confirmation dialog when deleting files
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ConfirmFileDelete" /t REG_DWORD /d "1" /f

:: 1075839525 - Auto arrange icons and Align icons to grid on Desktop / 1075839520 / 1075839521 / 1075839524
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags\1\Desktop" /v "FFlags" /t REG_DWORD /d "1075839525" /f

:: SSRP
Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\safer" /f

:: Pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True

:: 0 - Foreground and background applications equally responsive / 1 - Foreground application more responsive than background / 2 - Best foreground application response time (Default)
:: 38 - Adjust for best performance of Programs / 24 - Adjust for best performance of Background Services
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation " /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f

:: System Restore
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f
Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /v " {09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}" /t REG_MULTI_SZ /d "1" /f
schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Enable
vssadmin Resize ShadowStorage /For=C: /On=C: /Maxsize=5GB
sc config wbengine start= demand
sc config swprv start= demand
sc config vds start= demand
sc config VSS start= demand

:: Reduce windows size
vssadmin delete shadows /all /quiet
dism /online /cleanup-image /startcomponentcleanup /resetbase

:: 1 - Disable File History (Creating previous versions of files/Windows Backup)
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f

:: Tasks
schtasks /DELETE /TN "Adobe Flash Player PPAPI Notifier" /f
schtasks /DELETE /TN "Adobe Flash Player Updater" /f
schtasks /DELETE /TN "AMDLinkUpdate" /f
schtasks /DELETE /TN "Driver Easy Scheduled Scan" /f
schtasks /DELETE /TN "GPU Tweak II" /f
schtasks /DELETE /TN "klcp_update" /f
schtasks /DELETE /TN "ModifyLinkUpdate" /f
schtasks /DELETE /TN "Repairing Yandex Browser update service" /f
schtasks /DELETE /TN "StartDVR" /f
schtasks /DELETE /TN "StartCN" /f
schtasks /DELETE /TN "System update for Yandex Browser" /f
schtasks /DELETE /TN "Update for Yandex Browser" /f
schtasks /Change /TN "CreateExplorerShellUnelevatedTask" /Enable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\appuriverifierdaily" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\appuriverifierinstall" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\CleanupTemporaryState" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\DsSvcCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdates" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdatesAsUser" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndContinueUpdates" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndScanForUpdates" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\SmartRetry" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\WindowsActionDialog" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\HeadsetButtonPress" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Subscription\EnableLicenseAcquisition" /Disable
schtasks /Change /TN "Microsoft\Windows\Subscription\LicenseAcquisition" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\USB\Usb-Notifications" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable

:: Save space
dism.exe /Image:C:\test\offline /Cleanup-Image /StartComponentCleanup
compact /s:%SystemDrive%\Windows\WinSxs\ /c /a /i /EXE:xpress16k

:: Label
label %SystemDrive% Windows

:: Machine policy
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseAdvancedStartup" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "EnableBDEWithNoTPM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseTPM" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseTPMPIN" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseTPMKey" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseTPMKeyPIN" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CRLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CTLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\Certificates" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CRLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CTLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\CRLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\CTLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\Certificates" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\CRLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\CTLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\TPM" /v "OSManagedAuthLevel" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowSavedCredentials" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "ConcatenateDefaults_AllowSaved" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowFreshCredentials" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "ConcatenateDefaults_AllowFresh" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowDefaultCredentials" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "ConcatenateDefaults_AllowDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CallLegacyWCMPolicies" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "ConfigureSystemGuardLaunch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_PersonalFirewallConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" /v "AllowRemoteDASD" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" /v "Deny_All" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}" /v "Deny_Write" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}" /v "Deny_Write" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "EnableBackupForWin8Apps" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Fdeploy" /v "PrimaryComputerEnabledFR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TenantRestrictions\Payload\PreventPolicyKeyDelete" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local" /v "WCMPresent" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WSDAPI\Discovery Proxies" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "RegisterSpoolerRemoteRpcEndPoint" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v "IgnoreDelegationFailure" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v "RestrictRemoteClients" /t REG_DWORD /d "0" /f
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
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbBlockDeviceBySetupClasses" /v "1000" /t REG_SZ /d "{3376f4ce-ff8d-40a2-a80f-bb4359d1415c}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbSelectDeviceByInterfaces" /v "1000" /t REG_SZ /d "{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection" /v "KnownDllList" /t REG_SZ /d "nlhtml.dll" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d "0" /f

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

:: Exit
popd
exit