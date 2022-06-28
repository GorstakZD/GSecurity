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

:: Take ownership of Desktop
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Flush DNS Cache
ipconfig /flushdns

:: Remove default user
net user defaultuser1 /delete
net user defaultuser100000 /delete

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

:: Remove random reg keys (Startup/Privacy/Policies/Malware related)
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
reg delete "HKLM\System\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /f
reg delete "HKLM\System\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /f
reg delete "HKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "Execute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /f
reg delete "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /v "StartupPrograms" /f

:: Remove/Rebuild Font Cache
del "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*FontCache*"/s /f /q
del "%WinDir%\System32\FNTCACHE.DAT" /s /f /q

:: Remove Pester
takeown /f "%ProgramFiles%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles%\WindowsPowerShell" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles%\WindowsPowerShell" /s /q
takeown /f "%ProgramFiles(x86)%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles(x86)%\WindowsPowerShell" /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles(x86)%\WindowsPowerShell" /s /q

:: Prevent files from being run/altered/recreated
takeown /f "%WINDIR%\System32\sethc.exe" /a
icacls "%WINDIR%\System32\sethc.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\SysWOW64\sethc.exe" /a
icacls "%WINDIR%\SysWOW64\sethc.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\System32\utilman.exe" /a
icacls "%WINDIR%\System32\utilman.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\SysWOW64\utilman.exe" /a
icacls "%WINDIR%\SysWOW64\utilman.exe" /remove "Administrators" "Authenticated Users" "Users" "System"

:: Pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True

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

:: Lower ram usage and process count
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

:: IPSec
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local" /v "ActivePolicy" /t REG_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /v "className" /t REG_SZ /d "ipsecFilter" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /v "name" /t REG_SZ /d "ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /v "ipsecName" /t REG_SZ /d "All IP Filter List" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /v "ipsecID" /t REG_SZ /d "{45f48cfc-241d-42f7-bcd4-927054db1b67}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /v "ipsecData" /t REG_BINARY /d "b520dc80c82ed111a89e00a0248d302146000000010000000200000000000200000000000200000000005125fa5c69bae64b9f1cd192432c2fee010000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /v "whenChanged" /t REG_DWORD /d "1655772376" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /v "ipsecOwnersReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /v "className" /t REG_SZ /d "ipsecFilter" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /v "name" /t REG_SZ /d "ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /v "ipsecName" /t REG_SZ /d "Blocked IP Filter List" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /v "ipsecID" /t REG_SZ /d "{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /v "ipsecData" /t REG_BINARY /d "b520dc80c82ed111a89e00a0248d3021c008000020000000020000000000020000000000020000000000757925a15f3053418149a2c497624ca201000000000000000000000000000000000000000000000006000000160000000000000002000000000002000000000002000000000098774cc5da9abd4680ecfdd85a24a0360100000000000000000000000000000000000000000000000600000017000000000000000200000000000200000000000200000000003e8a09256115a145bf3e229906e4da8c0100000000000000000000000000000000000000000000000600000087000000000000000200000000000200000000000200000000005e40a4d8e7064049911b62798efdc5c9010000000000000000000000000000000000000000000000060000008900000000000000020000000000020000000000020000000000b294968fb8e52945acca287c74b1834b010000000000000000000000000000000000000000000000060000008a0000000000000002000000000002000000000002000000000021f1448913133b47b7f7e69ad1451684010000000000000000000000000000000000000000000000060000008b000000000000000200000000000200000000000200000000001dd54cc05bdda54da1bd744bbed65b9001000000000000000000000000000000000000000000000006000000bd01000000000000020000000000020000000000020000000000bfec6a7a3d36364ebde879ea93c474640100000000000000000000000000000000000000000000000600000000001600000000000200000000000200000000000200000000000e637263a3dff64b82d36312f130c087010000000000000000000000000000000000000000000000060000000000170000000000020000000000020000000000020000000000e1a875ed0f2f0943a7478f0dcf126c41010000000000000000000000000000000000000000000000060000000000870000000000020000000000020000000000020000000000f83a50795e307340beae751e49c44cb40100000000000000000000000000000000000000000000000600000000008900000000000200000000000200000000000200000000002839488282178e4889799ded5c41372b0100000000000000000000000000000000000000000000000600000000008a000000000002000000000002000000000002000000000010e8e2dad2458745bdbd77cc03ed8e9f0100000000000000000000000000000000000000000000000600000000008b000000000002000000000002000000000002000000000006ee7ce2c753324a98e9f92e7cd603d2010000000000000000000000000000000000000000000000060000000000bd01000000000200000000000200000000000200000000007ddae2ca7d42944b9ef9f4b048cd02910100000000000000000000000000000000000000000000001100000016000000000000000200000000000200000000000200000000006248d976240e8248a91ebfc6bf1a290c010000000000000000000000000000000000000000000000110000001700000000000000020000000000020000000000020000000000c5c6166e1fe6ca4ab8230b3be06dc901010000000000000000000000000000000000000000000000110000008700000000000000020000000000020000000000020000000000500a4b5de38af245beef6f36d887268601000000000000000000000000000000000000000000000011000000890000000000000002000000000002000000000002000000000081f9d93995158341b290bfe6a5bb3473010000000000000000000000000000000000000000000000110000008a0000000000000002000000000002000000000002000000000057786828ed03ea4eafb8a373823164bb010000000000000000000000000000000000000000000000110000008b00000000000000020000000000020000000000020000000000e215652113cf684bb9456148903e542201000000000000000000000000000000000000000000000011000000bd01000000000000020000000000020000000000020000000000365f7e4589fdff4daa9ea710219862c00100000000000000000000000000000000000000000000001100000000001600000000000200000000000200000000000200000000007eec5185dcb1ef4e9cc4d8af0673afa2010000000000000000000000000000000000000000000000110000000000170000000000020000000000020000000000020000000000e65259f9acd2544abf0bf712ee1d7c060100000000000000000000000000000000000000000000001100000000008700000000000200000000000200000000000200000000003878a23ed1dc4944b077f694082208a9010000000000000000000000000000000000000000000000110000000000890000000000020000000000020000000000020000000000177dcf7a8034d44481f44d54bd88e2b80100000000000000000000000000000000000000000000001100000000008a0000000000020000000000020000000000020000000000a497ab261f0dd441b858664f727e54d30100000000000000000000000000000000000000000000001100000000008b0000000000020000000000020000000000020000000000a42f7a9fa5e6ac419dde1c76b9b179a2010000000000000000000000000000000000000000000000110000000000bd010000000002000000000002000000000002000000000028e55ae4f646de44a699dba275475f0601000000c0a800ffffffffff000000000000000000000000000000000000000000000000020000000000020000000000020000000000fc582dfcf979e243927f9ca83bb7c1e701000000c0a801ffffffffff000000000000000000000000000000000000000000000000020000000000020000000000020000000000aeb04974fd39004ca28fb363ae503449010000000000000000000000c0a800ffffffffff00000000000000000000000000000000020000000000020000000000020000000000821729f35021674c8bd8c43648c3f82a010000000000000000000000c0a801ffffffffff00000000000000000000000000000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /v "whenChanged" /t REG_DWORD /d "1656389249" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /v "ipsecOwnersReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /v "className" /t REG_SZ /d "ipsecISAKMPPolicy" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /v "name" /t REG_SZ /d "ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /v "ipsecID" /t REG_SZ /d "{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /v "ipsecData" /t REG_BINARY /d "b820dc80c82ed111a89e00a0248d302180000000000000000000000000000000000000000000000000000000000000000000000000000000807000000000000000000000000000000000000000000000010000000000000003000000000000000000000002000000000000000000000000000000000000000000000000000000020000000000000000000000807000000000000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /v "whenChanged" /t REG_DWORD /d "1654308019" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /v "ipsecOwnersReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "className" /t REG_SZ /d "ipsecNegotiationPolicy" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "name" /t REG_SZ /d "ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "ipsecID" /t REG_SZ /d "{ab61c8e1-10e8-4207-b84d-681caa72b848}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "ipsecNegotiationPolicyAction" /t REG_SZ /d "{8a171dd3-77e3-11d1-8659-a04f00000000}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "ipsecNegotiationPolicyType" /t REG_SZ /d "{62f49e13-6c37-11d1-864c-14a300000000}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "ipsecData" /t REG_BINARY /d "b920dc80c82ed111a89e00a0248d3021a4000000020000000000000000000000000000000000000001000000030000000200000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000002000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "whenChanged" /t REG_DWORD /d "1654308020" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /v "ipsecOwnersReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "className" /t REG_SZ /d "ipsecNegotiationPolicy" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "name" /t REG_SZ /d "ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "ipsecName" /t REG_SZ /d "Block" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "ipsecID" /t REG_SZ /d "{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "ipsecNegotiationPolicyAction" /t REG_SZ /d "{3f91a819-7647-11d1-864d-d46a00000000}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "ipsecNegotiationPolicyType" /t REG_SZ /d "{62f49e10-6c37-11d1-864c-14a300000000}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "ipsecData" /t REG_BINARY /d "b920dc80c82ed111a89e00a0248d3021040000000000000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "whenChanged" /t REG_DWORD /d "1654308646" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /v "ipsecOwnersReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}\0SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /v "className" /t REG_SZ /d "ipsecNFA" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /v "name" /t REG_SZ /d "ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /v "ipsecID" /t REG_SZ /d "{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /v "ipsecData" /t REG_BINARY /d "00acbb118d49d111863900a0248d30212a0000000100000005000000020000000000fdffffff0200000000000000000000000000000000000200000000000101010101010101010101010101010101000000050000000000000001010101010101010101010101010102010000000000000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /v "ipsecNegotiationPolicyReference" /t REG_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNegotiationPolicy{ab61c8e1-10e8-4207-b84d-681caa72b848}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /v "whenChanged" /t REG_DWORD /d "1654308020" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /v "ipsecOwnersReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "className" /t REG_SZ /d "ipsecNFA" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "name" /t REG_SZ /d "ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "ipsecID" /t REG_SZ /d "{78e7557c-d821-4f61-9144-f089c30899f6}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "ipsecData" /t REG_BINARY /d "00acbb118d49d111863900a0248d30212a0000000100000005000000020000000000ffffffff0200000000000000000000000000010000000200000000000101010101010101010101010101010101000000050000000000000001010101010101010101010101010102010000000000000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "ipsecNegotiationPolicyReference" /t REG_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "ipsecFilterReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecFilter{45f48cfc-241d-42f7-bcd4-927054db1b67}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "whenChanged" /t REG_DWORD /d "1656389252" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}" /v "ipsecOwnersReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "className" /t REG_SZ /d "ipsecNFA" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "name" /t REG_SZ /d "ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "ipsecID" /t REG_SZ /d "{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "ipsecData" /t REG_BINARY /d "00acbb118d49d111863900a0248d30212a0000000100000005000000020000000000fdffffff0200000000000000000000000000010000000200000000000101010101010101010101010101010101000000050000000000000001010101010101010101010101010102010000000000000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "ipsecNegotiationPolicyReference" /t REG_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNegotiationPolicy{c4b410bf-dd4c-4275-bedc-abd92cca3f19}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "ipsecFilterReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecFilter{641c767c-fe15-40d4-831d-bd9a5d4fb9cf}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "whenChanged" /t REG_DWORD /d "1656389253" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}" /v "ipsecOwnersReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "className" /t REG_SZ /d "ipsecPolicy" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "name" /t REG_SZ /d "ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "ipsecName" /t REG_SZ /d "GSecurity IP Policy" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "ipsecID" /t REG_SZ /d "{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "ipsecDataType" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "ipsecData" /t REG_BINARY /d "632120224c4fd111863b00a0248d302104000000302a000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "ipsecISAKMPReference" /t REG_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecISAKMPPolicy{e627a7fc-634a-466b-bd85-4b84ffa02dee}" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "whenChanged" /t REG_DWORD /d "1656389252" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy{c0ccd3b2-2871-436c-be91-4e919c8b5aa0}" /v "ipsecNFAReference" /t REG_MULTI_SZ /d "SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNFA{78e7557c-d821-4f61-9144-f089c30899f6}\0SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNFA{7f50b588-f6a5-4187-861f-d7ae6c28f78b}\0SOFTWARE\Policies\Microsoft\Windows\IPSEC\Policy\Local\ipsecNFA{57c1533e-02ee-4ca2-9bc2-69e4b6aaaba2}" /f

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

:: Sign
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "StartMenuLogOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "StartMenuLogOff" /t REG_DWORD /d "1" /f

:: PatchMyPC
curl -# https://patchmypc.com/freeupdater/PatchMyPC.exe -o %userprofile%\Desktop\PatchMyPC.exe

:: Additional tweaks
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "AutofillAddressEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "LocalProvidersEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "ResolveNavigationErrorsUseWebService" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "NetworkPredictionOptions" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSecondsInSystemClock" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "9341288" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "dontdisplaylastusername" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLinkedConnections" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\BootControl" /v "BootProgressAnimation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "ForceEffectMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NoNetCrawling" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Parameters" /v "Hidden" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Network" /v "NoEntireNetwork" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "StartMenuLogOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "StartMenuLogOff" /t REG_DWORD /d "1" /f

::Exit
mshta vbscript:Execute("msgbox ""GSecurity script finished. You should restart your device."":close")
