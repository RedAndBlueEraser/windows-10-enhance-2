<#
windows-10-enhance-privacy-and-control.ps1
Version 20201229
Written by Harry Wong (RedAndBlueEraser)
#>

<#
.SYNOPSIS
A PowerShell script to automatically configure for the highest privacy and control settings in Windows 10.
.DESCRIPTION
This script minimises telemetry and data collection sent to Microsoft and third parties, removes advertising elements, and uninstalls useless apps.
.PARAMETER EditGroupPolicies
Edits the group policy (via the registry) in addition to toggling settings. This prevents the user from being able to toggle some settings through the UI. Precaution should be taken when using this option in conjunction with higher optimisation levels. Some tweaks are only available by editing Group Policies while some settings are not controlled by any Group Policy.
.PARAMETER AggressiveOptimization
By default, the standard optimisation only changes settings that should not impact any functionality. For example: turning off telemetry data collection, disabling advertising elements, and tightening privacy controls. Aggressive optimisation goes further by turning off privacy intrusive, yet unlikely to be useful, features.
.EXAMPLE
./windows-10-enhance-privacy-and-control.ps1
Configure while avoid making changes that remove or disable features or functions, such as Cortana and shared experiences.
.EXAMPLE
./windows-10-enhance-privacy-and-control.ps1 -EditGroupPolicies
Configure by editing the group policy (via the registry) in addition to toggling settings while avoid making changes that remove or disable features or functions, such as Cortana and shared experiences.
.EXAMPLE
./windows-10-enhance-privacy-and-control.ps1 -AggressiveOptimization
Configure aggressively, making changes that remove or disable features or functions, such as Cortana and shared experiences.
.EXAMPLE
./windows-10-enhance-privacy-and-control.ps1 -AggressiveOptimization -EditGroupPolicies
Configure aggressively, by editing the group policy (via the registry) in addition to toggling settings, making changes that remove or disable features or functions, such as Cortana and shared experiences.
#>

Param(
    [switch]$editGroupPolicies,
    [switch]$aggressiveOptimization,

    [bool]$windowsWelcomeExperience = $true,
    [bool]$finishSettingUpDevice = $true,
    [bool]$tipsTricksSuggestions = $true,
    [bool]$timelineSuggestions = $true,
    [bool]$sharedDevices = $aggressiveOptimization.isPresent,
    [bool]$clipboardHistory = $aggressiveOptimization.isPresent,
    [bool]$clipboardSync = $aggressiveOptimization.isPresent,
    [bool]$swiftPair = $true,
    [bool]$windowsInkWorkspaceRecommendedApps = $true,
    [bool]$phone = $aggressiveOptimization.isPresent,
    [bool]$wiFiSense = $true,
    [bool]$hotspot20Networks = $true,
    [bool]$lockScreenBackground = $true,
    [bool]$lockScreenFunFactsTips = $true,
    [bool]$startSuggestions = $true,
    [bool]$myPeopleAppSuggestions = $true,

    [bool]$apps3DBuilder                    = $aggressiveOptimization.isPresent,
    [bool]$appsAlarmsClock                  = $false,
    [bool]$appsAppConnector                 = $false,
    [bool]$appsAppInstaller                 = $false,
    [bool]$appsAsphalt8Airborne             = $aggressiveOptimization.isPresent,
    [bool]$appsCalculator                   = $false,
    [bool]$appsCamera                       = $false,
    [bool]$appsCandyCrushSodaSaga           = $aggressiveOptimization.isPresent,
    [bool]$appsConnect                      = $false,
    [bool]$appsDrawboardPDF                 = $aggressiveOptimization.isPresent,
    [bool]$appsFacebook                     = $aggressiveOptimization.isPresent,
    [bool]$appsFalloutShelter               = $aggressiveOptimization.isPresent,
    [bool]$appsFarmVille2CountryEscape      = $aggressiveOptimization.isPresent,
    [bool]$appsFeedbackHub                  = $true,
    [bool]$appsGetHelp                      = $aggressiveOptimization.isPresent,
    [bool]$appsGetOffice                    = $true,
    [bool]$appsGrooveMusic                  = $false,
    [bool]$appsHEIFImageExtensions          = $false,
    [bool]$appsMailAndCalendar              = $false,
    [bool]$appsMaps                         = $false,
    [bool]$appsMessaging                    = $false,
    [bool]$appsMicrosoftEdge                = $false,
    [bool]$appsMicrosoftSolitaireCollection = $aggressiveOptimization.isPresent,
    [bool]$appsMicrosoftStore               = $false,
    [bool]$appsMicrosoftWallet              = $false,
    [bool]$appsMicrosoftWiFi                = $aggressiveOptimization.isPresent,
    [bool]$appsMinecraft                    = $aggressiveOptimization.isPresent,
    [bool]$appsMixedRealityViewer           = $false,
    [bool]$appsMixedRealityPortal           = $false,
    [bool]$appsMoney                        = $aggressiveOptimization.isPresent,
    [bool]$appsMoviesTV                     = $false,
    [bool]$appsNetflix                      = $aggressiveOptimization.isPresent,
    [bool]$appsNews                         = $aggressiveOptimization.isPresent,
    [bool]$appsOneDrive                     = $aggressiveOptimization.isPresent,
    [bool]$appsOneNote                      = $aggressiveOptimization.isPresent,
    [bool]$appsPaidWiFiCellular             = $false,
    [bool]$appsPaint3D                      = $false,
    [bool]$appsPandora                      = $aggressiveOptimization.isPresent,
    [bool]$appsPeople                       = $false,
    [bool]$appsPhone                        = $false,
    [bool]$appsPhoneCompanion               = $false,
    [bool]$appsPhotos                       = $false,
    [bool]$appsPrint3D                      = $false,
    [bool]$appsRoyalRevolt2                 = $aggressiveOptimization.isPresent,
    [bool]$appsScan                         = $false,
    [bool]$appsSnipSketch                   = $false,
    [bool]$appsSkype                        = $aggressiveOptimization.isPresent,
    [bool]$appsSports                       = $aggressiveOptimization.isPresent,
    [bool]$appsStickyNotes                  = $false,
    [bool]$appsSway                         = $aggressiveOptimization.isPresent,
    [bool]$appsTips                         = $aggressiveOptimization.isPresent,
    [bool]$appsTwitter                      = $aggressiveOptimization.isPresent,
    [bool]$appsVoiceRecorder                = $false,
    [bool]$appsView3D                       = $aggressiveOptimization.isPresent,
    [bool]$appsWeather                      = $aggressiveOptimization.isPresent,
    [bool]$appsWebMediaExtensions           = $false,
    [bool]$appsWebpImageExtensions          = $false,
    [bool]$appsWindowsPhone                 = $aggressiveOptimization.isPresent,
    [bool]$appsWindowsPhoneConnector        = $aggressiveOptimization.isPresent,
    [bool]$appsXbox                         = $aggressiveOptimization.isPresent,
    [bool]$appsXboxGameSpeechWindows        = $aggressiveOptimization.isPresent,
    [bool]$appsXboxLive                     = $aggressiveOptimization.isPresent,
    [bool]$appsXboxOneSmartGlass            = $aggressiveOptimization.isPresent,

    [bool]$autoUpdateMaps = $aggressiveOptimization.isPresent,
    [bool]$showAccountDetails = $aggressiveOptimization.isPresent,
    [bool]$useSignInInfoToFinishSetup = $aggressiveOptimization.isPresent,
    [bool]$syncSettings = $aggressiveOptimization.isPresent,
    [bool]$truePlay = $true,
    [bool]$narratorGetImageTitlesLinks = $true,
    [bool]$narratorSendMoreDiagPerfData = $true,
    [bool]$searchMicrosoftAccount = $true,
    [bool]$searchWorkSchoolAccount = $true,
    [bool]$searchHistory = $true,
    [bool]$advertisingId = $true,
    [bool]$locallyRelevantContent = $true,
    [bool]$trackAppLaunches = $true,
    [bool]$settingsSuggestedContent = $true,
    [bool]$turnOffSpeechAndTypingSuggestions = $true,
    [bool]$diagnosticData = $true,
    [bool]$sendInkingTypingData = $true,
    [bool]$tailoredExperiences = $true,
    [bool]$feedbackFrequency = $true,
    [bool]$activitiesCollect = $true,
    [bool]$activitiesSync = $true,
    [bool]$location = $aggressiveOptimization.isPresent,
    [bool]$locationService = $aggressiveOptimization.isPresent,
    [bool]$cameraAccess = $aggressiveOptimization.isPresent,
    [bool]$cameraApps = $aggressiveOptimization.isPresent,
    [bool]$microphoneAccess = $aggressiveOptimization.isPresent,
    [bool]$microphoneApps = $aggressiveOptimization.isPresent,
    [bool]$notificationsApps = $aggressiveOptimization.isPresent,
    [bool]$accountInfoAccess = $aggressiveOptimization.isPresent,
    [bool]$accountInfoApps = $aggressiveOptimization.isPresent,
    [bool]$contactsAccess = $aggressiveOptimization.isPresent,
    [bool]$contactsApps = $aggressiveOptimization.isPresent,
    [bool]$calendarAccess = $aggressiveOptimization.isPresent,
    [bool]$calendarApps = $aggressiveOptimization.isPresent,
    [bool]$callHistoryAccess = $aggressiveOptimization.isPresent,
    [bool]$callHistoryApps = $aggressiveOptimization.isPresent,
    [bool]$emailAccess = $aggressiveOptimization.isPresent,
    [bool]$emailApps = $aggressiveOptimization.isPresent,
    [bool]$tasksAccess = $aggressiveOptimization.isPresent,
    [bool]$tasksApps = $aggressiveOptimization.isPresent,
    [bool]$messagingAccess = $aggressiveOptimization.isPresent,
    [bool]$messagingApps = $aggressiveOptimization.isPresent,
    [bool]$radiosApps = $aggressiveOptimization.isPresent,
    [bool]$otherDevicesApps = $aggressiveOptimization.isPresent,
    [bool]$backgroundApps = $aggressiveOptimization.isPresent,
    [bool]$diagnosticsApps = $true,
    [bool]$windowsUpdateBranchReadinessLevel = $true,
    [bool]$allowDownloadsFromOtherPCs = $true,
    [bool]$cloudDeliveredProtection = $aggressiveOptimization.isPresent,
    [bool]$automaticSampleSubmission = $true,
    [bool]$findMyDevice = $aggressiveOptimization.isPresent,
    [bool]$windowsInsiderProgram = $aggressiveOptimization.isPresent,
    [bool]$ieDoNotTrack = $true,
    [bool]$ieSuggestedSites = $true,
    [bool]$edgeNewTabs = $true,
    [bool]$edgeDoNotTrack = $true,
    [bool]$edgeCortana = $aggressiveOptimization.isPresent,
    [bool]$edgeSearchSiteSuggestions = $aggressiveOptimization.isPresent,
    [bool]$explorerFileExtensions = $true,
    [bool]$explorerSystemFiles = $true,
    [bool]$explorerSyncProviderNotifications = $true
)

# Settings > System > Notifications & actions > Show me the Windows welcome experience... => Off
if ($windowsWelcomeExperience) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /t REG_DWORD /d 0 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Cloud Content\Turn off the Windows Welcome Experience => Enabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightWindowsWelcomeExperience /t REG_DWORD /d 1 /f
    }
}

# Settings > System > Notifications & actions > Suggest ways I can finish setting up my device... => Off
if ($finishSettingUpDevice) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f
}

# Settings > System > Notifications & actions > Get tips, tricks, and suggestions... => Off
if ($tipsTricksSuggestions) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Cloud Content\Do not show Windows tips => Enabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
    }
}

# Settings > System > Multitasking > Show suggestions occasionally in Timeline => Off
if ($timelineSuggestions) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
}

# Settings > System > Shared experiences > Share content with a nearby device by using Bluetooth and Wi-Fi => Off
# Settings > System > Shared experiences > I can share or receive content from => My devices only
# Settings > System > Shared experiences > Let apps on other devices (including linked phones and tablets) open and message... => Off
# Settings > System > Shared experiences > I can share or receive from => My devices only
if ($sharedDevices) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" /v UserAuthPolicy /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v CdpSessionUserAuthzPolicy /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v NearShareChannelUserAuthzPolicy /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v RomeSdkChannelUserAuthzPolicy /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v BluetoothLastDisabledNearShare /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v NearShareChannelUserAuthzPolicy /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v RomeSdkChannelUserAuthzPolicy /t REG_DWORD /d 1 /f
    # Group Policy > Computer Configuration\Administrative Templates\System\Group Policy\Continue experiences on this device => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp /t REG_DWORD /d 0 /f
    }
}

# Settings > System > Clipboard > Save multiple items to the clipboard to use later... => Off
if ($clipboardHistory) {
    reg add "HKCU\SOFTWARE\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\System\OS Policies\Allow Clipboard History => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowClipboardHistory /t REG_DWORD /d 0 /f
    }
}

# Settings > System > Clipboard > Paste text on your other devices... => Off
# Settings > System > Clipboard > Automatic syncing => Never automatically sync text that I copy
if ($clipboardSync) {
    reg add "HKCU\SOFTWARE\Microsoft\Clipboard" /v EnableCloudClipboard /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Clipboard" /v CloudClipboardAutomaticUpload /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\System\OS Policies\Allow Clipboard synchronization across devices => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /t REG_DWORD /d 0 /f
    }
}

# Settings > Devices > Bluetooth & other devices > Show notifications to connect using Swift Pair => Off
if ($swiftPair) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Bluetooth" /v QuickPair /t REG_DWORD /d 0 /f
}

# Settings > Devices > Pen & Windows Ink > Show recommended app suggestions => Off
if ($windowsInkWorkspaceRecommendedApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /v PenWorkspaceAppSuggestionsEnabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Ink Workspace\Allow suggested apps in Windows Ink Workspace => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
    }
}

# Settings > Phone => Disable
# Group Policy > Computer Configuration\Administrative Templates\System\Group Policy\Phone-PC linking on this device => Disabled
if ($phone -and $editGroupPolicies) {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableMmx /t REG_DWORD /d 0 /f
}

# Settings > Network & Internet > Wi-Fi > Find paid plans for suggested open hotspots near me => Off
# Settings > Network & Internet > Wi-Fi > Connect to suggested open hotspots => Off
# Settings > Network & Internet > Wi-Fi > Connect to networks shared by my contacts => Off
# Group Policy > Computer Configuration\Administrative Templates\Network\WLAN Service\WLAN Settings\Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services => Disabled
if ($wiFiSense -and $editGroupPolicies) {
    reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
}

# Settings > Network & Internet > Wi-Fi > Let me use Online Sign-Up to get connected => Off
if ($hotspot20Networks) {
    reg add "HKLM\SOFTWARE\Microsoft\WlanSvc\AnqpCache" /v OsuRegistrationStatus /t REG_DWORD /d 0 /f
}

# Settings > Personalization > Lock screen > Background => Picture
if ($lockScreenBackground) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Cloud Content\Configure Windows spotlight on lock screen => Disabled
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Cloud Content\Turn off all Windows spotlight features => Enabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /t REG_DWORD /d 2 /f
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
    }
}

# Settings > Personalization > Lock screen > Get fun facts, tips, and more... => Off
if ($lockScreenFunFactsTips) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Control Panel\Personalization\Force a specific default lock screen image => Turn off fun facts, tips, tricks, and more on lock screen
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v LockScreenOverlaysDisabled /t REG_DWORD /d 1 /f
    }
}

# Settings > Personalization > Start > Occasionally show suggestions in Start => Off
# Settings > Personalization > Start > Show suggestions occasionally in Start => Off
if ($startSuggestions) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Cloud Content\Turn off Microsoft consumer experiences => Enabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
    }
}

# Settings > Personalization > Taskbar > Show My People app suggestions => Off
if ($myPeopleAppSuggestions) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-314563Enabled /t REG_DWORD /d 0 /f
}

# Settings > Apps > Apps & features
$appxProvisionedPackage = Get-AppxProvisionedPackage -Online
#   3D Builder => Uninstall
if ($apps3DBuilder) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.3DBuilder*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.3DBuilder* | Remove-AppxPackage
}
#   Alarms & Clock => Uninstall
if ($appsAlarmsClock) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.WindowsAlarms*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage
}
#   App Connector => Uninstall
if ($appsAppConnector) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.Appconnector*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.Appconnector* | Remove-AppxPackage
}
#   App Installer => Uninstall
if ($appsAppInstaller) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.DesktopAppInstaller*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.DesktopAppInstaller* | Remove-AppxPackage
}
#   Asphalt 8: Airborne => Uninstall
if ($appsAsphalt8Airborne) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.Asphalt8Airborne*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.Asphalt8Airborne* | Remove-AppxPackage
}
#   Calculator => Uninstall
if ($appsCalculator) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.WindowsCalculator*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.WindowsCalculator* | Remove-AppxPackage
}
#   Camera => Uninstall
if ($appsCamera) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.WindowsCamera*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage
}
#   Candy Crush Soda Saga => Uninstall
if ($appsCandyCrushSodaSaga) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*king.com.CandyCrushSodaSaga*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *king.com.CandyCrushSodaSaga* | Remove-AppxPackage
}
#   Connect => Uninstall
if ($appsConnect) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.PPIProjection*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.PPIProjection* | Remove-AppxPackage
}
#   Drawboard PDF => Uninstall
if ($appsDrawboardPDF) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.DrawboardPDF*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.DrawboardPDF* | Remove-AppxPackage
}
#   Facebook => Uninstall
if ($appsFacebook) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Facebook*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Facebook* | Remove-AppxPackage
}
#   Fallout Shelter => Uninstall
if ($appsFalloutShelter) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*BethesdaSoftworks.FalloutShelter*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *BethesdaSoftworks.FalloutShelter* | Remove-AppxPackage
}
#   FarmVille 2: Country Escape => Uninstall
if ($appsFarmVille2CountryEscape) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*FarmVille2CountryEscape*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *FarmVille2CountryEscape* | Remove-AppxPackage
}
#   Feedback Hub => Uninstall
if ($appsFeedbackHub) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.WindowsFeedbackHub*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
}
#   Get Help => Uninstall
if ($appsGetHelp) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.GetHelp*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage
}
#   Get Office => Uninstall
if ($appsGetOffice) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.MicrosoftOfficeHub*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage
}
#   Groove Music => Uninstall
if ($appsGrooveMusic) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.ZuneMusic*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage
}
#   HEIF Image Extensions => Uninstall
if ($appsHEIFImageExtensions) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.HEIFImageExtension*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.HEIFImageExtension* | Remove-AppxPackage
}
#   Mail and Calendar => Uninstall
if ($appsMailAndCalendar) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*microsoft.windowscommunicationsapps*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage
}
#   Maps => Uninstall
if ($appsMaps) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.WindowsMaps*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage
}
#   Messaging => Uninstall
if ($appsMessaging) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.Messaging*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage
}
#   Microsoft Edge => Uninstall
if ($appsMicrosoftEdge) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.MicrosoftEdge*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.MicrosoftEdge* | Remove-AppxPackage
}
#   Microsoft Solitaire Collection => Uninstall
if ($appsMicrosoftSolitaireCollection) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.MicrosoftSolitaireCollection*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
}
#   Microsoft Store => Uninstall
if ($appsMicrosoftStore) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.WindowsStore*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage
}
#   Microsoft Wallet => Uninstall
if ($appsMicrosoftWallet) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Wallet*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Wallet* | Remove-AppxPackage
}
#   Microsoft Wi-Fi => Uninstall
if ($appsMicrosoftWiFi) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.ConnectivityStore*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.ConnectivityStore* | Remove-AppxPackage
}
#   Minecraft => Uninstall
if ($appsMinecraft) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*MinecraftUWP*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *MinecraftUWP* | Remove-AppxPackage
}
#   Mixed Reality Viewer => Uninstall
if ($appsMixedRealityViewer) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.Microsoft3DViewer*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage
}
#   Mixed Reality Portal => Uninstall
if ($appsMixedRealityPortal) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.Windows.HolographicFirstRun*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.Windows.HolographicFirstRun* | Remove-AppxPackage
}
#   Money => Uninstall
if ($appsMoney) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.BingFinance*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.BingFinance* | Remove-AppxPackage
}
#   Movies & TV => Uninstall
if ($appsMoviesTV) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.ZuneVideo*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage
}
#   Netflix => Uninstall
if ($appsNetflix) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Netflix*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Netflix* | Remove-AppxPackage
}
#   News => Uninstall
if ($appsNews) {
    $appxProvisionedPackage | Where-Object { $_.PackageName -Like "*Microsoft.BingNews*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
    Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage
}
#   Onedrive => Uninstall
& "$env:SystemRoot\System32\OneDriveSetup.exe" /Uninstall
& "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /Uninstall
Remove-Item C:\OneDriveTemp -Recurse -Force
Remove-Item $env:USERPROFILE\OneDrive -Recurse -Force
Remove-Item $env:LOCALAPPDATA\Microsoft\OneDrive -Recurse -Force
Remove-Item "$env:ProgramData\Microsoft OneDrive" -Recurse -Force
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v Attributes /t REG_DWORD /d 0 /f
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v Attributes /t REG_DWORD /d 0 /f
#   OneNote => Uninstall
if ($appsOneNote) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.Office.OneNote*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage
}
#   Paid Wi-Fi & Cellular => Uninstall
if ($appsPaidWiFiCellular) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.OneConnect*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage
}
#   Paint 3D => Uninstall
if ($appsPaint3D) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.MSPaint*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage
}
#   Pandora => Uninstall
if ($appsPandora) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*PandoraMediaInc*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *PandoraMediaInc* | Remove-AppxPackage
}
#   People => Uninstall
if ($appsPeople) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.People*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.People* | Remove-AppxPackage
}
#   Phone => Uninstall
if ($appsPhone) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.CommsPhone*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.CommsPhone* | Remove-AppxPackage
}
#   Phone Companion => Uninstall
if ($appsPhoneCompanion) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*windowsphone*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *windowsphone* | Remove-AppxPackage
}
#   Photos => Uninstall
if ($appsPhotos) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.Windows.Photos*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.Windows.Photos* | Remove-AppxPackage
}
#   Print 3D => Uninstall
if ($appsPrint3D) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.Print3D*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage
}
#   Royal Revolt 2 => Uninstall
if ($appsRoyalRevolt2) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*flaregamesGmbH.RoyalRevolt2*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *flaregamesGmbH.RoyalRevolt2* | Remove-AppxPackage
}
#   Scan => Uninstall
if ($appsScan) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*WindowsScan*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *WindowsScan* | Remove-AppxPackage
}
#   Snip & Sketch => Uninstall
if ($appsSnipSketch) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.ScreenSketch*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage
}
#   Skype => Uninstall
if ($appsSkype) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.SkypeApp*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage
}
#   Sports => Uninstall
if ($appsSports) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.BingSports*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.BingSports* | Remove-AppxPackage
}
#   Sticky Notes => Uninstall
if ($appsStickyNotes) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.MicrosoftStickyNotes*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage
}
#   Sway => Uninstall
if ($appsSway) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.Office.Sway*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage
}
#   Tips => Uninstall
if ($appsTips) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.Getstarted*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage
}
#   Twitter => Uninstall
if ($appsTwitter) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Twitter*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Twitter* | Remove-AppxPackage
}
#   Voice Recorder => Uninstall
if ($appsVoiceRecorder) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.WindowsSoundRecorder*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage
}
#   View 3D => Uninstall
if ($appsView3D) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.Microsoft3DViewer*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage
}
#   Weather => Uninstall
if ($appsWeather) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.BingWeather*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage
}
#   Web Media Extensions => Uninstall
if ($appsWebMediaExtensions) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.WebMediaExtensions*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.WebMediaExtensions* | Remove-AppxPackage
}
#   Webp Image Extensions => Uninstall
if ($appsWebpImageExtensions) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.WebpImageExtension*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.WebpImageExtension* | Remove-AppxPackage
}
#   Windows Phone => Uninstall
if ($appsWindowsPhone) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.WindowsPhone*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.WindowsPhone* | Remove-AppxPackage
}
#   Windows Phone Connector => Uninstall
if ($appsWindowsPhoneConnector) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.Windows.Phone*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.Windows.Phone* | Remove-AppxPackage
}
#   Xbox => Uninstall
if ($appsXbox) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.XboxApp*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage
}
#   Xbox Game Speech Windows => Uninstall
if ($appsXboxGameSpeechWindows) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.XboxSpeechToTextOverlay*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage
}
#   Xbox Live => Uninstall
if ($appsXboxLive) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Microsoft.Xbox.TCUI*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage
}
#   Xbox One SmartGlass => Uninstall
if ($appsXboxOneSmartGlass) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*XboxOneSmartGlass*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *XboxOneSmartGlass* | Remove-AppxPackage
}

# Settings > Apps > Offline maps > Automatically update maps => Off
if ($autoUpdateMaps) {
    reg add "HKLM\SYSTEM\Maps" /v AutoUpdateEnabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Maps\Turn off Automatic Download and Update of Map Data => Enabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v AutoDownloadAndUpdateMapData /t REG_DWORD /d 0 /f
    }
}

# Settings > Accounts > Sign-in options > Show account details on sign-in screen => Off
if ($showAccountDetails) {
    # Group Policy > Computer Configuration\Administrative Templates\System\Logon\Block user from showing account details on sign-in => Enabled
    # Local Security Policy > Local Policies\Security Options\Interactive logon: Display user information when the session is locked => User display name only
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v BlockUserFromShowingAccountDetailsOnSignin /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLockedUserId /t REG_DWORD /d 2 /f
    }
}

# Settings > Accounts > Sign-in options > Use my sign-in info to automatically finish setting up my device... => Off
if ($useSignInInfoToFinishSetup) {
    $sid = (New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).ToString()
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$sid" /v OptOut /t REG_DWORD /d 1 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Logon Options\Sign-in last interactive user automatically after a system-initiated restart => Enabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f
    }
}

# Settings > Accounts > Sync your settings > Sync settings => Off
# Settings > Accounts > Sync your settings > Theme => Off
# Settings > Accounts > Sync your settings > Passwords => Off
# Settings > Accounts > Sync your settings > Language preferences => Off
# Settings > Accounts > Sync your settings > Other Windows settings => Off
if ($syncSettings) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v Enabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync app settings => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync Apps => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync browser settings => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync desktop personalization => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync other Windows settings => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync passwords => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync personalize => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Sync your settings\Do not sync start settings => Enabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSyncUserOverride /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableAppSyncSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableAppSyncSettingSyncUserOverride /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWebBrowserSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWebBrowserSettingSyncUserOverride /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableDesktopThemeSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableDesktopThemeSettingSyncUserOverride /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWindowsSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWindowsSettingSyncUserOverride /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableCredentialsSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableCredentialsSettingSyncUserOverride /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisablePersonalizationSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisablePersonalizationSettingSyncUserOverride /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableStartLayoutSettingSync /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableStartLayoutSettingSyncUserOverride /t REG_DWORD /d 1 /f
    }
}

# Settings > Gaming > TruePlay > TruePlay => Off
if ($truePlay) {
    reg add "HKCU\Software\Microsoft\Games" /v EnableXBGM /t REG_DWORD /d 0 /f
}

# Settings > Ease of Access > Narrator > Get image descriptions, page titles, and popular links => Off
if ($narratorGetImageTitlesLinks) {
    reg add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v OnlineServicesEnabled /t REG_DWORD /d 0 /f
}

# Settings > Ease of Access > Narrator > Send additional diagnostic and performance data... => Off
# Settings > Ease of Access > Narrator > Help make Narrator better => Off
if ($narratorSendMoreDiagPerfData) {
    reg add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v DetailedFeedback /t REG_DWORD /d 0 /f
}

# Settings > Search > Permissions & History > Allow Windows Search to provide results from your Microsoft account. => Off
if ($searchMicrosoftAccount) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsMSACloudSearchEnabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Search\Allow Cloud Search => Disable Cloud Search
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f
    }
}

# Settings > Search > Permissions & History > Allow Windows Search to provide results from your work or school account. => Off
if ($searchWorkSchoolAccount) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsAADCloudSearchEnabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Search\Allow Cloud Search => Disable Cloud Search
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f
    }
}

# Settings > Search > Permissions & History > To improve your search suggestions, let Windows Search store your search history... => Off
if ($searchHistory) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsDeviceSearchHistoryEnabled /t REG_DWORD /d 0 /f
}

# Settings > Privacy > General > Let apps use my advertising ID... => Off
# Settings > Privacy > General > Let apps use advertising ID... => Off
if ($advertisingId) {
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\System\User Profiles\Turn off the advertising ID => Enabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
    }
}

# Settings > Privacy > General > Let websites provide locally relevant content... => Off
if ($locallyRelevantContent) {
    reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
}

# Settings > Privacy > General > Let Windows track app launches... => Off
if ($trackAppLaunches) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f
}

# Settings > Privacy > General > Show me suggested content in the Settings app => Off
if ($settingsSuggestedContent) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Cloud Content\Turn off Windows Spotlight on Settings => Enabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnSettings /t REG_DWORD /d 1 /f
    }
}

# Settings > Privacy > Speech, inking, & typing > Turn off speech services and typing suggestions
if ($turnOffSpeechAndTypingSuggestions) {
    reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Control Panel\Regional and Language Options\Allow input personalization => Disabled
    # Group Policy > Computer Configuration\Administrative Templates\Control Panel\Regional and Language Options\Allow users to enable online speech recognition services => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 0 /f
    }
}

# Settings > Privacy > Diagnostics & feedback > Select how much data you send to Microsoft => Security
# Settings > Privacy > Diagnostics & feedback > Choose how much data you send to Microsoft => Security
if ($diagnosticData) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Telemetry => 0 - Security
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Telemetry => 0 - Security
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
    }
}

# Settings > Privacy > Diagnostics & feedback > Send inking and typing data to Microsoft... => Off
if ($sendInkingTypingData) {
    reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Text Input\Improve inking and typing recognition => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v AllowLinguisticDataCollection /t REG_DWORD /d 0 /f
    }
}

# Settings > Privacy > Diagnostics & feedback > Let Microsoft provide more tailored experiences... => Off
# Settings > Privacy > Diagnostics & feedback > Let Microsoft offer you tailored experiences... => Off
if ($tailoredExperiences) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Cloud Content\Do not use diagnostic data for tailored experiences => Enabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
    }
}

# Settings > Privacy > Diagnostics & feedback > Windows should ask for my feedback => Never
if ($feedbackFrequency) {
    reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /t REG_QWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds\Do not show feedback notifications => Enabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
    }
}

# Settings > Privacy > Activity history > Let Windows collect my activities... => Off
if ($activitiesCollect) {
    # Group Policy > Computer Configuration\Administrative Templates\System\OS Policies\Allow publishing of User Activities => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
    }
}

# Settings > Privacy > Activity history > Let Windows sync my activities... => Off
if ($activitiesSync) {
    # Group Policy > Computer Configuration\Administrative Templates\System\OS Policies\Allow upload of User Activities => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f
    }
}

# Settings > Privacy > Location > Location for this device => Off
if ($location) {
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 0 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Location and Sensors\Turn off location => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Location and Sensors\Turn off location => Enabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f
    }
}

# Settings > Privacy > Location > Location service => Off
if ($locationService) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access location => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessLocation /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Camera > Camera access for this device => Off
if ($cameraAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access the camera => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessCamera /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Camera > Let apps use my camera hardware => Off
# Settings > Privacy > Camera > Allow apps to access your camera => Off
if ($cameraApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Microphone > Microphone access for this device => Off
if ($microphoneAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access the microphone => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessMicrophone /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Microphone > Let apps use my microphone => Off
# Settings > Privacy > Microphone > Allow apps to access your microphone => Off
if ($microphoneApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Notifications >  => Off
if ($notificationsApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access notifications => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessNotifications /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Account info > Account info access for this device => Off
if ($accountInfoAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access account information => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessAccountInfo /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Account info > Let apps access my name, picture, and other account info => Off
# Settings > Privacy > Account info > Allow apps to access your account info => Off
if ($accountInfoApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Contacts > Contacts access for this device => Off
if ($contactsAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access contacts => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessContacts /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Contacts > Let apps access my contacts => Off
# Settings > Privacy > Contacts > Allow apps to access your contacts => Off
if ($contactsApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Calendar > Calendar access for this device => Off
if ($calendarAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access the calendar => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessCalendar /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Calendar > Let apps access my calendar => Off
# Settings > Privacy > Calendar > Allow apps to access your calendar => Off
if ($calendarApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Call history > Call history access for this device => Off
if ($callHistoryAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access call history => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessCallHistory /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Call history > Let apps access my call history => Off
# Settings > Privacy > Call history > Allow apps to access your call history => Off
if ($callHistoryApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Email > Email access for this device => Off
if ($emailAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access email => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessEmail /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Email > Let apps access and send email => Off
# Settings > Privacy > Email > Allow apps to access your email => Off
if ($emailApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Tasks > Tasks access for this device => Off
if ($tasksAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access Tasks => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessTasks /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Tasks => Off
# Settings > Privacy > Tasks > Allow apps to access your tasks => Off
if ($tasksApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Messaging > Messaging access for this device => Off
if ($messagingAccess) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access messaging => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessMessaging /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Messaging > Let apps read or send messages (text or MMS) => Off
# Settings > Privacy > Messaging > Allow apps to read or send messages => Off
if ($messagingApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v Value /t REG_SZ /d Deny /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v Value /t REG_SZ /d Deny /f
}

# Settings > Privacy > Radios > Let apps control radios => Off
if ($radiosApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps control radios => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessRadios /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Other devices > Let your apps automatically share and sync info with... => Off
# Settings > Privacy > Other devices > Communicate with unpaired devices => Off
if ($otherDevicesApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps sync with devices => Force Deny
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps communicate with unpaired devices => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsSyncWithDevices /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > Background apps > Let apps run in the background => Off
if ($backgroundApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps run in the background => Force Deny
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access user movements while running in the background => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessBackgroundSpatialPerception /t REG_DWORD /d 2 /f
    }
}

# Settings > Privacy > App diagnostics > Let apps access diagnostic information => Off
if ($diagnosticsApps) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v Value /t REG_SZ /d Deny /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access diagnostic information about other apps => Force Deny
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsGetDiagnosticInfo /t REG_DWORD /d 2 /f
    }
}

# Settings > Update & Security > Windows Update > Advanced options > Choose the branch readiness level... => Semi-Annual Channel
if ($windowsUpdateBranchReadinessLevel) {
    reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v InsiderProgramEnabled /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v BranchReadinessLevel /t REG_DWORD /d 16 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Update\Windows Update for Business\Select when Preview Builds and Feature Updates are received => Semi-Annual Channel
    if ($editGroupPolicies) {
        reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v BranchReadinessLevel /t REG_DWORD /d 16 /f
        reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DeferFeatureUpdates /t REG_DWORD /d 1 /f
        reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DeferFeatureUpdatesPeriodinDays /t REG_DWORD /d 90 /f
    }
}

# Settings > Update & Security > Windows Update > Advanced options > Delivery Optimization > Allow downloads from other PCs => On, PCs on my local network
if ($allowDownloadsFromOtherPCs) {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v DownloadMode /t REG_SZ /d 1 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Delivery Optimization\Download Mode => LAN (1)
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 1 /f
    }
}

# Settings > Update & Security > Windows Security > Open Windows Defender Security Center > Settings > Virus & threat protection settings > Cloud-delivered protection => Off
if ($cloudDeliveredProtection) {
    Set-MpPreference -MAPSReporting Disabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS\Configure the 'Block at First Sight' feature => Disabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS\Configure local setting override for reporting to Microsoft Active Protection Service (MAPS) => Disabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS\Join Microsoft MAPS => Disabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Security Intelligence Updates\Allow real-time security intelligence updates based on reports to Microsoft MAPS => Disabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Security Intelligence Updates\Allow notifications to disable security intelligence based reports to Microsoft MAPS => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v LocalSettingOverrideSpynetReporting /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v RealTimeSignatureDelivery /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v SignatureDisableNotification /t REG_DWORD /d 0 /f
    }
}

# Settings > Update & Security > Windows Security > Open Windows Defender Security Center > Settings > Virus & threat protection settings > Automatic sample submission => Off
if ($automaticSampleSubmission) {
    Set-MpPreference -SubmitSamplesConsent Never
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS\Send file samples when further analysis is required => Never Send
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
    }
}

# Settings > Update & Security > Find my device > Find my device => Off
if ($findMyDevice) {
    reg add "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /v LocationSyncEnabled /t REG_DWORD /d 0 /f
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Find My Device\Turn On/Off Find My Device => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /t REG_DWORD /d 0 /f
    }
}

# Settings > Update & Security > Windows Insider Program => Disable
if ($windowsInsiderProgram) {
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds\Toggle user control over Insider builds => Disabled
    if ($editGroupPolicies) {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v AllowBuildPreview /t REG_DWORD /d 0 /f
    }
}

# Internet Explorer > Internet Options > Advanced > Security\Send Do Not Track requests to sites... => On
if ($ieDoNotTrack) {
    reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Internet Explorer\Internet Control Panel\Advanced Page\Always send Do Not Track header => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Internet Control Panel\Advanced Page\Always send Do Not Track header => Enabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    }
}

# Internet Explorer > Internet Options > Advanced > Browsing\Enable Suggested Sites => Off
if ($ieSuggestedSites) {
    reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v Enabled /t REG_DWORD /d 0 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Internet Explorer\Turn on Suggested Sites => Disabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Turn on Suggested Sites => Disabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" /v Enabled /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" /v Enabled /t REG_DWORD /d 0 /f
    }
}

# Microsoft Edge > Settings > Open new tabs with => Top sites
if ($edgeNewTabs) {
    reg add "HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI" /v NewTabPageDisplayOption /t REG_DWORD /d 1 /f
}

# Microsoft Edge > Settings > View advanced settings > Send Do Not Track requests => On
if ($edgeDoNotTrack) {
    reg add "HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Microsoft Edge\Configure Do Not Track => Enabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Microsoft Edge\Configure Do Not Track => Enabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v ConfigureDoNotTrack /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ConfigureDoNotTrack /t REG_DWORD /d 1 /f
    }
}

# Microsoft Edge > Settings > View advanced settings > Have Cortana assist me... => Off
if ($edgeCortana) {
    reg add "HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI" /v EnableCortana /t REG_DWORD /d 0 /f
}

# Microsoft Edge > Settings > View advanced settings > Show search and site suggestions... => Off
if ($edgeSearchSiteSuggestions) {
    reg add "HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v ShowSearchSuggestionsGlobal /t REG_DWORD /d 0 /f
    # Group Policy > User Configuration\Administrative Templates\Windows Components\Microsoft Edge\Configure search suggestions in Address bar => Disabled
    # Group Policy > Computer Configuration\Administrative Templates\Windows Components\Microsoft Edge\Configure search suggestions in Address bar => Disabled
    if ($editGroupPolicies) {
        reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v ShowSearchSuggestionsGlobal /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v ShowSearchSuggestionsGlobal /t REG_DWORD /d 0 /f
    }
}

# File Explorer > Folder Options > View > Hide extensions for known file types => Off
if ($explorerFileExtensions) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
}

# File Explorer > Folder Options > View > Hide protected operating system files (Recommended) => Off
if ($explorerSystemFiles) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
}

# File Explorer > Folder Options > View > Show sync provider notifications => Off
if ($explorerSyncProviderNotifications) {
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f
}

# Additional Group Policies
if ($editGroupPolicies) {
    # See https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services
    #   Cortana and Search
    #     Allow Cortana => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Search\Allow Cortana => Disabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f }
    #     Allow search and Cortana to use location => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Search\Allow search and Cortana to use location => Disabled
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
    #     Do not allow web search => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Search\Do not allow web search => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f }
    #     Don't search the web or display web results in Search => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Search\Don't search the web or display web results in Search => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f }
    #     Set what information is shared in Search => Anonymous info
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Search\Set what information is shared in Search => Anonymous info
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchPrivacy /t REG_DWORD /d 3 /f

    #   Device metadata retrieval
    #     Prevent device metadata retrieval from the Internet => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\System\Device Installation\Prevent device metadata retrieval from the Internet => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f }

    #   Internet Explorer
    #     Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar => Disabled
    #       Group Policy > User Configuration\Administrative Templates\Windows Components\Internet Explorer\Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar => Disabled
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer" /v AllowServicePoweredQSA /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer" /v AllowServicePoweredQSA /t REG_DWORD /d 0 /f
    #     Turn off browser geolocation => Enabled
    #       Group Policy > User Configuration\Administrative Templates\Windows Components\Internet Explorer\Turn off browser geolocation => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Turn off browser geolocation => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" /v PolicyDisableGeolocation /t REG_DWORD /d 1 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" /v PolicyDisableGeolocation /t REG_DWORD /d 1 /f }
    #     Turn off the flip ahead with page prediction feature => Enabled
    #       Group Policy > User Configuration\Administrative Templates\Windows Components\Internet Explorer\Internet Control Panel\Advanced Page\Turn off the flip ahead with page prediction feature => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Internet Control Panel\Advanced Page\Turn off the flip ahead with page prediction feature => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" /v Enabled /t REG_DWORD /d 0 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" /v Enabled /t REG_DWORD /d 0 /f }
    #     Turn off background synchronization for feeds and Web Slices => Enabled
    #       Group Policy > User Configuration\Administrative Templates\Windows Components\RSS Feeds\Turn off background synchronization for feeds and Web Slices => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\RSS Feeds\Turn off background synchronization for feeds and Web Slices => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v BackgroundSyncStatus /t REG_DWORD /d 0 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v BackgroundSyncStatus /t REG_DWORD /d 0 /f }
    #     Allow Online Tips => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Control Panel\Allow Online Tips => Disabled
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /t REG_DWORD /d 0 /f

    #   Live Tiles
    #     Turn Off notifications network usage => Enabled
    #       Group Policy > User Configuration\Administrative Templates\Start Menu and Taskbar\Notifications\Turn Off notifications network usage => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoCloudApplicationNotification /t REG_DWORD /d 1 /f }

    #   Microsoft Account
    #     Accounts: Block Microsoft Accounts => Users can't add Microsoft accounts
    #       Group Policy > Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Block Microsoft Accounts => Users can't add Microsoft accounts
    if ($false) { reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUser /t REG_DWORD /d 3 /f }
    if ($false) { reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvc" /v Start /t REG_DWORD /d 4 /f }

    #   Microsoft Edge
    #     Allow Address bar drop-down list suggestions => Disabled
    #       Group Policy > User Configuration\Administrative Templates\Windows Components\Microsoft Edge\Allow Address bar drop-down list suggestions => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Microsoft Edge\Allow Address bar drop-down list suggestions => Disabled
    if ($false) { reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" /v ShowOneBox /t REG_DWORD /d 0 /f }
    if ($false) { reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" /v ShowOneBox /t REG_DWORD /d 0 /f }
    #     Allow configuration updates for the Books Library => Disabled
    #       Group Policy > User Configuration\Administrative Templates\Windows Components\Microsoft Edge\Allow configuration updates for the Books Library => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Microsoft Edge\Allow configuration updates for the Books Library => Disabled
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v AllowConfigurationUpdateForBooksLibrary /t REG_DWORD /d 0 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v AllowConfigurationUpdateForBooksLibrary /t REG_DWORD /d 0 /f }
    #     Allow web content on New Tab page => Disabled
    #       Group Policy > User Configuration\Administrative Templates\Windows Components\Microsoft Edge\Allow web content on New Tab page => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Microsoft Edge\Allow web content on New Tab page => Disabled
    if ($false) { reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" /v AllowWebContentOnNewTabPage /t REG_DWORD /d 0 /f }
    if ($false) { reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" /v AllowWebContentOnNewTabPage /t REG_DWORD /d 0 /f }

    #   Offline maps
    #     Turn off unsolicited network traffic on the Offline Maps settings page => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Maps\Turn off unsolicited network traffic on the Offline Maps settings page => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v AllowUntriggeredNetworkTrafficOnSettingsPage /t REG_DWORD /d 0 /f }

    #   OneDrive
    #     Prevent the usage of OneDrive for file storage => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\OneDrive\Prevent the usage of OneDrive for file storage => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f }
    #     Prevent OneDrive from generating network traffic until the user signs in to OneDrive => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\OneDrive\Prevent OneDrive from generating network traffic until the user signs in to OneDrive => Enabled
    reg add "HKLM\SOFTWARE\Microsoft\OneDrive" /v PreventNetworkTrafficPreUserSignIn /t REG_DWORD /d 1 /f

    #   Speech, inking, & typing
    #     Turn off automatic learning => Enabled
    #       Group Policy > User Configuration\Administrative Templates\Control Panel\Regional and Language Options\Handwriting personalization\Turn off automatic learning => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Control Panel\Regional and Language Options\Handwriting personalization\Turn off automatic learning => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f }
    #     Allow automatically update of Speech Data => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Speech\Allow Automatic Update of Speech Data => Disabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v ModelDownloadAllowed /t REG_DWORD /d 0 /f }

    #   Phone calls
    #     Let Windows apps make phone calls => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps make phone calls => Disabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessPhone /t REG_DWORD /d 2 /f }

    #   Motion
    #     Let Windows apps access motion => Disabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps access motion => Disabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessMotion /t REG_DWORD /d 2 /f }

    #   Voice Activation
    #     Let Windows apps activate with voice => Force Deny
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps activate with voice => Force Deny
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f }
    #     Let Windows apps activate with voice while the system is locked => Force Deny
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\App Privacy\Let Windows apps activate with voice while the system is locked => Force Deny
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f }

    #   Software Protection Platform
    #     Turn off KMS Client Online AVS Validation => Enabled
    #       Group Policy > Computer Configuration\Administrative Templates\Windows Components\Software Protection Platform\Turn off KMS Client Online AVS Validation => Enabled
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f

    #   Sync your settings
    #     To turn off Messaging cloud sync
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Microsoft\Messaging" /v CloudServiceSyncEnabled /t REG_DWORD /d 0 /f }

    #   Malicious Software Removal Tool
    #     Turn off Malicious Software Removal Tool telemetry
    reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f

    # More Group Policies
    #   Telemetry related
    reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v CEIPEnable /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v DisableCustomerImprovementProgram /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v DisableCustomerImprovementProgram /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" /v CEIP /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v CEIP /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f

    #   Error Reporting related
    reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v AllOrNone /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v DoReport /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v IncludeKernelFaults /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v IncludeMicrosoftApps /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v IncludeShutdownErrs /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v IncludeWindowsApps /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v DWNoFileCollection /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v DWNoSecondLevelCollection /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableSendGenericDriverNotFoundToWER /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableSendRequestAdditionalSoftwareToWER /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v AutoApproveOSDumps /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v AutoApproveOSDumps /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v BypassDataThrottling /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v BypassDataThrottling /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v BypassNetworkCostThrottling /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v BypassNetworkCostThrottling /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v BypassPowerThrottling /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v BypassPowerThrottling /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultConsent /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultConsent /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultOverrideBehavior /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultOverrideBehavior /t REG_DWORD /d 1 /f

    #   Windows Spotlight related
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnActionCenter /t REG_DWORD /d 1 /f

    #   Microsoft Edge related
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v AlwaysEnableBooksLibrary /t REG_DWORD /d 0 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v AlwaysEnableBooksLibrary /t REG_DWORD /d 0 /f }
    reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v EnableExtendedBooksTelemetry /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v EnableExtendedBooksTelemetry /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v PreventLiveTileDataCollection /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v PreventLiveTileDataCollection /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v MicrosoftEdgeDataOptIn /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v MicrosoftEdgeDataOptIn /t REG_DWORD /d 0 /f
    #    Allow Microsoft Edge to start and load the Start and New Tab page at Windows startup and each time Microsoft Edge is closed => Prevent tab preloading
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v AllowTabPreloading /t REG_DWORD /d 0 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v AllowTabPreloading /t REG_DWORD /d 0 /f }
    #    Allow Microsoft Edge to pre-launch at Windows startup, when the system is idle, and each time Microsoft Edge is closed => Prevent pre-launching
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d 0 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d 0 /f }

    #   Windows Media Player related
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v PreventLibrarySharing /t REG_DWORD /d 1 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v PreventCDDVDMetadataRetrieval /t REG_DWORD /d 1 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v PreventMusicFileMetadataRetrieval /t REG_DWORD /d 1 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v PreventRadioPresetsRetrieval /t REG_DWORD /d 1 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v PreventCodecDownload /t REG_DWORD /d 1 /f }

    #   Allow Message Service Cloud Sync => Disabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v AllowMessageSync /t REG_DWORD /d 0 /f }

    #   Allow Microsoft accounts to be optional => Enabled
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MSAOptional /t REG_DWORD /d 1 /f

    #   Configure Automatic Updates => Notify for download and auto install
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f }
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f }

    #   Disable pre-release features or settings => Disabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v EnableConfigFlighting /t REG_DWORD /d 0 /f }
    if ($aggressiveOptimization.isPresent) { reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v EnableExperimentation /f }

    #   Enable/Disable PerfTrack => Disabled
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f

    #   Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider => Disabled
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v DisableQueryRemoteServer /t REG_DWORD /d 0 /f

    #   Turn off feature advertisement balloon notifications => Enabled
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoBalloonFeatureAdvertisements /t REG_DWORD /d 1 /f

    #   Turn off handwriting personalization data sharing => Enabled
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f

    #   Turn off Help Experience Improvement Program => Enabled
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v NoImplicitFeedback /t REG_DWORD /d 1 /f

    #   Turn off Windows Location Provider => Enabled
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableWindowsLocationProvider /t REG_DWORD /d 1 /f }

    #   Let Windows apps access an eye tracker device  => Force Deny
    if ($aggressiveOptimization.isPresent) { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessGazeInput /t REG_DWORD /d 2 /f }

    #   Limit Enhanced diagnostic data to the minimum required by Windows Analytics => Disable Windows Analytics collection
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 0 /f

    #   Allow device name to be sent in Windows diagnostic data => Disabled
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f

    #   Configure telemetry opt-in change notifications.
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInChangeNotification /t REG_DWORD /d 1 /f

    #   Configure telemetry opt-in setting user interface. => Disable telemetry opt-in Settings
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInSettingsUx /t REG_DWORD /d 1 /f

    #   Select a method to restrict Peer Selection => Subnet
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DORestrictPeerSelectionBy /t REG_DWORD /d 1 /f

    #   Turn on Live Sticker => Disabled
    if ($aggressiveOptimization.isPresent) { reg add "HKCU\SOFTWARE\Policies\Microsoft\InputMethod\Settings\CHS" /v EnableLiveSticker /t REG_DWORD /d 0 /f }
}

# Services
#   Xbox related => Disabled
if ($aggressiveOptimization.isPresent) {
    sc.exe stop XboxGipSvc
    sc.exe config XboxGipSvc start= disabled
    sc.exe stop xbgm
    sc.exe config xbgm start= disabled
    sc.exe stop XblAuthManager
    sc.exe config XblAuthManager start= disabled
    sc.exe stop XblGameSave
    sc.exe config XblGameSave start= disabled
    sc.exe stop XboxNetApiSvc
    sc.exe config XboxNetApiSvc start= disabled
}

#   Connected User Experiences and Telemetry => Disabled
sc.exe stop DiagTrack
sc.exe config DiagTrack start= disabled
sc.exe stop dmwappushservice
sc.exe config dmwappushservice start= disabled
sc.exe stop diagnosticshub.standardcollector.service
sc.exe config diagnosticshub.standardcollector.service start= disabled

#   Windows Error Reporting Service
sc.exe stop WerSvc
sc.exe config WerSvc start= disabled

#   Windows Insider Service
if ($windowsInsiderProgram) {
    sc.exe stop wisvc
    sc.exe config wisvc start= disabled
}

#   Windows Media Player Network Sharing Service => Disabled.
sc.exe stop WMPNetworkSvc
sc.exe config WMPNetworkSvc start= disabled

# Scheduled tasks
#   Telemetry and feedback related => Disabled
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable

#   Office 15 Subscription Heartbeat => Disabled
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

#   XblGameSaveTask => Disabled
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable

# Registry
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v CEIPEnable /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v SqmLoggerRunning /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v CEIPEnable /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v SqmLoggerRunning /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v DisableOptinExperience /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v DiagTrackAuthorization /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags" /v UpgradeEligible /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /v HaveUploadedForTarget /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v DontRetryOnError /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v IsCensusDisabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v TaskEnableRun /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v Start /t REG_DWORD /d 0 /f
