<#
.SYNOPSIS
  HMI Optimization Script - Optimizes Windows for a clean, efficient HMI application.
  Run using
    iex (iwr "https://raw.githubusercontent.com/lithos-systems/Lithos-Automation-Toolkit/main/Windows/HMI-Optimizer.ps1")
.DESCRIPTION
  Removes bloatware, disables telemetry, and optimizes performance for a lightweight Windows installation.
  Sets specified system services to Manual for on-demand startup, excluding critical networking and remote access services.
  Designed for Windows 7/8/10/11 with robust error handling and logging.
.PARAMETER NoReboot
  Skips the reboot prompt and initial confirmation prompt for automated or remote deployments (e.g., SCCM, RealVNC).
.PARAMETER Force
  Skips the initial confirmation prompt for unattended runs, even if -NoReboot is not specified.
.PARAMETER RestoreHosts
  Restores the hosts file from the most recent backup in C:\Logs\hosts.backup.*.
.PARAMETER SkipCleanup
  Skips disk cleanup and component cleanup to reduce execution time, useful for real-time VNC sessions.
.PARAMETER JsonLog
  Emits structured JSON logs to C:\Logs\HMIOptimize_*.json instead of CSV.
.NOTES
  Requires elevated privileges and PowerShell 5.1 or later on Windows 7 (build 6.1) or newer.
  Test in a VM or non-production environment before deployment.
  Removed packages may require re-provisioning via Add-AppxProvisionedPackage.
  For remote execution (e.g., via RealVNC), use -NoReboot or -Force to avoid session disruption.
  Hosts-file modifications block Adobe domains; use -RestoreHosts to revert if Adobe services are needed.
#>

param (
    [switch]$NoReboot,
    [switch]$Force,
    [switch]$RestoreHosts,
    [switch]$SkipCleanup,
    [switch]$JsonLog
)

# Set global error preference
$ErrorActionPreference = 'Stop'

# Check minimum OS and PowerShell version
$osVersion = [System.Environment]::OSVersion.Version
$psVersion = $PSVersionTable.PSVersion
$minOsBuild = [Version]"6.1"  # Windows 7
$minPsVersion = [Version]"5.1"
if ($osVersion -lt $minOsBuild) {
    Write-Error "This script requires Windows 7 (build 6.1) or later. Current build: $osVersion"
    exit 1
}
if ($psVersion -lt $minPsVersion) {
    Write-Error "This script requires PowerShell 5.1 or later. Current version: $psVersion"
    exit 1
}

# Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..."
    Start-Process powershell "-File $PSCommandPath $($PSBoundParameters.GetEnumerator() | ForEach-Object { "-$($_.Key)" + $(if ($_.Value -is [switch]) {''} else {" '$($_.Value)'"})}) " -Verb RunAs
    exit
}

# Initialize logging
$logDir = "C:\Logs"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
$transcriptPath = "$logDir\HMIOptimize_$timestamp.log"
$logPath = "$logDir\HMIOptimize_$timestamp.$($JsonLog ? 'json' : 'csv')"
$hostsModified = $false
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path $transcriptPath

# Custom logging function
function Write-Log {
    param ($Section, $Status, $Message)
    $logEntry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        Section   = $Section
        Status    = $Status
        Message   = $Message
    }
    if ($JsonLog) {
        $logEntry | ConvertTo-Json -Depth 3 | Add-Content -Path $logPath
    } else {
        $logEntry | Export-Csv -Path $logPath -Append -NoTypeInformation -Force
    }
}

Write-Log -Section "Initialization" -Status "Info" -Message "Script started in elevated context"

# Handle hosts file restoration
if ($RestoreHosts) {
    Write-Host "Restoring hosts file from backup..."
    Try {
        $latestBackup = Get-ChildItem -Path "$logDir\hosts.backup.*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latestBackup) {
            Copy-Item -Path $latestBackup.FullName -Destination "C:\Windows\System32\drivers\etc\hosts" -Force
            Write-Log -Section "HostsRestore" -Status "Success" -Message "Restored hosts file from $($latestBackup.FullName)"
        } else {
            Write-Warning "No hosts file backup found in $logDir"
            Write-Log -Section "HostsRestore" -Status "Warning" -Message "No hosts file backup found"
        }
    } Catch {
        Write-Warning "Error restoring hosts file: $_"
        Write-Log -Section "HostsRestore" -Status "Error" -Message "Error restoring hosts file: $_"
    }
    Stop-Transcript
    exit
}

# Initial confirmation prompt (skipped for -NoReboot or -Force)
if (-not ($NoReboot -or $Force)) {
    Write-Host "This script optimizes Windows for an HMI application by:" -ForegroundColor Yellow
    Write-Host "- Removing bloatware (e.g., Xbox, Candy Crush)" -ForegroundColor Yellow
    Write-Host "- Disabling telemetry and consumer features" -ForegroundColor Yellow
    Write-Host "- Setting specified system services to Manual startup (excluding networking/remote access)" -ForegroundColor Yellow
    Write-Host "- Tuning performance settings" -ForegroundColor Yellow
    Write-Host "The script requires Administrator privileges and may require a reboot." -ForegroundColor Yellow
    Write-Host "Logs will be saved to $logPath." -ForegroundColor Yellow
    Write-Host "Do you want to proceed? [Y/N] (default: N)" -ForegroundColor Yellow
    $response = Read-Host
    if ($response -ne 'Y' -and $response -ne 'y') {
        Write-Host "Script execution aborted by user." -ForegroundColor Red
        Write-Log -Section "Initialization" -Status "Info" -Message "Script aborted by user at initial prompt"
        Stop-Transcript
        exit
    }
}

# Check Windows version
$isWin11 = $osVersion.Build -ge 22000
$isWin7or8 = $osVersion.Major -eq 6 -and ($osVersion.Minor -eq 1 -or $osVersion.Minor -eq 2)
Write-Host "Applying HMI Optimization Script on Windows Build $osVersion" -ForegroundColor Cyan
Write-Log -Section "Initialization" -Status "Info" -Message "Detected Windows Build $osVersion"

# 1) CREATE A RESTORE POINT
Write-Host "Creating system restore point..."
Try {
    if (-not $isWin7or8) {
        Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
        Checkpoint-Computer -Description "Pre-Optimization Restore Point" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
    }
    Write-Log -Section "RestorePoint" -Status "Success" -Message "Created restore point"
} Catch {
    Write-Warning "Could not create restore point: $_"
    Write-Log -Section "RestorePoint" -Status "Error" -Message "Failed to create restore point: $_"
}

# 2) DELETE TEMPORARY FILES
Write-Host "Cleaning Temp folders..."
Try {
    $tempPaths = @("C:\Windows\Temp", "$env:TEMP", "$env:LocalAppData\Microsoft\Windows\INetCache")
    foreach ($path in $tempPaths) {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Section "TempCleanup" -Status "Success" -Message "Cleared temporary files"
} Catch {
    Write-Warning "Error cleaning temp folders: $_"
    Write-Log -Section "TempCleanup" -Status "Error" -Message "Error cleaning temp folders: $_"
}

# 3) DISABLE CONSUMER FEATURES
Write-Host "Disabling Windows consumer features..."
Try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -Force -ErrorAction Stop
    Write-Log -Section "ConsumerFeatures" -Status "Success" -Message "Disabled consumer features"
} Catch {
    Write-Warning "Error disabling consumer features: $_"
    Write-Log -Section "ConsumerFeatures" -Status "Error" -Message "Error disabling consumer features: $_"
}

# 4) DISABLE TELEMETRY (Scheduled Tasks & Registry)
Write-Host "Disabling telemetry..."
Try {
    $tasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "\Microsoft\Windows\Application Experience\MareBackup",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Application Experience\PcaPatchDbTask",
        "\Microsoft\Windows\Maps\MapsUpdateTask"
    )
    foreach ($t in $tasks) {
        Try {
            Disable-ScheduledTask -TaskPath ($t | Split-Path -Parent) -TaskName ($t | Split-Path -Leaf) -ErrorAction Stop
        } Catch {
            Write-Host "  ↳ Could not disable: $t"
        }
    }
    $regPaths = @(
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0 },
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0 },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="ContentDeliveryAllowed"; Value=0 },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="OemPreInstalledAppsEnabled"; Value=0 },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"; Value=0 },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEverEnabled"; Value=0 },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"; Value=0 },
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338387Enabled"; Value=0 },
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338388Enabled"; Value=0 },
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338389Enabled"; Value=0 },
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353698Enabled"; Value=0 },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SystemPaneSuggestionsEnabled"; Value=0 }
    )
    foreach ($r in $regPaths) {
        New-Item -Path $r.Path -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $r.Path -Name $r.Name -PropertyType DWord -Value $r.Value -Force -ErrorAction Stop | Out-Null
    }
    Write-Log -Section "Telemetry" -Status "Success" -Message "Disabled telemetry tasks and registry settings"
} Catch {
    Write-Warning "Error disabling telemetry: $_"
    Write-Log -Section "Telemetry" -Status "Error" -Message "Error disabling telemetry: $_"
}

# 5) DISABLE ACTIVITY HISTORY
Write-Host "Disabling Activity History..."
Try {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" `
        -Name "PublishUserActivities" -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
    Write-Log -Section "ActivityHistory" -Status "Success" -Message "Disabled activity history"
} Catch {
    Write-Warning "Error disabling activity history: $_"
    Write-Log -Section "ActivityHistory" -Status "Error" -Message "Error disabling activity history: $_"
}

# 6) DISABLE GAMEDVR
Write-Host "Disabling Game DVR..."
Try {
    $gameDVRPaths = @("HKCU:\System\GameConfigStore", "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")
    $gameDVRNames = @{
        "GameDVR_FSEBehavior" = 2
        "GameDVR_Enabled" = 0
        "GameDVR_HonorUserFSEBehaviorMode" = 1
        "GameDVR_EFSEFeatureFlags" = 0
        "AllowGameDVR" = 0
    }
    foreach ($path in $gameDVRPaths) {
        New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        foreach ($n in $gameDVRNames.GetEnumerator()) {
            New-ItemProperty -Path $path -Name $n.Key -PropertyType DWord -Value $n.Value -Force -ErrorAction Stop | Out-Null
        }
    }
    Write-Log -Section "GameDVR" -Status "Success" -Message "Disabled Game DVR"
} Catch {
    Write-Warning "Error disabling Game DVR: $_"
    Write-Log -Section "GameDVR" -Status "Error" -Message "Error disabling Game DVR: $_"
}

# 7) DISABLE HIBERNATION
Write-Host "Disabling hibernation..."
Try {
    powercfg -hibernate off
    Write-Log -Section "Hibernation" -Status "Success" -Message "Disabled hibernation"
} Catch {
    Write-Warning "Error disabling hibernation: $_"
    Write-Log -Section "Hibernation" -Status "Error" -Message "Error disabling hibernation: $_"
}

# 8) DISABLE HOMEGROUP (Windows 7/8/10 only)
if (-not $isWin11) {
    Write-Host "Disabling HomeGroup services..."
    Try {
        $hgSvcs = @("HomeGroupListener", "HomeGroupProvider")
        foreach ($s in $hgSvcs) {
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
                Stop-Service -Name $s -Force -ErrorAction Stop
                Set-Service -Name $s -StartupType Disabled -ErrorAction Stop
            }
        }
        Write-Log -Section "HomeGroup" -Status "Success" -Message "Disabled HomeGroup services"
    } Catch {
        Write-Warning "Error disabling HomeGroup: $_"
        Write-Log -Section "HomeGroup" -Status "Error" -Message "Error disabling HomeGroup: $_"
    }
}

# 9) DISABLE LOCATION TRACKING
Write-Host "Disabling Location Tracking..."
Try {
    $locKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides"
    New-Item -Path $locKey -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $locKey -Name "{ED434E38-EEE3-400B-8F5A-A0C60C88F847},0" `
        -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
    Write-Log -Section "LocationTracking" -Status "Success" -Message "Disabled location tracking"
} Catch {
    Write-Warning "Error disabling location tracking: $_"
    Write-Log -Section "LocationTracking" -Status "Error" -Message "Error disabling location tracking: $_"
}

# 10) DISABLE STORAGE SENSE
Write-Host "Disabling Storage Sense..."
Try {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" `
        -Name "01" -Type DWord -Value 0 -Force -ErrorAction Stop
    Write-Log -Section "StorageSense" -Status "Success" -Message "Disabled Storage Sense"
} Catch {
    Write-Warning "Error disabling Storage Sense: $_"
    Write-Log -Section "StorageSense" -Status "Error" -Message "Error disabling Storage Sense: $_"
}

# 11) DISABLE WIFI-SENSE (Windows 7/8/10 only)
if (-not $isWin11) {
    Write-Host "Disabling WiFi Sense..."
    Try {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" `
            -Name "Value" -Type DWord -Value 0 -Force -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" `
            -Name "Value" -Type DWord -Value 0 -Force -ErrorAction Stop
        Write-Log -Section "WiFiSense" -Status "Success" -Message "Disabled WiFi Sense"
    } Catch {
        Write-Warning "Error disabling WiFi Sense: $_"
        Write-Log -Section "WiFiSense" -Status "Error" -Message "Error disabling WiFi Sense: $_"
    }
}

# 12) ENABLE TASKBAR “END TASK” ON RIGHT-CLICK
Write-Host "Enabling End Task on Taskbar..."
Try {
    $ttPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings"
    New-Item -Path $ttPath -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $ttPath -Name "TaskbarEndTask" -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    Write-Log -Section "TaskbarEndTask" -Status "Success" -Message "Enabled Taskbar End Task"
} Catch {
    Write-Warning "Error enabling Taskbar End Task: $_"
    Write-Log -Section "TaskbarEndTask" -Status "Error" -Message "Error enabling Taskbar End Task: $_"
}

# 13) RUN DISK CLEANUP + COMPONENT CLEANUP (Optional)
if (-not $SkipCleanup) {
    Write-Host "Running Disk Cleanup & component cleanup (async)..."
    Try {
        $job = Start-Job -ScriptBlock {
            if ($using:isWin7or8) {
                Start-Process cleanmgr.exe -ArgumentList "/d C: /VERYLOWDISK" -Wait
            } else {
                Start-Process cleanmgr.exe -ArgumentList "/d C: /VERYLOWDISK" -Wait
                Start-Process Dism.exe -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait
            }
        }
        $job | Wait-Job -Timeout 600 | Out-Null  # 10-minute timeout
        if ($job.State -eq 'Running') {
            Write-Warning "Disk cleanup job timed out after 10 minutes"
            Write-Log -Section "DiskCleanup" -Status "Warning" -Message "Disk cleanup job timed out"
            $job | Stop-Job
        } else {
            Write-Log -Section "DiskCleanup" -Status "Success" -Message "Completed disk cleanup and component cleanup"
        }
        $job | Remove-Job
    } Catch {
        Write-Warning "Error running disk cleanup: $_"
        Write-Log -Section "DiskCleanup" -Status "Error" -Message "Error running disk cleanup: $_"
    }
} else {
    Write-Log -Section "DiskCleanup" -Status "Info" -Message "Skipped disk cleanup due to -SkipCleanup"
}

# 14) INSTALL AND SET POWERSHELL 7 AS DEFAULT
Write-Host "Installing PowerShell 7 and setting as default..."
Try {
    if (-not $isWin7or8) {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Host "Installing winget..."
            $isLtscOrServer = (Get-WindowsEdition -Online).Edition -match "LTSC|Server"
            if ($isLtscOrServer) {
                Write-Host "Detected LTSC/Server; using winget MSI installer..."
                $wingetUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
                $wingetPath = "$env:TEMP\winget.msixbundle"
                Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath
                Add-AppxPackage -Path $wingetPath
                Remove-Item $wingetPath
                Write-Log -Section "WingetInstall" -Status "Success" -Message "Installed winget via MSI"
            } else {
                Try {
                    Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
                    Write-Log -Section "WingetInstall" -Status "Success" -Message "Installed winget via DesktopAppInstaller"
                } Catch {
                    Write-Warning "Could not install winget with DesktopAppInstaller: $_"
                    Try {
                        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.AppInstaller_8wekyb3d8bbwe
                        Write-Log -Section "WingetInstall" -Status "Success" -Message "Installed winget via AppInstaller"
                    } Catch {
                        Write-Warning "Could not install winget with AppInstaller: $_"
                        Write-Log -Section "WingetInstall" -Status "Error" -Message "Failed to install winget: $_"
                    }
                }
            }
        }
        winget install Microsoft.PowerShell --accept-source-agreements --accept-package-agreements
        $wtPath = "$env:LocalAppData\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        if (Test-Path $wtPath) {
            $wtSettings = Get-Content $wtPath | ConvertFrom-Json
            $wtSettings.profiles.defaults.shell = "pwsh"
            $wtSettings | ConvertTo-Json -Depth 10 | Set-Content $wtPath
        }
        Write-Log -Section "PowerShell7" -Status "Success" -Message "Installed and configured PowerShell 7"
    }
} Catch {
    Write-Warning "Could not configure PowerShell 7: $_"
    Write-Log -Section "PowerShell7" -Status "Error" -Message "Could not configure PowerShell 7: $_"
}

# 15) DISABLE POWERSHELL 7 TELEMETRY
Write-Host "Disabling PS7 telemetry..."
Try {
    [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')
    Write-Log -Section "PS7Telemetry" -Status "Success" -Message "Disabled PowerShell 7 telemetry"
} Catch {
    Write-Warning "Error disabling PS7 telemetry: $_"
    Write-Log -Section "PS7Telemetry" -Status "Error" -Message "Error disabling PS7 telemetry: $_"
}

# 16) DISABLE RECALL (Windows 11 24H2 only)
if ($isWin11 -and $osVersion.Build -ge 26100) {
    Write-Host "Disabling Recall feature..."
    Try {
        Dism /Online /Disable-Feature /FeatureName:Recall /Quiet /NoRestart
        Write-Log -Section "Recall" -Status "Success" -Message "Disabled Recall feature"
    } Catch {
        Write-Warning "Error disabling Recall: $_"
        Write-Log -Section "Recall" -Status "Error" -Message "Error disabling Recall: $_"
    }
}

# 17) SET SERVICES TO MANUAL
Write-Host "Adjusting service startup types to Manual..."
Try {
    # Check for proxy configuration
    $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    $proxyExclusions = if ($proxySettings -and $proxySettings.ProxyEnable -eq 1) {
        Write-Warning "Proxy configuration detected. Excluding proxy-related services from modification."
        Write-Log -Section "Services" -Status "Warning" -Message "Proxy configuration detected; excluding proxy-related services"
        @("WinHttpAutoProxySvc", "WebClient")
    } else {
        @()
    }

    $services = @(
        "ALG", "AppIDSvc", "AppMgmt", "AppReadiness", "AppXSvc", "Appinfo", "AxInstSV", "BDESVC",
        "BTAGService", "BcastDVRUserService_*", "BluetoothUserService_*", "Browser", "COMSysApp",
        "CaptureService_*", "CertPropSvc", "ConsentUxUserSvc_*", "CscService", "DcpSvc",
        "DevQueryBroker", "DeviceAssociationBrokerSvc_*", "DeviceAssociationService",
        "DevicePickerUserSvc_*", "DevicesFlowUserSvc_*", "DisplayEnhancementService", "DmEnrollmentSvc",
        "EFS", "EapHost", "EntAppSvc", "FDResPub", "Fax", "FrameServer", "FrameServerMonitor",
        "GraphicsPerfSvc", "HomeGroupListener", "HomeGroupProvider", "HvHost", "IEEtwCollectorService",
        "IKEEXT", "InstallService", "InventorySvc", "IpxlatCfgSvc", "KtmRm", "LicenseManager", "LxpSvc",
        "MSDTC", "MSiSCSI", "McpManagementService", "MessagingService_*", "MicrosoftEdgeElevationService",
        "MixedRealityOpenXRSvc", "MsKeyboardFilter", "NPSMSvc_*", "NaturalAuthentication", "NcaSvc",
        "NcbService", "NcdAutoSetup", "NetSetupSvc", "NgcCtnrSvc", "NgcSvc",
        "P9RdrService_*", "PNRPAutoReg", "PNRPsvc", "PeerDistSvc", "PenService_*", "PerfHost",
        "PhoneSvc", "PimIndexMaintenanceSvc_*", "PrintNotify",
        "PrintWorkflowUserSvc_*", "PushToInstall", "QWAVE", "RasAuto", "RasMan", "RetailDemo", "RmSvc",
        "RpcLocator", "SCPolicySvc", "SCardSvr", "SDRSVC", "SEMgrSvc", "SNMPTRAP", "SSDPSRV",
        "ScDeviceEnum", "SecurityHealthService", "Sense", "SensorDataService", "SensorService",
        "SensrSvc", "SessionEnv", "SharedAccess", "SharedRealitySvc", "SmsRouter", "SstpSvc", "StiSvc",
        "TimeBroker", "TimeBrokerSvc", "TokenBroker", "TroubleshootingSvc", "TrustedInstaller",
        "UI0Detect", "UdkUserSvc_*", "UnistoreSvc_*", "UserDataSvc_*",
        "WEPHOSTSVC", "WFDSConMgrSvc", "WMPNetworkSvc", "WManSvc", "WPDBusEnum", "WSService",
        "WaaSMedicSvc", "WalletService", "WarpJITSvc", "WbioSrvc", "WcsPlugInService", "WdNisSvc",
        "WdiServiceHost", "WdiSystemHost", "Wecsvc", "WerSvc", "WiaRpc",
        "WpcMonSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
        "autotimesvc", "bthserv", "camsvc", "cloudidsvc", "dcsvc", "defragsvc",
        "diagnosticshub.standardcollector.service", "diagsvc", "dmwappushservice", "dot3svc",
        "edgeupdatem", "embeddedmode", "fdPHost", "fhsvc", "hidserv", "icssvc", "lfsvc", "lltdsvc",
        "lmhosts", "msiserver", "netprofm", "p2pimsvc", "p2psvc", "perceptionsimulation", "pla",
        "seclogon", "smphost", "spectrum", "svsvc", "swprv", "upnphost", "vds", "vm3dservice",
        "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown",
        "vmictimesync", "vmicvmsession", "vmicvss", "vmvss", "wbengine", "wcncsvc", "webthreatdefsvc",
        "wercplsupport", "wisvc", "wlidsvc", "wlpasvc", "wmiApSrv", "workfolderssvc", "wudfsvc"
    )

    # Whitelist critical services using patterns
    $whitelistPatterns = @("*vnc*", "TermService", "NlaSvc", "Netman", "WinHttpAutoProxySvc", "W32Time", "WinRM", "UmRdpService", "WebClient", "ClipSVC", "gpsvc", "Dnscache", "WaaSMedicSvc", "PlugPlay", "DeviceInstall")
    $toAdjust = Get-Service | Where-Object {
        $name = $_.Name
        -not ($whitelistPatterns | Where-Object { $name -like $_ }) -and $name -notin $proxyExclusions
    } | Select-Object -ExpandProperty Name

    foreach ($s in $services) {
        if ($s -like "*_*") {
            # Handle wildcard services (e.g., BcastDVRUserService_*)
            $servicePattern = $s -replace "\*$", ""
            $matchingServices = Get-Service -Name "$servicePattern*" -ErrorAction SilentlyContinue | Where-Object { $toAdjust -contains $_.Name }
            foreach ($ms in $matchingServices) {
                Try {
                    Set-Service -Name $ms.Name -StartupType Manual -ErrorAction Stop
                    Write-Log -Section "Services" -Status "Success" -Message "Set service $($ms.Name) to Manual"
                } Catch {
                    Write-Warning "Error setting service $($ms.Name) to Manual: $_"
                    Write-Log -Section "Services" -Status "Error" -Message "Error setting service $($ms.Name) to Manual: $_"
                }
            }
        } else {
            # Handle regular services
            if ($toAdjust -notcontains $s) {
                Write-Log -Section "Services" -Status "Info" -Message "Skipped service $s (whitelisted or proxy-excluded)"
                continue
            }
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
                Try {
                    Set-Service -Name $s -StartupType Manual -ErrorAction Stop
                    Write-Log -Section "Services" -Status "Success" -Message "Set service $s to Manual"
                } Catch {
                    Write-Warning "Error setting service $s to Manual: $_"
                    Write-Log -Section "Services" -Status "Error" -Message "Error setting service $s to Manual: $_"
                }
            }
        }
    }
    Write-Log -Section "Services" -Status "Success" -Message "Completed setting services to Manual"
} Catch {
    Write-Warning "Error adjusting services: $_"
    Write-Log -Section "Services" -Status "Error" -Message "Error adjusting services: $_"
}

# 18) DEBLOAT EDGE
Write-Host "Applying Edge debloat policies..."
Try {
    $edgePolicies = @{
        "CreateDesktopShortcutDefault" = 0
        "PersonalizationReportingEnabled" = 0
        "ShowRecommendationsEnabled" = 0
        "HideFirstRunExperience" = 1
        "UserFeedbackAllowed" = 0
        "ConfigureDoNotTrack" = 1
        "AlternateErrorPagesEnabled" = 0
        "EdgeCollectionsEnabled" = 0
        "EdgeShoppingAssistantEnabled" = 0
        "MicrosoftEdgeInsiderPromotionEnabled" = 0
        "ShowMicrosoftRewards" = 0
        "WebWidgetAllowed" = 0
        "DiagnosticData" = 0
        "EdgeAssetDeliveryServiceEnabled" = 0
        "CryptoWalletEnabled" = 0
        "WalletDonationEnabled" = 0
    }
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force -ErrorAction Stop | Out-Null
    foreach ($k in $edgePolicies.Keys) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
            -Name $k -PropertyType DWord -Value $edgePolicies[$k] -Force -ErrorAction Stop | Out-Null
    }
    Write-Log -Section "EdgeDebloat" -Status "Success" -Message "Applied Edge debloat policies"
} Catch {
    Write-Warning "Error applying Edge debloat: $_"
    Write-Log -Section "EdgeDebloat" -Status "Error" -Message "Error applying Edge debloat: $_"
}

# 19) ADVANCED CAUTION TWEAKS
Write-Host "Applying advanced tweaks..."
Try {
    # Adobe Network Block (idempotent)
    # Note: Remove these entries if Adobe services are required
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $hostsBackup = "$logDir\hosts.backup.$timestamp"
    $adobeBlocks = @(
        "0.0.0.0 adobe.com",
        "0.0.0.0 www.adobe.com",
        "0.0.0.0 activate.adobe.com"
    )
    Try {
        Copy-Item -Path $hostsPath -Destination $hostsBackup -Force
        Write-Log -Section "AdobeBlock" -Status "Success" -Message "Backed up hosts file to $hostsBackup"
    } Catch {
        Write-Warning "Could not back up hosts file: $_"
        Write-Log -Section "AdobeBlock" -Status "Error" -Message "Could not back up hosts file: $_"
        throw "Hosts file backup failed; skipping modifications"
    }
    foreach ($entry in $adobeBlocks) {
        Try {
            if (-not (Select-String -Path $hostsPath -Pattern [regex]::Escape($entry))) {
                Add-Content -Path $hostsPath -Value $entry -ErrorAction Stop
                $hostsModified = $true
            }
        } Catch {
            Write-Warning "Could not modify hosts file for $entry: $_"
            Write-Log -Section "AdobeBlock" -Status "Error" -Message "Could not modify hosts file for $entry: $_"
        }
    }
    # Delay DNS flush until script completion if VNC is active
    if ($hostsModified) {
        $vncActive = Get-Process -Name "vncviewer", "vncserver" -ErrorAction SilentlyContinue
        if ($vncActive) {
            Write-Log -Section "AdobeBlock" -Status "Info" -Message "Delaying ipconfig /flushdns due to active VNC session"
        } else {
            ipconfig /flushdns
            Write-Log -Section "AdobeBlock" -Status "Success" -Message "Flushed DNS cache"
        }
    }

    # Disable Copilot (Windows 11)
    if ($isWin11) {
        Write-Host "Disabling Copilot..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
            -Name "ShowCopilotButton" -Type DWord -Value 0 -Force -ErrorAction Stop
    }

    # Disable Notifications
    Write-Host "Disabling notifications..."
    $notifyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"
    New-Item -Path $notifyPath -Force -ErrorAction Stop | Out-Null
    Set-ItemProperty -Path $notifyPath -Name "Enabled" -Type DWord -Value 0 -Force -ErrorAction Stop

    Write-Log -Section "AdvancedTweaks" -Status "Success" -Message "Applied advanced tweaks"
} Catch {
    Write-Warning "Error applying advanced tweaks: $_"
    Write-Log -Section "AdvancedTweaks" -Status "Error" -Message "Error applying advanced tweaks: $_"
}

# 20) SET DISPLAY FOR PERFORMANCE
Write-Host "Tuning visual effects for performance..."
Try {
    $perfKeys = @(
        @{Path="HKCU:\Control Panel\Desktop"; Name="DragFullWindows"; Value="0"; Type="String"},
        @{Path="HKCU:\Control Panel\Desktop"; Name="MenuShowDelay"; Value="200"; Type="String"},
        @{Path="HKCU:\Control Panel\Desktop\WindowMetrics"; Name="MinAnimate"; Value="0"; Type="String"},
        @{Path="HKCU:\Control Panel\Keyboard"; Name="KeyboardDelay"; Value=0; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ListviewAlphaSelect"; Value=0; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ListviewShadow"; Value=0; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarAnimations"; Value=0; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"; Name="VisualFXSetting"; Value=3; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\DWM"; Name="EnableAeroPeek"; Value=0; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarMn"; Value=0; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarDa"; Value=0; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ShowTaskViewButton"; Value=0; Type="DWord"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="SearchboxTaskbarMode"; Value=0; Type="DWord"}
    )
    foreach ($k in $perfKeys) {
        New-Item -Path $k.Path -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $k.Path -Name $k.Name -PropertyType $k.Type `
            -Value $k.Value -Force -ErrorAction Stop | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" `
        -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0)) -Force -ErrorAction Stop
    Write-Log -Section "VisualEffects" -Status "Success" -Message "Tuned visual effects for performance"
} Catch {
    Write-Warning "Error tuning visual effects: $_"
    Write-Log -Section "VisualEffects" -Status "Error" -Message "Error tuning visual effects: $_"
}

# 21) REMOVE SELECTED MS STORE APPS
Write-Host "Removing selected Microsoft Store apps..."
# Note: Removed provisioned packages are destructive. To re-provision, use Add-AppxProvisionedPackage.
Try {
    $keepApps = @("Microsoft.WindowsStore", "Microsoft.WindowsCalculator", "Microsoft.DesktopAppInstaller")
    $appxPackages = @(
        "Microsoft.Microsoft3DViewer",
        "Microsoft.AppConnector",
        "Microsoft.BingFinance",
        "Microsoft.BingNews",
        "Microsoft.BingSports",
        "Microsoft.BingTranslator",
        "Microsoft.BingWeather",
        "Microsoft.GamingServices",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Messaging",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.NetworkSpeedTest",
        "Microsoft.News",
        "Microsoft.Office.Lens",
        "Microsoft.Office.OneNote",
        "Microsoft.People",
        "Microsoft.Print3D",
        "Microsoft.SkypeApp",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsCommunicationsApps",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.MixedReality.Portal",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "*CandyCrush*",
        "*BubbleWitch3Saga*",
        "*Twitter*",
        "*Facebook*",
        "*Netflix*",
        "*Hulu*"
    )

    # Check for VNC-related UWP apps
    $vncUwp = Get-AppxPackage -Name "RealVNC.VNCViewer" -AllUsers -ErrorAction SilentlyContinue
    if ($vncUwp) {
        Write-Warning "VNC Viewer UWP app detected. Skipping UWP app removal to avoid breaking remote access."
        Write-Log -Section "StoreApps" -Status "Warning" -Message "VNC Viewer UWP app detected; skipping UWP app removal"
    } else {
        foreach ($name in $appxPackages) {
            if ($name -in $keepApps) {
                Write-Log -Section "StoreApps" -Status "Info" -Message "Skipped package $name (preserved)"
                continue
            }
            $packages = Get-AppxPackage -Name $name -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $keepApps }
            if ($packages) {
                $packages | Remove-AppxPackage -AllUsers -ErrorAction Stop
                Write-Log -Section "StoreApps" -Status "Success" -Message "Removed Appx package: $name"
            }
            $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $name -and $_.DisplayName -notin $keepApps }
            if ($provisioned) {
                $provisioned | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
                Write-Log -Section "StoreApps" -Status "Success" -Message "Removed provisioned package: $name"
            }
        }
    }
    Write-Log -Section "StoreApps" -Status "Success" -Message "Completed removal of selected Microsoft Store apps"
} Catch {
    Write-Warning "Error removing Store apps: $_"
    Write-Log -Section "StoreApps" -Status "Error" -Message "Error removing Store apps: $_"
}

# 22) CONFIGURE WINDOWS UPDATE
Write-Host "Configuring Windows Update to Manual..."
Try {
    if (Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue) {
        Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction Stop
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Section "WindowsUpdate" -Status "Success" -Message "Set Windows Update to Manual"
} Catch {
    Write-Warning "Error configuring Windows Update: $_"
    Write-Log -Section "WindowsUpdate" -Status "Error" -Message "Error configuring Windows Update: $_"
}

# 23) FINAL CLEANUP AND REBOOT PROMPT
Write-Host "All optimizations applied." -ForegroundColor Green
Write-Log -Section "Completion" -Status "Info" -Message "All optimizations applied"

# Perform delayed DNS flush if needed
if ($hostsModified) {
    Try {
        ipconfig /flushdns
        Write-Log -Section "AdobeBlock" -Status "Success" -Message "Flushed DNS cache (delayed)"
    } Catch {
        Write-Warning "Error flushing DNS cache: $_"
        Write-Log -Section "AdobeBlock" -Status "Error" -Message "Error flushing DNS cache: $_"
    }
}

Stop-Transcript

if (-not $NoReboot) {
    Write-Host "A reboot is recommended to apply all changes."
    $response = Read-Host "Reboot now? [Y/N] (default: N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Log -Section "Reboot" -Status "Info" -Message "Initiating reboot"
        Restart-Computer -Force
    } else {
        Write-Log -Section "Reboot" -Status "Info" -Message "Reboot skipped by user"
    }
} else {
    Write-Log -Section "Reboot" -Status "Info" -Message "Reboot skipped due to -NoReboot parameter"
}
