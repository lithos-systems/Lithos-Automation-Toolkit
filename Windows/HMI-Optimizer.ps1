<#
.SYNOPSIS
  HMI Optimization Script - Optimizes Windows for a clean, efficient HMI application.
  Run using:
    iex (iwr "https://raw.githubusercontent.com/lithos-systems/Lithos-Automation-Toolkit/main/Windows/HMI-Optimizer.ps1" -UseBasicParsing).Content
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
.PARAMETER Verbose
  Enables detailed console output for debugging; without this, console output is minimal for unattended runs.
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
    [switch]$JsonLog,
    [switch]$Verbose
)

# ——————————————————————————————————————————————
# GLOBAL SETTINGS
# ——————————————————————————————————————————————
$ErrorActionPreference = 'Stop'

# Minimum OS and PowerShell check
$osVersion = [System.Environment]::OSVersion.Version
$psVersion = $PSVersionTable.PSVersion
$minOsBuild = [Version]"6.1"  # Windows 7
$minPsVersion = [Version]"5.1"
if ($osVersion -lt $minOsBuild) {
    Write-Error "Requires Windows 7 or later. Current: $osVersion"
    exit 1
}
if ($psVersion -lt $minPsVersion) {
    Write-Error "Requires PowerShell 5.1 or later. Current: $psVersion"
    exit 1
}

# Elevate if needed
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Relaunching as Administrator..."
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    $argList += $PSBoundParameters.GetEnumerator() | ForEach-Object { "-$($_.Key)" + $(if ($_.Value -is [switch]) { '' } else { " `"$($_.Value)`"" }) }
    Start-Process powershell -ArgumentList $argList -Verb RunAs
    exit
}

# Logging setup
$logDir = "C:\Logs"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop }
Start-Transcript -Path "$logDir\HMIOptimize_$timestamp.log" -NoClobber

# Ternary fix for extension
$extension = if ($JsonLog) { 'json' } else { 'csv' }
$logPath = "$logDir\HMIOptimize_$timestamp.$extension"
$hostsModified = $false

function Write-Log {
    param($Section, $Status, $Message)
    $entry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        Section   = $Section
        Status    = $Status
        Message   = $Message
    }
    if ($JsonLog) {
        $entry | ConvertTo-Json -Depth 3 | Add-Content -Path $logPath -ErrorAction Stop
    } else {
        $entry | Export-Csv -Path $logPath -Append -NoTypeInformation -Force -ErrorAction Stop
    }
}

Write-Log -Section "Initialization" -Status "Info" -Message "Script started (elevated)"

# ——————————————————————————————————————————————
# HANDLE HOSTS RESTORE
# ——————————————————————————————————————————————
if ($RestoreHosts) {
    Write-Verbose "Restoring hosts file from backup..."
    try {
        $latest = Get-ChildItem "$logDir\hosts.backup.*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) {
            Copy-Item -Path $latest.FullName -Destination "C:\Windows\System32\drivers\etc\hosts" -Force -ErrorAction Stop
            Write-Log -Section "HostsRestore" -Status "Success" -Message "Restored from $($latest.FullName)"
        } else {
            Write-Warning "No backup found"
            Write-Log -Section "HostsRestore" -Status "Warning" -Message "No backup found"
        }
    } catch {
        Write-Warning "Restore failed: $($_.Exception.Message)"
        Write-Log -Section "HostsRestore" -Status "Error" -Message "Restore failed: $($_.Exception.Message)"
    }
    Stop-Transcript
    exit
}

# ——————————————————————————————————————————————
# INITIAL PROMPT
# ——————————————————————————————————————————————
if (-not ($NoReboot -or $Force)) {
    Write-Host "This will optimize Windows for HMI:"
    Write-Host " • Remove bloatware"
    Write-Host " • Disable telemetry & consumer features"
    Write-Host " • Set many services to Manual (whitelisting networking/RDP)"
    Write-Host " • Performance tweaks"
    Write-Host "Requires Admin, may reboot. Logs: $logPath"
    $r = Read-Host "Proceed? [Y/N]"
    if ($r -notin 'Y','y') {
        Write-Host "Aborted."
        Write-Log -Section "Initialization" -Status "Info" -Message "User aborted"
        Stop-Transcript
        exit
    }
}

# OS detection
$isWin11 = $osVersion.Build -ge 22000
$isWin7or8 = $osVersion.Major -eq 6 -and $osVersion.Minor -in 1,2

Write-Verbose "Running on build $osVersion"
Write-Log -Section "Initialization" -Status "Info" -Message "Detected Windows Build $osVersion"

# ——————————————————————————————————————————————
# 1) CREATE RESTORE POINT
# ——————————————————————————————————————————————
Write-Verbose "Creating restore point…"
try {
    if (-not $isWin7or8) {
        Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
        Checkpoint-Computer -Description "Pre-Optimization" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Log -Section "RestorePoint" -Status "Success" -Message "Created"
    } else {
        Write-Log -Section "RestorePoint" -Status "Info" -Message "Skipped on Windows 7/8"
    }
} catch {
    Write-Warning "Restore point failed: $($_.Exception.Message)"
    Write-Log -Section "RestorePoint" -Status "Error" -Message "Failed: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 2) CLEAN TEMP
# ——————————————————————————————————————————————
Write-Verbose "Cleaning Temp folders…"
try {
    $tempPaths = @("C:\Windows\Temp", "$env:TEMP", "$env:LocalAppData\Microsoft\Windows\INetCache")
    foreach ($p in $tempPaths) {
        Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Section "TempCleanup" -Status "Success" -Message "Cleared"
} catch {
    Write-Warning "Temp cleanup error: $($_.Exception.Message)"
    Write-Log -Section "TempCleanup" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 3) DISABLE CONSUMER FEATURES
# ——————————————————————————————————————————————
Write-Verbose "Disabling consumer features…"
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        -Name DisableWindowsConsumerFeatures -Type DWord -Value 1 -Force -ErrorAction Stop
    Write-Log -Section "ConsumerFeatures" -Status "Success" -Message "Disabled"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "ConsumerFeatures" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 4) DISABLE TELEMETRY
# ——————————————————————————————————————————————
Write-Verbose "Disabling telemetry…"
try {
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
        try { Disable-ScheduledTask -TaskPath ($t | Split-Path -Parent) -TaskName ($t | Split-Path -Leaf) -ErrorAction Stop }
        catch { Write-Verbose "  ↳ Could not disable: $($t)" }
    }

    $regPaths = @(
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="ContentDeliveryAllowed"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="OemPreInstalledAppsEnabled"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEverEnabled"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338387Enabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338388Enabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338389Enabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353698Enabled"; Value=0},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SystemPaneSuggestionsEnabled"; Value=0}
    )
    foreach ($r in $regPaths) {
        New-Item -Path $r.Path -Force -ErrorAction Stop
        New-ItemProperty -Path $r.Path -Name $r.Name -PropertyType DWord -Value $r.Value -Force -ErrorAction Stop
    }

    Write-Log -Section "Telemetry" -Status "Success" -Message "Disabled"
} catch {
    Write-Warning "Telemetry error: $($_.Exception.Message)"
    Write-Log -Section "Telemetry" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 5) DISABLE ACTIVITY HISTORY
# ——————————————————————————————————————————————
Write-Verbose "Disabling Activity History…"
try {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force -ErrorAction Stop
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" `
        -Name "PublishUserActivities" -PropertyType DWord -Value 0 -Force -ErrorAction Stop
    Write-Log -Section "ActivityHistory" -Status "Success" -Message "Disabled"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "ActivityHistory" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 6) DISABLE GAMEDVR
# ——————————————————————————————————————————————
Write-Verbose "Disabling Game DVR…"
try {
    $gameDVRPaths = @("HKCU:\System\GameConfigStore", "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")
    $gameDVRNames = @{
        "GameDVR_FSEBehavior" = 2
        "GameDVR_Enabled" = 0
        "GameDVR_HonorUserFSEBehaviorMode" = 1
        "GameDVR_EFSEFeatureFlags" = 0
        "AllowGameDVR" = 0
    }
    foreach ($path in $gameDVRPaths) {
        New-Item -Path $path -Force -ErrorAction Stop
        foreach ($n in $gameDVRNames.GetEnumerator()) {
            New-ItemProperty -Path $path -Name $n.Key -PropertyType DWord -Value $n.Value -Force -ErrorAction Stop
        }
    }
    Write-Log -Section "GameDVR" -Status "Success" -Message "Disabled"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "GameDVR" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 7) DISABLE HIBERNATION
# ——————————————————————————————————————————————
Write-Verbose "Disabling hibernation…"
try {
    powercfg -hibernate off
    Write-Log -Section "Hibernation" -Status "Success" -Message "Disabled"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "Hibernation" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 8) DISABLE HOMEGROUP (Windows 7/8/10 only)
# ——————————————————————————————————————————————
if (-not $isWin11) {
    Write-Verbose "Disabling HomeGroup services…"
    try {
        $hgSvcs = @("HomeGroupListener", "HomeGroupProvider")
        foreach ($s in $hgSvcs) {
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
                Stop-Service -Name $s -Force -ErrorAction Stop
                Set-Service -Name $s -StartupType Disabled -ErrorAction Stop
            }
        }
        Write-Log -Section "HomeGroup" -Status "Success" -Message "Disabled"
    } catch {
        Write-Warning "Error: $($_.Exception.Message)"
        Write-Log -Section "HomeGroup" -Status "Error" -Message "Error: $($_.Exception.Message)"
    }
}

# ——————————————————————————————————————————————
# 9) DISABLE LOCATION TRACKING
# ——————————————————————————————————————————————
Write-Verbose "Disabling Location Tracking…"
try {
    $locKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides"
    New-Item -Path $locKey -Force -ErrorAction Stop
    New-ItemProperty -Path $locKey -Name "{ED434E38-EEE3-400B-8F5A-A0C60C88F847},0" `
        -PropertyType DWord -Value 0 -Force -ErrorAction Stop
    Write-Log -Section "LocationTracking" -Status "Success" -Message "Disabled"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "LocationTracking" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 10) DISABLE STORAGE SENSE
# ——————————————————————————————————————————————
Write-Verbose "Disabling Storage Sense…"
try {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" `
        -Name "01" -Type DWord -Value 0 -Force -ErrorAction Stop
    Write-Log -Section "StorageSense" -Status "Success" -Message "Disabled"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "StorageSense" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 11) DISABLE WIFI-SENSE (Windows 7/8/10 only)
# ——————————————————————————————————————————————
if (-not $isWin11) {
    Write-Verbose "Disabling WiFi Sense…"
    try {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" `
            -Name "Value" -Type DWord -Value 0 -Force -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" `
            -Name "Value" -Type DWord -Value 0 -Force -ErrorAction Stop
        Write-Log -Section "WiFiSense" -Status "Success" -Message "Disabled"
    } catch {
        Write-Warning "Error: $($_.Exception.Message)"
        Write-Log -Section "WiFiSense" -Status "Error" -Message "Error: $($_.Exception.Message)"
    }
}

# ——————————————————————————————————————————————
# 12) ENABLE TASKBAR “END TASK” ON RIGHT-CLICK
# ——————————————————————————————————————————————
Write-Verbose "Enabling End Task on Taskbar…"
try {
    $ttPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings"
    New-Item -Path $ttPath -Force -ErrorAction Stop
    New-ItemProperty -Path $ttPath -Name "TaskbarEndTask" -PropertyType DWord -Value 1 -Force -ErrorAction Stop
    Write-Log -Section "TaskbarEndTask" -Status "Success" -Message "Enabled"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "TaskbarEndTask" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 13) RUN DISK CLEANUP + COMPONENT CLEANUP (Optional)
# ——————————————————————————————————————————————
if (-not $SkipCleanup) {
    Write-Verbose "Running Disk Cleanup & component cleanup (async)…"
    try {
        $job = Start-Job -ScriptBlock {
            if ($using:isWin7or8) {
                Start-Process cleanmgr.exe -ArgumentList "/d C: /VERYLOWDISK" -Wait
            } else {
                Start-Process cleanmgr.exe -ArgumentList "/d C: /VERYLOWDISK" -Wait
            }
        }
        $startTime = (Get-Job $job.Id).PSBeginTime
        $job | Wait-Job -Timeout 600 | Out-Null  # 10-minute timeout
        $duration = if ($job.State -eq 'Completed') { ((Get-Job $job.Id).PSEndTime - $startTime).TotalSeconds } else { 'Timed out' }
        if ($job.State -eq 'Running') {
            Write-Warning "Disk cleanup job timed out after 10 minutes"
            Write-Log -Section "DiskCleanup" -Status "Warning" -Message "Timed out after 600 seconds"
            $job | Stop-Job
        } else {
            Write-Log -Section "DiskCleanup" -Status "Success" -Message "Completed in $($duration) seconds"
        }
        $job | Remove-Job
    } catch {
        Write-Warning "Error: $($_.Exception.Message)"
        Write-Log -Section "DiskCleanup" -Status "Error" -Message "Error: $($_.Exception.Message)"
    }
} else {
    Write-Log -Section "DiskCleanup" -Status "Info" -Message "Skipped (-SkipCleanup)"
}

# ——————————————————————————————————————————————
# 14) INSTALL AND SET POWERSHELL 7 AS DEFAULT
# ——————————————————————————————————————————————
Write-Verbose "Installing PowerShell 7 and setting as default…"
try {
    if (-not $isWin7or8) {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Verbose "Installing winget…"
            $isLtscOrServer = (Get-WindowsEdition -Online).Edition -match "LTSC|Server"
            if ($isLtscOrServer) {
                Write-Verbose "Detected LTSC/Server; using winget MSI installer…"
                $wingetUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
                $wingetPath = "$env:TEMP\winget.msixbundle"
                Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath -UseBasicParsing -ErrorAction Stop
                Add-AppxPackage -Path $wingetPath -ErrorAction Stop
                Remove-Item -Path $wingetPath -Force -ErrorAction Stop
                Write-Log -Section "WingetInstall" -Status "Success" -Message "Installed via MSI"
            } else {
                try {
                    Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop
                    Write-Log -Section "WingetInstall" -Status "Success" -Message "Installed via DesktopAppInstaller"
                } catch {
                    Write-Warning "DesktopAppInstaller failed: $($_.Exception.Message)"
                    try {
                        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.AppInstaller_8wekyb3d8bbwe -ErrorAction Stop
                        Write-Log -Section "WingetInstall" -Status "Success" -Message "Installed via AppInstaller"
                    } catch {
                        Write-Warning "AppInstaller failed: $($_.Exception.Message)"
                        Write-Log -Section "WingetInstall" -Status "Error" -Message "Failed: $($_.Exception.Message)"
                    }
                }
            }
        }
        winget install Microsoft.PowerShell --accept-source-agreements --accept-package-agreements
        $wtPath = "$env:LocalAppData\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        if (Test-Path $wtPath) {
            $wtSettings = Get-Content $wtPath | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($wtSettings -and $wtSettings.profiles -and $wtSettings.profiles.defaults) {
                $wtSettings.profiles.defaults | Add-Member -MemberType NoteProperty -Name shell -Value "pwsh" -Force
                $wtSettings | ConvertTo-Json -Depth 10 | Set-Content $wtPath -ErrorAction Stop
            } else {
                Write-Warning "Windows Terminal settings.json is invalid or missing profiles.defaults"
                Write-Log -Section "PowerShell7" -Status "Warning" -Message "Skipped shell configuration: invalid settings.json"
            }
        } else {
            Write-Warning "Windows Terminal settings.json not found"
            Write-Log -Section "PowerShell7" -Status "Warning" -Message "Skipped shell configuration: settings.json not found"
        }
        Write-Log -Section "PowerShell7" -Status "Success" -Message "Installed and configured"
    } else {
        Write-Log -Section "PowerShell7" -Status "Info" -Message "Skipped on Windows 7/8"
    }
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "PowerShell7" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 15) DISABLE POWERSHELL 7 TELEMETRY
# ——————————————————————————————————————————————
Write-Verbose "Disabling PS7 telemetry…"
try {
    [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')
    Write-Log -Section "PS7Telemetry" -Status "Success" -Message "Disabled"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "PS7Telemetry" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 16) DISABLE RECALL (Windows 11 24H2 only)
# ——————————————————————————————————————————————
if ($isWin11 -and $osVersion.Build -ge 26100) {
    Write-Verbose "Disabling Recall feature…"
    try {
        Dism /Online /Disable-Feature /FeatureName:Recall /Quiet /NoRestart
        Write-Log -Section "Recall" -Status "Success" -Message "Disabled"
    } catch {
        Write-Warning "Error: $($_.Exception.Message)"
        Write-Log -Section "Recall" -Status "Error" -Message "Error: $($_.Exception.Message)"
    }
}

# ——————————————————————————————————————————————
# 17) SET SERVICES TO MANUAL
# ——————————————————————————————————————————————
Write-Verbose "Adjusting service startup types to Manual…"
try {
    $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    $proxyExclusions = if ($proxySettings -and $proxySettings.ProxyEnable -eq 1) {
        Write-Warning "Proxy configuration detected. Excluding proxy-related services."
        Write-Log -Section "Services" -Status "Warning" -Message "Proxy detected; excluding proxy services"
        @("WinHttpAutoProxySvc", "WebClient")
    } else {
        @()
    }

    $services = @(
        "ALG", "AppMgmt", "AppReadiness", "Appinfo", "AxInstSV", "BDESVC",
        "BTAGService", "Browser", "COMSysApp",
        "CertPropSvc", "CscService", "DcpSvc",
        "DevQueryBroker", "DeviceAssociationService",
        "DisplayEnhancementService", "DmEnrollmentSvc",
        "EFS", "EapHost", "FDResPub", "Fax", "FrameServer", "FrameServerMonitor",
        "GraphicsPerfSvc", "HomeGroupListener", "HomeGroupProvider", "HvHost", "IEEtwCollectorService",
        "IKEEXT", "InstallService", "InventorySvc", "IpxlatCfgSvc", "KtmRm", "LicenseManager", "LxpSvc",
        "MSDTC", "MSiSCSI", "McpManagementService", "MicrosoftEdgeElevationService",
        "MixedRealityOpenXRSvc", "MsKeyboardFilter", "NaturalAuthentication", "NcaSvc",
        "NcbService", "NcdAutoSetup", "NetSetupSvc",
        "PNRPAutoReg", "PNRPsvc", "PeerDistSvc", "PerfHost",
        "PhoneSvc", "PrintNotify",
        "PushToInstall", "QWAVE", "RasAuto", "RasMan", "RetailDemo", "RmSvc",
        "RpcLocator", "SCPolicySvc", "SCardSvr", "SDRSVC", "SEMgrSvc", "SNMPTRAP", "SSDPSRV",
        "ScDeviceEnum", "SensorDataService", "SensorService",
        "SensrSvc", "SessionEnv", "SharedAccess", "SharedRealitySvc", "SmsRouter", "SstpSvc", "StiSvc",
        "TimeBroker", "TokenBroker", "TroubleshootingSvc", "TrustedInstaller",
        "UI0Detect", "WEPHOSTSVC", "WFDSConMgrSvc", "WMPNetworkSvc", "WManSvc", "WPDBusEnum", "WSService",
        "WaaSMedicSvc", "WalletService", "WarpJITSvc", "WbioSrvc", "WcsPlugInService",
        "WdiServiceHost", "WdiSystemHost", "Wecsvc", "WerSvc", "WiaRpc",
        "WpcMonSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
        "autotimesvc", "bthserv", "camsvc", "cloudidsvc", "dcsvc", "defragsvc",
        "diagnosticshub.standardcollector.service", "diagsvc", "dmwappushservice", "dot3svc",
        "edgeupdatem", "fdPHost", "fhsvc", "hidserv", "icssvc", "lfsvc", "lltdsvc",
        "lmhosts", "netprofm", "p2pimsvc", "p2psvc", "perceptionsimulation", "pla",
        "seclogon", "smphost", "spectrum", "svsvc", "swprv", "upnphost", "vds", "vm3dservice",
        "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown",
        "vmictimesync", "vmicvmsession", "vmicvss", "vmvss", "wbengine", "wcncsvc", "webthreatdefsvc",
        "wercplsupport", "wisvc", "wlidsvc", "wlpasvc", "wmiApSrv", "workfolderssvc", "wudfsvc"
    )

    $protectedServices = @(
        "AppIDSvc", "AppXSvc", "EntAppSvc", "NgcCtnrSvc", "NgcSvc", "PrintWorkflowUserSvc_*",
        "SecurityHealthService", "Sense", "TimeBrokerSvc", "WdNisSvc", "embeddedmode", "msiserver"
    )
    $whitelistPatterns = @("*vnc*", "TermService", "NlaSvc", "Netman", "WinHttpAutoProxySvc", "W32Time", "WinRM", "UmRdpService", "WebClient", "ClipSVC", "gpsvc", "Dnscache", "WaaSMedicSvc", "PlugPlay", "DeviceInstall")
    $toAdjust = Get-Service | Where-Object {
        $name = $_.Name
        -not ($whitelistPatterns | Where-Object { $name -like $_ }) -and $name -notin $proxyExclusions
    } | Select-Object -ExpandProperty Name

    foreach ($s in $services) {
        if ($s -in $protectedServices -or ($s -like "*_*" -and $protectedServices -contains ($s -replace "_.*", ""))) {
            Write-Log -Section "Services" -Status "Info" -Message "Skipped $($s) (protected service)"
            continue
        }
        if ($s -like "*_*") {
            $servicePattern = $s -replace "\*$", ""
            $matchingServices = Get-Service -Name "$servicePattern*" -ErrorAction SilentlyContinue | Where-Object { $toAdjust -contains $_.Name }
            foreach ($ms in $matchingServices) {
                try {
                    Set-Service -Name $ms.Name -StartupType Manual -ErrorAction Stop
                    Write-Log -Section "Services" -Status "Success" -Message "Set $($ms.Name) to Manual"
                } catch {
                    if ($_.Exception.Message -match "parameter is incorrect") {
                        Write-Warning "Cannot set startup type for per-user service $($ms.Name)"
                        Write-Log -Section "Services" -Status "Warning" -Message "Skipped $($ms.Name): per-user service"
                    } else {
                        Write-Warning "Error setting $($ms.Name): $($_.Exception.Message)"
                        Write-Log -Section "Services" -Status "Error" -Message "Error setting $($ms.Name): $($_.Exception.Message)"
                    }
                }
            }
        } else {
            if ($toAdjust -notcontains $s) {
                Write-Log -Section "Services" -Status "Info" -Message "Skipped $($s) (whitelisted or proxy-excluded)"
                continue
            }
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
                try {
                    Set-Service -Name $s -StartupType Manual -ErrorAction Stop
                    Write-Log -Section "Services" -Status "Success" -Message "Set $($s) to Manual"
                } catch {
                    Write-Warning "Error setting $($s): $($_.Exception.Message)"
                    Write-Log -Section "Services" -Status "Error" -Message "Error setting $($s): $($_.Exception.Message)"
                }
            }
        }
    }
    Write-Log -Section "Services" -Status "Success" -Message "Completed"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "Services" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 18) DEBLOAT EDGE
# ——————————————————————————————————————————————
Write-Verbose "Applying Edge debloat policies…"
try {
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
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force -ErrorAction Stop
    foreach ($k in $edgePolicies.Keys) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name $k -PropertyType DWord -Value $edgePolicies[$k] -Force -ErrorAction Stop
    }
    Write-Log -Section "EdgeDebloat" -Status "Success" -Message "Applied"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "EdgeDebloat" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 19) ADVANCED CAUTION TWEAKS
# ——————————————————————————————————————————————
Write-Verbose "Applying advanced tweaks…"
try {
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $hostsBackup = "$logDir\hosts.backup.$timestamp"
    $adobeBlocks = @(
        "0.0.0.0 adobe.com",
        "0.0.0.0 www.adobe.com",
        "0.0.0.0 activate.adobe.com"
    )
    try {
        Copy-Item -Path $hostsPath -Destination $hostsBackup -Force -ErrorAction Stop
        Write-Log -Section "AdobeBlock" -Status "Success" -Message "Backed up to $($hostsBackup)"
    } catch {
        Write-Warning "Backup failed: $($_.Exception.Message)"
        Write-Log -Section "AdobeBlock" -Status "Error" -Message "Backup failed: $($_.Exception.Message)"
        throw "Hosts file backup failed; skipping modifications"
    }
    foreach ($entry in $adobeBlocks) {
        try {
            if (-not (Select-String -Path $hostsPath -Pattern ([regex]::Escape($entry)) -Quiet)) {
                Add-Content -Path $hostsPath -Value $entry -ErrorAction Stop
                $hostsModified = $true
            }
        } catch {
            Write-Warning "Error for $($entry): $($_.Exception.Message)"
            Write-Log -Section "AdobeBlock" -Status "Error" -Message "Error for $($entry): $($_.Exception.Message)"
        }
    }
    if ($hostsModified) {
        $vncActive = Get-Process -Name "vncviewer", "vncserver" -ErrorAction SilentlyContinue
        if ($vncActive) {
            Write-Log -Section "AdobeBlock" -Status "Info" -Message "Delaying ipconfig /flushdns due to VNC"
        } else {
            ipconfig /flushdns
            Write-Log -Section "AdobeBlock" -Status "Success" -Message "Flushed DNS"
        }
    }

    if ($isWin11) {
        Write-Verbose "Disabling Copilot…"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
            -Name "ShowCopilotButton" -Type DWord -Value 0 -Force -ErrorAction Stop
    }

    Write-Verbose "Disabling notifications…"
    $notifyParent = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications"
    $notifyPath = "$notifyParent\Settings"
    New-Item -Path $notifyParent -Force -ErrorAction Stop
    New-Item -Path $notifyPath -Force -ErrorAction Stop
    Set-ItemProperty -Path $notifyPath -Name "Enabled" -Type DWord -Value 0 -Force -ErrorAction Stop

    Write-Log -Section "AdvancedTweaks" -Status "Success" -Message "Applied"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "AdvancedTweaks" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 20) SET DISPLAY FOR PERFORMANCE
# ——————————————————————————————————————————————
Write-Verbose "Tuning visual effects for performance…"
try {
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
        New-Item -Path $k.Path -Force -ErrorAction Stop
        New-ItemProperty -Path $k.Path -Name $k.Name -PropertyType $k.Type -Value $k.Value -Force -ErrorAction Stop
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0)) -Force -ErrorAction Stop
    Write-Log -Section "VisualEffects" -Status "Success" -Message "Tuned"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "VisualEffects" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 21) REMOVE SELECTED MS STORE APPS
# ——————————————————————————————————————————————
Write-Verbose "Removing selected Microsoft Store apps…"
try {
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

    $vncUwp = Get-AppxPackage -Name "RealVNC.VNCViewer" -AllUsers -ErrorAction SilentlyContinue
    if ($vncUwp) {
        Write-Warning "VNC Viewer UWP app detected. Skipping UWP app removal."
        Write-Log -Section "StoreApps" -Status "Warning" -Message "VNC Viewer UWP detected; skipping removal"
    } else {
        foreach ($name in $appxPackages) {
            if ($name -in $keepApps) {
                Write-Log -Section "StoreApps" -Status "Info" -Message "Skipped $($name) (preserved)"
                continue
            }
            $packages = Get-AppxPackage -Name $name -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $keepApps }
            if ($packages) {
                $packages | Remove-AppxPackage -AllUsers -ErrorAction Stop
                Write-Log -Section "StoreApps" -Status "Success" -Message "Removed $($name)"
            }
            $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $name -and $_.DisplayName -notin $keepApps }
            if ($provisioned) {
                $provisioned | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
                Write-Log -Section "StoreApps" -Status "Success" -Message "Removed provisioned $($name)"
            }
        }
    }
    Write-Log -Section "StoreApps" -Status "Success" -Message "Completed"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "StoreApps" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 22) CONFIGURE WINDOWS UPDATE
# ——————————————————————————————————————————————
Write-Verbose "Configuring Windows Update to Manual…"
try {
    if (Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue) {
        Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction Stop
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Section "WindowsUpdate" -Status "Success" -Message "Set to Manual"
} catch {
    Write-Warning "Error: $($_.Exception.Message)"
    Write-Log -Section "WindowsUpdate" -Status "Error" -Message "Error: $($_.Exception.Message)"
}

# ——————————————————————————————————————————————
# 23) FINAL CLEANUP AND REBOOT PROMPT
# ——————————————————————————————————————————————
Write-Host "All optimizations applied." -ForegroundColor Green
Write-Log -Section "Completion" -Status "Info" -Message "Done"

if ($hostsModified) {
    try {
        ipconfig /flushdns
        Write-Log -Section "AdobeBlock" -Status "Success" -Message "Flushed DNS (delayed)"
    } catch {
        Write-Warning "DNS flush error: $($_.Exception.Message)"
        Write-Log -Section "AdobeBlock" -Status "Error" -Message "Error: $($_.Exception.Message)"
    }
}

if (-not $NoReboot) {
    Write-Host "Reboot now? [Y/N]"
    $r = Read-Host
    if ($r -in 'Y','y') {
        Write-Log -Section "Reboot" -Status "Info" -Message "Rebooting"
        Restart-Computer -Force
    } else {
        Write-Log -Section "Reboot" -Status "Info" -Message "Skipped by user"
    }
} else {
    Write-Log -Section "Reboot" -Status "Info" -Message "Skipped (-NoReboot)"
}

Stop-Transcript
