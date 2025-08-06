<#
.SYNOPSIS
    Fully automated Windows 10 junk cleaner and optimizer PowerShell script without logging.

.DESCRIPTION
    Performs comprehensive system maintenance and optimization silently without logging,
    then automatically reboots the system to complete cleanup.

.NOTES
    Requires running as Administrator.
    Tested on Windows 10.
#>

#region Settings
$MinFreeDiskGB = 15
$SystemDrive = "C"
$CCleanerURL = "https://download.ccleaner.com/ccleaner/ccsetup634_slim.exe"
$CCleanerInstallerPath = "$env:TEMP\ccsetup_slim.exe"
$CCleanerInstallPath = "${env:ProgramFiles(x86)}\CCleaner"
$TelemetryServices = @(
    'DiagTrack', 'DiagTrackRunner', 'dmwappushservice', 'DoSvc', 'WMPNetworkSvc'
)
#endregion

#region Functions

function Ensure-RunAsAdmin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}

function New-SystemRestorePoint {
    try {
        $desc = "System Maintenance Restore Point - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Checkpoint-Computer -Description $desc -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
    }
    catch { }
}

function Clear-Folder {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path $Path) {
        try {
            Get-ChildItem -Path $Path -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        catch { }
    }
}

function Clean-UserCaches {
    $excludedUsers = 'Public','Default','Default User','All Users'
    $users = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | Where-Object { $excludedUsers -notcontains $_.Name }
    foreach ($user in $users) {
        $userPath = $user.FullName

        Clear-Folder -Path "$userPath\AppData\Local\Temp"
        Clear-Folder -Path "$userPath\AppData\Local\Microsoft\Windows\INetCache"
        Clear-Folder -Path "$userPath\AppData\Local\Microsoft\Windows\INetCookies"
        Clear-Folder -Path "$userPath\AppData\Local\Microsoft\Edge\User Data\Default\Cache"
        Clear-Folder -Path "$userPath\AppData\Local\Google\Chrome\User Data\Default\Cache"

        $ffProfiles = "$userPath\AppData\Local\Mozilla\Firefox\Profiles"
        if (Test-Path $ffProfiles) {
            Get-ChildItem $ffProfiles -Directory | ForEach-Object {
                Clear-Folder -Path "$($_.FullName)\cache2"
            }
        }
        Clear-Folder -Path "$userPath\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\#!001\MicrosoftEdge\Cache"
    }
}

function Clean-SystemCaches {
    Clear-Folder -Path "$env:SystemRoot\Temp"

    $prefetch = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetch) {
        try {
            Get-ChildItem $prefetch -Filter '*.pf' | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        catch { }
    }

    Stop-Service wuauserv -ErrorAction SilentlyContinue
    Clear-Folder -Path "C:\Windows\SoftwareDistribution\DataStore"
    Clear-Folder -Path "C:\Windows\SoftwareDistribution\Download"
    Start-Service wuauserv -ErrorAction SilentlyContinue

    try {
        dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }
    catch { }

    Clear-Folder -Path "C:\ProgramData\Microsoft\Windows\WER"

    try {
        wevtutil cl Application
        wevtutil cl System
        wevtutil cl Setup
    } catch { }

    $thumbCachePath = "$env:LocalAppData\Microsoft\Windows\Explorer"
    Get-ChildItem -Path $thumbCachePath -Filter "thumbcache_*" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

    Clear-Folder -Path "C:\Windows\System32\LogFiles\Firewall"

    try {
        & "$env:SystemRoot\System32\wsreset.exe" | Out-Null
    } catch { }

    try {
        ipconfig /flushdns | Out-Null
    } catch { }
}

function Disable-TelemetryFeature {
    foreach ($svc in $TelemetryServices) {
        try {
            if (Get-Service $svc -ErrorAction SilentlyContinue) {
                Stop-Service $svc -Force -ErrorAction SilentlyContinue
                Set-Service $svc -StartupType Disabled
            }
        } catch { }
    }
    try {
        $policiesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (-not (Test-Path $policiesPath)) { New-Item -Path $policiesPath -Force | Out-Null }
        Set-ItemProperty -Path $policiesPath -Name AllowTelemetry -Value 0 -Type DWord -Force
    } catch { }
}

function Enable-LongPathSupport {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Type DWord -Force
    } catch { }
}

function Disable-SysMainService {
    try {
        Stop-Service -Name SysMain -Force -ErrorAction SilentlyContinue
        Set-Service -Name SysMain -StartupType Disabled
    } catch { }
}

function Run-SfcDismScan {
    sfc /scannow | Out-Null
    dism /Online /Cleanup-Image /StartComponentCleanup | Out-Null
    dism /Online /Cleanup-Image /RestoreHealth | Out-Null
}

function Optimize-DiskSpace {
    param([string]$Drive = $SystemDrive)
    try {
        $freeGB = (Get-PSDrive -Name $Drive).Free / 1GB
        if ($freeGB -lt $MinFreeDiskGB) {
            defrag $Drive -O -V | Out-Null
        }
    } catch { }
}

function Schedule-DiskCheck {
    param([string]$Drive = $SystemDrive)
    try {
        chkdsk $Drive /F /R /X | Out-Null
    } catch { }
}

function Empty-RecycleBin {
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    } catch { }
}

function Run-WindowsDefenderScan {
    try {
        $mpRunPath = Join-Path $env:ProgramData "Microsoft\Windows Defender\Platform"
        $latestMajor = Get-ChildItem $mpRunPath -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latestMajor) {
            $mpCmdRun = Join-Path $latestMajor.FullName "MpCmdRun.exe"
            if (Test-Path $mpCmdRun) {
                Start-Process -FilePath $mpCmdRun -ArgumentList "-Scan", "-ScanType", "1" -WindowStyle Hidden
            }
        }
    } catch { }
}

function Install-OrRun-CCleaner {
    $ccleanerExe64 = Join-Path $CCleanerInstallPath "CCleaner64.exe"
    $ccleanerExe32 = Join-Path $CCleanerInstallPath "CCleaner.exe"

    if ((-not (Test-Path $ccleanerExe64)) -and (-not (Test-Path $ccleanerExe32))) {
        try {
            Invoke-WebRequest -Uri $CCleanerURL -OutFile $CCleanerInstallerPath -UseBasicParsing
            Start-Process -FilePath $CCleanerInstallerPath -ArgumentList "/S" -Wait
        }
        catch { }
        finally {
            if (Test-Path $CCleanerInstallerPath) { Remove-Item $CCleanerInstallerPath -Force -ErrorAction SilentlyContinue }
        }
    }

    if (Test-Path $ccleanerExe64) {
        Start-Process -FilePath $ccleanerExe64 -ArgumentList "/AUTO" -Wait
    } elseif (Test-Path $ccleanerExe32) {
        Start-Process -FilePath $ccleanerExe32 -ArgumentList "/AUTO" -Wait
    }
}

function Create-ScheduledMaintenanceTask {
    try {
        $taskName = "WeeklySystemMaintenance"
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$PSCommandPath`""
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries)
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
    }
    catch { }
}

#endregion

#region Main

Ensure-RunAsAdmin

New-SystemRestorePoint

Disable-TelemetryFeature
Enable-LongPathSupport
Disable-SysMainService

Clean-SystemCaches
Clean-UserCaches

Install-OrRun-CCleaner

Run-SfcDismScan

Optimize-DiskSpace -Drive $SystemDrive

Schedule-DiskCheck -Drive $SystemDrive

Empty-RecycleBin

Run-WindowsDefenderScan

Create-ScheduledMaintenanceTask

Restart-Computer -Force

#endregion