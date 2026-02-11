<#
.SYNOPSIS
  Intune remediation script to remove McAfee thoroughly.
.DESCRIPTION
  1. Logs detailed output to
     C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log.
  2. Uses an enhanced detection function that checks for registry traces and
     counts files in common McAfee folders. It distinguishes:
       - State 0 (“Clean”): No registry traces and no leftover files.
       - State 2 (“Residual”): No registry traces and ≤10 leftover files, but
         file‑locking processes (e.g. QcShm.exe) are running (a reboot is required).
       - State 1 (“Installed”): Registry traces exist or more than 10 files remain.
  3. In the pre‑check:
       - If state 0 (clean) or state 2 (residual), the script schedules a reboot
         at local midnight (if residual) and exits with code 0.
       - Only if state 1 is detected does remediation proceed.
  3b. If a reboot is pending or the script detects likely file locks preventing cleanup,
      it schedules a reboot and registers a startup task (McAfeeRemovalPostReboot) so a second-pass cleanup runs after reboot.
  4. The script then downloads and runs cleanup tools, uninstalls registry items,
     removes directories and temporary files.
  5. After cleanup, it performs a final detection. If the result is state 0 or 2,
     it schedules a reboot at midnight (if residual) and exits with 0; if state 1 is
     still detected, it exits with 1 so that remediation will be re‑attempted.
.NOTES
  Must run under SYSTEM (device context) for sufficient privileges.
#>

[CmdletBinding()]
param(
    [switch]$PostReboot
)

$ErrorActionPreference = "SilentlyContinue"
$ThisScriptPath = $PSCommandPath

### Logging Setup ###
$logFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
if (-not (Test-Path $logFolder)) { New-Item -ItemType Directory -Path $logFolder | Out-Null }
$logFile = Join-Path $logFolder "RemoveMcAfee.log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARNING","ERROR","DEBUG")] [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    Write-Output $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

Write-Log "=== Starting McAfee Removal Remediation Script (SYSTEM) ==="

function Invoke-ProcessQuiet {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList,
        [string]$Description = "Process"
    )

    $id = [guid]::NewGuid().ToString()
    $stdoutPath = Join-Path $env:TEMP ("mcafee_{0}_out.log" -f $id)
    $stderrPath = Join-Path $env:TEMP ("mcafee_{0}_err.log" -f $id)

    try {
        $proc = Start-Process -FilePath $FilePath `
            -ArgumentList $ArgumentList `
            -Wait `
            -PassThru `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath

        $stderr = ""
        if (Test-Path $stderrPath) {
            $stderr = Get-Content -Path $stderrPath -Raw -ErrorAction SilentlyContinue
        }

        if ($stderr -and $stderr.Trim()) {
            # Keep these messages out of Intune stderr stream; log at DEBUG for troubleshooting.
            Write-Log ("{0} produced stderr output (suppressed from IME error stream)." -f $Description) "DEBUG"
        }

        return $proc.ExitCode
    }
    catch {
        Write-Log ("{0} failed to start: {1}" -f $Description, $_) "WARNING"
        return $null
    }
    finally {
        Remove-Item -Path $stdoutPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

### Enhanced Detection Function ###
function Get-McAfeeStatus {
    param(
        [int]$fileThreshold = 10
    )
    $foundRegistry = $false
    $totalFiles = 0

    # Registry Check
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            Get-ChildItem -Path $rp -ErrorAction SilentlyContinue | ForEach-Object {
                $displayName = $_.GetValue("DisplayName")
                if ($displayName -and ($displayName -like "*McAfee*")) {
                    Write-Log ("Detected registry entry: {0}" -f $displayName) "DEBUG"
                    $foundRegistry = $true
                }
            }
        }
    }

    # Directory Check with Detailed Logging
    $mcAfeeDirs = @(
        "C:\Program Files\McAfee",
        "C:\Program Files (x86)\McAfee",
        "C:\ProgramData\McAfee"
    )
    foreach ($dir in $mcAfeeDirs) {
        if (Test-Path $dir) {
            $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue
            $fileCount = $files.Count
            Write-Log ("Directory found: {0} - File count: {1}" -f $dir, $fileCount) "DEBUG"
            $totalFiles += $fileCount
        }
        else {
            Write-Log ("Directory not found: {0}" -f $dir) "DEBUG"
        }
    }
    Write-Log ("Total McAfee file count: {0}" -f $totalFiles) "DEBUG"

    # Check for file-locking process (QcShm.exe)
    $qcshmRunning = $null -ne (Get-Process -Name "QcShm" -ErrorAction SilentlyContinue)
    if ($qcshmRunning) {
        Write-Log "QcShm.exe is running." "DEBUG"
    }
    else {
        Write-Log "QcShm.exe is not running." "DEBUG"
    }

    # Determine state:
    # State 1: Installed if registry traces exist or file count > threshold.
    $state = 0
    if ($foundRegistry -or ($totalFiles -gt $fileThreshold)) { $state = 1 }
    elseif ($totalFiles -eq 0) { $state = 0 }
    elseif (($totalFiles -le $fileThreshold) -and $qcshmRunning) { $state = 2 }
    else { $state = 0 }

    Write-Log ("Registry traces present: {0}" -f $foundRegistry) "DEBUG"

    [pscustomobject]@{
        State        = $state
        FoundRegistry = $foundRegistry
        TotalFiles   = $totalFiles
        QcShmRunning = $qcshmRunning
    }
}

### Schedule Reboot at Midnight Function ###
function Set-RebootAtMidnight {
    $now = Get-Date
    $midnight = [datetime]::Today.AddDays(1)
    $secondsUntilMidnight = [int]($midnight - $now).TotalSeconds
    Write-Log ("Scheduling reboot at local midnight (in {0} seconds, at {1})." -f $secondsUntilMidnight, $midnight) "INFO"
    shutdown.exe /r /t $secondsUntilMidnight
}

function Set-RebootMarker {
    param(
        [string]$MarkerPath,
        [string]$Reason
    )

    try {
        $payload = [pscustomobject]@{
            CreatedUtc = (Get-Date).ToUniversalTime().ToString("o")
            Reason     = $Reason
        } | ConvertTo-Json -Compress

        Set-Content -Path $MarkerPath -Value $payload -Encoding Ascii -Force
        Write-Log ("Wrote reboot marker: {0} (Reason: {1})" -f $MarkerPath, $Reason) "INFO"
    }
    catch {
        Write-Log ("Failed to write reboot marker {0}: {1}" -f $MarkerPath, $_) "WARNING"
    }
}

function Clear-RebootMarker {
    param(
        [string]$MarkerPath
    )

    try {
        if (Test-Path $MarkerPath) {
            Remove-Item -Path $MarkerPath -Force -ErrorAction SilentlyContinue
            Write-Log ("Cleared reboot marker: {0}" -f $MarkerPath) "INFO"
        }
    }
    catch {}
}

### Pending Reboot Check ###
function Test-PendingReboot {
    $pending = $false
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $pending = $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $pending = $true }
    $pfr = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($pfr -and $pfr.PendingFileRenameOperations) { $pending = $true }
    return $pending
}

function Get-LastBootUtc {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os -and $os.LastBootUpTime) {
            return ([datetime]$os.LastBootUpTime).ToUniversalTime()
        }
    }
    catch {}
    return $null
}

function Get-RebootMarker {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return $null }

    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
        if (-not $raw) { return $null }
        return ($raw | ConvertFrom-Json -ErrorAction SilentlyContinue)
    }
    catch {
        return $null
    }
}

function Get-McAfeeLockIndicators {
    $hits = New-Object System.Collections.Generic.List[string]

    if ($null -ne (Get-Process -Name "QcShm" -ErrorAction SilentlyContinue)) { $hits.Add("Process:QcShm") }

    foreach ($svc in @("mc-wps-update")) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq "Running") { $hits.Add("Service:$svc") }
    }

    # Common McAfee/Trellix drivers/services that often require a reboot to fully unload.
    foreach ($drv in @("mfesec","mfeelam")) {
        $d = Get-Service -Name $drv -ErrorAction SilentlyContinue
        if ($d -and $d.Status -eq "Running") { $hits.Add("Driver:$drv") }
    }

    if (Test-PendingReboot) { $hits.Add("PendingReboot") }

    return ,$hits.ToArray()
}

# PSScriptAnalyzer: use an approved verb.
function Register-PostRebootTask {
    param(
        [string]$WorkingFolder
    )

    $stableScript = Join-Path $WorkingFolder "mcafee_remediate_postreboot.ps1"

    # $MyInvocation.MyCommand.Path is empty inside functions; use the script path captured at startup.
    try {
        if ($ThisScriptPath -and (Test-Path $ThisScriptPath)) {
            $content = Get-Content -Path $ThisScriptPath -Raw -ErrorAction SilentlyContinue
            if ($content) {
                Set-Content -Path $stableScript -Value $content -Encoding Ascii -Force
            }
        }

        if (-not (Test-Path $stableScript)) {
            Write-Log ("Failed to stage post-reboot script to {0}; scheduled task will not be able to run." -f $stableScript) "WARNING"
        }
    }
    catch {
        Write-Log ("Failed to stage post-reboot script: {0}" -f $_) "WARNING"
    }

    $taskName = "McAfeeRemovalPostReboot"

    # Run once at next startup, then self-delete so it cannot keep re-running every boot.
    $action = "cmd.exe"
    $taskCmdArgs = "/c powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$stableScript`" -PostReboot & schtasks.exe /Delete /TN `"$taskName`" /F"

    # Register or refresh the task so it runs at startup as SYSTEM.
    try {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }

        $a = New-ScheduledTaskAction -Execute $action -Argument $taskCmdArgs
        $t = New-ScheduledTaskTrigger -AtStartup
        $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $s = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

        Register-ScheduledTask -TaskName $taskName -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
        Write-Log "Registered startup task '$taskName' to run post-reboot cleanup." "INFO"
    }
    catch {
        Write-Log ("Failed to register post-reboot scheduled task: {0}" -f $_) "WARNING"
    }
}

function Remove-PostRebootTask {
    $taskName = "McAfeeRemovalPostReboot"
    try {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Removed startup task '$taskName'." "INFO"
        }
    }
    catch {}
}

### Working Folder ###
$DebloatFolder = "C:\ProgramData\Debloat"
if (-not (Test-Path $DebloatFolder)) {
    New-Item -Path $DebloatFolder -ItemType Directory | Out-Null
    Write-Log "Created working folder: $DebloatFolder" "DEBUG"
}
$RebootMarkerPath = Join-Path $DebloatFolder "McAfeeRemoval.reboot.json"
$RebootMarkerMaxAgeHours = 48

if ($PostReboot) {
    Write-Log "Running in post-reboot phase." "INFO"
}
else {
    Write-Log "Running in initial phase." "INFO"
}


# If we previously scheduled a reboot (marker file), do not keep attempting cleanup before the reboot happens.
$marker = Get-RebootMarker -Path $RebootMarkerPath
if ($marker -and $marker.CreatedUtc) {
    $markerUtc = $null
    try { $markerUtc = [datetime]::Parse($marker.CreatedUtc).ToUniversalTime() } catch {}

    $bootUtc = Get-LastBootUtc

    if ($markerUtc -and (([datetime]::UtcNow - $markerUtc).TotalHours -ge $RebootMarkerMaxAgeHours)) {
        Write-Log ("Reboot marker is older than {0} hours; clearing and continuing remediation." -f $RebootMarkerMaxAgeHours) "WARNING"
        Clear-RebootMarker -MarkerPath $RebootMarkerPath
    }
    elseif ($bootUtc -and $markerUtc -and ($bootUtc -gt $markerUtc)) {
        Write-Log "Reboot marker exists, but device has rebooted since it was set. Clearing marker and continuing remediation." "INFO"
        Clear-RebootMarker -MarkerPath $RebootMarkerPath
    }
    elseif (-not $PostReboot) {
        $reason = $marker.Reason
        if (-not $reason) { $reason = "Unknown" }
        Write-Log ("Reboot marker present; waiting for reboot before continuing cleanup. Reason: {0}" -f $reason) "WARNING"
        Register-PostRebootTask -WorkingFolder $DebloatFolder
        exit 0
    }
}

### Pre-Check ###
$status = Get-McAfeeStatus -fileThreshold 10
switch ($status.State) {
    0 {
        Write-Log "Pre-check: McAfee appears cleanly uninstalled (no registry traces and no residual files)." "INFO"
        Clear-RebootMarker -MarkerPath $RebootMarkerPath
        if ($PostReboot) { Remove-PostRebootTask }
        exit 0
    }
    2 {
        Write-Log "Pre-check: Residual McAfee files detected (≤10 files with QcShm.exe running); a reboot is required to clear file locks." "INFO"
        Set-RebootAtMidnight
    Register-PostRebootTask -WorkingFolder $DebloatFolder
        Set-RebootMarker -MarkerPath $RebootMarkerPath -Reason "ResidualState"
        exit 0
    }
    1 {
        Write-Log "Pre-check: McAfee is detected (registry traces or significant leftover files found). Proceeding with removal steps..." "INFO"
    }
}

### URLs ###
# Note: ServiceUI is no longer used.
$McAfeeCleanZipUrl  = "https://github.com/nullifyac/McAfee_Removal/raw/refs/heads/main/mcafeeclean.zip"
$McCleanupZipUrl    = "https://github.com/nullifyac/McAfee_Removal/raw/refs/heads/main/mccleanup.zip"

# Local file paths
$McAfeeCleanZipPath = Join-Path $DebloatFolder "mcafeeclean.zip"
$McCleanupZipPath   = Join-Path $DebloatFolder "mccleanup.zip"

### Download Files If Missing ###
function Get-LocalFileIfMissing {
    param(
        [string]$Url,
        [string]$LocalPath,
        [string]$Description
    )
    if (Test-Path $LocalPath) {
        Write-Log ("{0} already present at {1}; skipping download." -f $Description, $LocalPath) "DEBUG"
    }
    else {
        Write-Log ("Downloading {0} from {1}..." -f $Description, $Url) "INFO"
        try {
            Invoke-WebRequest -Uri $Url -OutFile $LocalPath -UseBasicParsing
            Write-Log ("Successfully downloaded {0} => {1}" -f $Description, $LocalPath) "DEBUG"
        }
        catch {
            Write-Log ("Failed to download {0} from {1}: {2}" -f $Description, $Url, $_) "WARNING"
        }
    }
}

Get-LocalFileIfMissing -Url $McAfeeCleanZipUrl -LocalPath $McAfeeCleanZipPath -Description "mcafeeclean.zip"
Get-LocalFileIfMissing -Url $McCleanupZipUrl   -LocalPath $McCleanupZipPath   -Description "mccleanup.zip"

### Run Cleanup Tools ###
function Start-McAfeeCleanupTool {
    param(
        [string]$ZipPath,
        [string]$ExtractFolder,
        [string]$ToolName
    )
    if (Test-Path $ZipPath) {
        Write-Log ("Extracting {0} from {1}..." -f $ToolName, $ZipPath) "INFO"
        if (-not (Test-Path $ExtractFolder)) {
            New-Item -ItemType Directory -Path $ExtractFolder | Out-Null
        }
        try {
            Expand-Archive -Path $ZipPath -DestinationPath $ExtractFolder -Force
            $exePath = Join-Path $ExtractFolder "Mccleanup.exe"
            if (Test-Path $exePath) {
                Write-Log ("Running {0} => {1}" -f $ToolName, $exePath) "INFO"
                [void](Invoke-ProcessQuiet -FilePath $exePath `
                    -ArgumentList @("-p StopServices,MFSY,PEF,MXD,CSP,Sustainability,MOCP,MFP,APPSTATS,Auth,EMproxy,FWdiver,HW,MAS,MAT,MBK,MCPR,McProxy,McSvcHost,VUL,MHN,MNA,MOBK,MPFP,MPFPCU,MPS,SHRED,MPSCU,MQC,MQCCU,MSAD,MSHR,MSK,MSKCU,MWL,NMC,RedirSvc,VS,REMEDIATION,MSC,YAP,TRUEKEY,LAM,PCB,Symlink,SafeConnect,MGS,WMIRemover,RESIDUE -v -s") `
                    -Description ("{0} cleanup tool" -f $ToolName))
                Write-Log ("{0} completed." -f $ToolName) "INFO"
            }
            else {
                Write-Log ("Mccleanup.exe not found after extracting {0}!" -f $ToolName) "WARNING"
            }
        }
        catch {
            Write-Log ("Failed to run {0}. Error: {1}" -f $ToolName, $_) "WARNING"
        }
    }
    else {
        Write-Log ("{0} ZIP not found. Skipping." -f $ToolName) "WARNING"
    }
}

$ExtractFolder1 = Join-Path $DebloatFolder "mcafeeclean_extracted"
$ExtractFolder2 = Join-Path $DebloatFolder "mccleanup_extracted"

Start-McAfeeCleanupTool -ZipPath $McAfeeCleanZipPath -ExtractFolder $ExtractFolder1 -ToolName "mcafeeclean"
Start-McAfeeCleanupTool -ZipPath $McCleanupZipPath   -ExtractFolder $ExtractFolder2 -ToolName "mccleanup"

### Uninstall Leftover Registry Items ###
Write-Log "Looking for Hostage Popup Installation and Uninstalling leftover McAfee items from registry..." "INFO"
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
# Define uninstall path for McAfee Security Scan
$mcAfeeUninstaller = "C:\Program Files (x86)\McAfee Security Scan\uninstall.exe"
# Check if the McAfee Security Scan uninstaller exists, then execute silently
if (Test-Path $mcAfeeUninstaller) {
# Stop McAfee background processes before uninstalling
$processes = @("SSScheduler", "mc-webview-cnt")
foreach ($proc in $processes) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Write-Log "Attempting silent uninstall of McAfee Security Scan Plus..." "INFO"
    [void](Invoke-ProcessQuiet -FilePath $mcAfeeUninstaller -ArgumentList @("/S", "/inner") -Description "McAfee Security Scan Plus uninstall")
    Write-Log "McAfee Security Scan Plus uninstallation completed." "INFO"
} else {
    Write-Log "Uninstaller not found at expected location: $mcAfeeUninstaller" "INFO"
}
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $apps = Get-ChildItem $rp -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*McAfee*" }
        foreach ($app in $apps) {
            $uninstallCmd = $app.UninstallString
            $dispName = $app.DisplayName
            if ($uninstallCmd) {
                Write-Log ("Attempting uninstall of {0}" -f $dispName) "INFO"
                try {
                    if ($uninstallCmd -match "^msiexec") {
                        $msiArgs = $uninstallCmd -replace "msiexec.exe",""
                        $msiArgs = $msiArgs -replace "/I","/X "
                        if ($msiArgs -notmatch "/quiet") { $msiArgs += " /quiet /norestart" }
                        [void](Invoke-ProcessQuiet -FilePath "msiexec.exe" -ArgumentList @($msiArgs) -Description ("Uninstall {0}" -f $dispName))
                    }
                    else {
                        if ($uninstallCmd -notmatch "/quiet") { $uninstallCmd += " /quiet /norestart" }
                        [void](Invoke-ProcessQuiet -FilePath "cmd.exe" -ArgumentList @("/c", $uninstallCmd) -Description ("Uninstall {0}" -f $dispName))
                    }
                }
                catch {
                    Write-Log ("Failed uninstall of {0}: {1}" -f $dispName, $_) "WARNING"
                }
            }
        }
    }
}

### Remove McAfee Safe Connect ###
Write-Log "Checking for McAfee Safe Connect..." "INFO"
$safeConnects = @()
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $foundSC = Get-ChildItem $rp -ErrorAction SilentlyContinue |
                   Get-ItemProperty -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -match "McAfee Safe Connect" }
        if ($foundSC) { $safeConnects += $foundSC }
    }
}
foreach ($sc in $safeConnects) {
    if ($sc.UninstallString) {
        Write-Log ("Uninstalling McAfee Safe Connect => {0}" -f $sc.UninstallString) "INFO"
        [void](Invoke-ProcessQuiet -FilePath "cmd.exe" -ArgumentList @("/c", "$($sc.UninstallString) /quiet /norestart") -Description "Uninstall McAfee Safe Connect")
    }
}

### Remove Leftover Start Menu Items, Registry Keys & Directories ###
Write-Log "Removing McAfee Start Menu folder if present..." "INFO"
$startMenuPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\McAfee"
if (Test-Path $startMenuPath) {
    Remove-Item $startMenuPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log ("Removed Start Menu folder: {0}" -f $startMenuPath) "DEBUG"
}

Write-Log "Removing leftover McAfee.WPS registry key..." "INFO"
$wpsKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee.WPS"
if (Test-Path $wpsKey) {
    Remove-Item $wpsKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log ("Removed registry key: {0}" -f $wpsKey) "DEBUG"
}

Write-Log "Removing McAfee AppX package (if present)..." "INFO"
try {
    $appx = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "McAfeeWPSSparsePackage" }
    if ($appx) {
        Remove-AppxProvisionedPackage -Online -PackageName $appx.PackageName -AllUsers
        Write-Log "Removed McAfee AppX package." "DEBUG"
    }
}
catch {
    Write-Log ("Failed to remove McAfee AppX package: {0}" -f $_) "WARNING"
}

Write-Log "Removing leftover McAfee registry entries..." "INFO"
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        Get-ChildItem $rp -ErrorAction SilentlyContinue | ForEach-Object {
            $dn = $_.GetValue("DisplayName")
            if ($dn -and ($dn -like "*McAfee*")) {
                try {
                    $regKeyPath = $_.PSPath
                    Remove-Item -LiteralPath $regKeyPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log ("Removed registry entry: {0}" -f $dn) "DEBUG"
                }
                catch {
                    Write-Log ("Could not remove registry entry for {0}: {1}" -f $dn, $_) "WARNING"
                }
            }
        }
    }
}

Write-Log "Removing known McAfee folders..." "INFO"
$mcAfeeDirs = @(
    "C:\Program Files\McAfee",
    "C:\Program Files (x86)\McAfee",
    "C:\ProgramData\McAfee"
)

# Stop common McAfee components that frequently keep files open.
try { Get-Service -Name "mc-wps-update" -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue } catch {}
try { Get-Process -Name "QcShm" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}

foreach ($dir in $mcAfeeDirs) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $dir) {
            Write-Log ("Forcing removal via cmd.exe for folder: {0}" -f $dir) "DEBUG"
            [void](Invoke-ProcessQuiet -FilePath "cmd.exe" -ArgumentList @("/c", "rd /s /q ""$dir"" 1>nul 2>nul") -Description ("Force-remove folder {0}" -f $dir))
        }
    }
}

### Remove Temporary Folders & ZIP Files ###
Write-Log "Removing temporary folders and ZIP files..." "INFO"
foreach ($fld in @($ExtractFolder1, $ExtractFolder2)) {
    if (Test-Path $fld) {
        Remove-Item $fld -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log ("Removed temporary folder: {0}" -f $fld) "DEBUG"
    }
}
foreach ($zipFile in @($McAfeeCleanZipPath, $McCleanupZipPath)) {
    if (Test-Path $zipFile) {
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        Write-Log ("Removed ZIP file: {0}" -f $zipFile) "DEBUG"
    }
}

### Final Detection & Reboot Handling ###
Write-Log "Performing final detection check..." "INFO"
$status = Get-McAfeeStatus -fileThreshold 10
$lockIndicators = Get-McAfeeLockIndicators
if ($lockIndicators.Count -gt 0) {
    Write-Log ("Lock indicators present: {0}" -f ($lockIndicators -join ", ")) "INFO"
}

switch ($status.State) {
    0 {
        Write-Log "Final detection: McAfee is cleanly uninstalled." "INFO"
        Clear-RebootMarker -MarkerPath $RebootMarkerPath
        if ($PostReboot) { Remove-PostRebootTask }
        exit 0
    }
    2 {
        Write-Log "Final detection: Residual McAfee files remain (≤10 files with QcShm.exe running). A reboot is required to clear file locks." "INFO"
        Set-RebootAtMidnight
        Register-PostRebootTask -WorkingFolder $DebloatFolder
        Set-RebootMarker -MarkerPath $RebootMarkerPath -Reason "ResidualStateFinal"
        exit 0
    }
    1 {
        # If registry traces are gone but files remain and lock indicators exist, treat as reboot-required.
        if (-not $status.FoundRegistry -and $status.TotalFiles -gt 0 -and $lockIndicators.Count -gt 0) {
            Write-Log "Final detection: McAfee remnants still detected, but file locks are likely preventing cleanup. Scheduling reboot and deferring failure." "WARNING"
            Set-RebootAtMidnight
            Register-PostRebootTask -WorkingFolder $DebloatFolder
            Set-RebootMarker -MarkerPath $RebootMarkerPath -Reason ("FileLocks:" + ($lockIndicators -join ","))
            exit 0
        }

        Write-Log "Final detection: McAfee remnants still detected (registry entries or significant file count). Exiting with code 1 to trigger remediation re-attempt." "WARNING"
        exit 1
    }
}
