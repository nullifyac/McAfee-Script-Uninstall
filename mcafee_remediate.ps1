<#
.SYNOPSIS
  Intune remediation script to remove McAfee thoroughly, but only downloads
  cleanup tools + ServiceUI if McAfee is actually present.
.DESCRIPTION
  1. Logs to C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log
  2. Checks for McAfee presence first:
     - If NOT found, exits 0 immediately (no downloads performed).
  3. If found, downloads mcafeeclean.zip, mccleanup.zip, ServiceUI.exe (if missing).
  4. Runs the McAfee cleanup tools + extensive registry/directory cleanup.
  5. Removes all temporary files afterward.
  6. If a reboot is needed, displays an indefinite “Snooze or Restart” prompt to the logged-on user (non-admin).
  7. If no user is logged on or ServiceUI can’t be used, forces an immediate reboot.
.NOTES
  Must run under SYSTEM (device context) to have privileges to uninstall McAfee.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

### --- LOGGING --- ###
$logFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
if (-not (Test-Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder | Out-Null
}
$logFile = Join-Path $logFolder "RemoveMcAfee.log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARNING","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    Write-Output $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

Write-Log "=== Starting McAfee Removal Remediation Script (SYSTEM) ==="

### --- DETECTION FUNCTION FIRST --- ###
function Test-McAfeePresence {
    [CmdletBinding()]
    param()

    $found = $false

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            Get-ChildItem $rp -ErrorAction SilentlyContinue | ForEach-Object {
                $displayName = $_.GetValue("DisplayName")
                if ($displayName -and ($displayName -like "*McAfee*")) {
                    Write-Log ("Found McAfee in registry => {0}" -f $displayName) "WARNING"
                    $found = $true
                }
            }
        }
    }

    $mcAfeeDirs = @(
        "C:\Program Files\McAfee",
        "C:\Program Files (x86)\McAfee",
        "C:\ProgramData\McAfee"
    )
    foreach ($dir in $mcAfeeDirs) {
        if (Test-Path $dir) {
            Write-Log ("Found McAfee directory => {0}" -f $dir) "WARNING"
            $found = $true
        }
    }

    # QcShm.exe often locks leftover files
    if (Get-Process -Name "QcShm" -ErrorAction SilentlyContinue) {
        Write-Log "QcShm.exe is running (file lock)." "WARNING"
        $found = $true
    }

    return $found
}

### --- PRE-CHECK FOR MCAFEE --- ###
if (-not (Test-McAfeePresence)) {
    Write-Log "No McAfee detected. Exiting with code 0. (Skipping downloads.)"
    exit 0
}
Write-Log "McAfee is present; proceeding with download and removal steps..."

### --- WORKING FOLDER & URLS --- ###
$DebloatFolder = "C:\ProgramData\Debloat"
if (-not (Test-Path $DebloatFolder)) {
    New-Item -Path $DebloatFolder -ItemType Directory | Out-Null
    Write-Log "Created working folder: $DebloatFolder"
}

# Adjust URLs if needed:
$ServiceUIUrl       = "https://github.com/alexpsp00/McAfee_Removal/raw/refs/heads/main/ServiceUI.exe"
$McAfeeCleanZipUrl  = "https://github.com/alexpsp00/McAfee_Removal/raw/refs/heads/main/mcafeeclean.zip"
$McCleanupZipUrl    = "https://github.com/alexpsp00/McAfee_Removal/raw/refs/heads/main/mccleanup.zip"

# Local file paths
$ServiceUIExe       = Join-Path $DebloatFolder "ServiceUI.exe"
$McAfeeCleanZipPath = Join-Path $DebloatFolder "mcafeeclean.zip"
$McCleanupZipPath   = Join-Path $DebloatFolder "mccleanup.zip"

### --- 1) GET LOCAL FILE IF MISSING (Download) --- ###
function Get-LocalFileIfMissing {
    param(
        [string]$Url,
        [string]$LocalPath,
        [string]$Description
    )
    if (Test-Path $LocalPath) {
        Write-Log ("{0} already present at {1}; skipping download." -f $Description, $LocalPath)
    }
    else {
        Write-Log ("Downloading {0} from {1} ..." -f $Description, $Url)
        try {
            Invoke-WebRequest -Uri $Url -OutFile $LocalPath -UseBasicParsing
            Write-Log ("Successfully downloaded {0} => {1}" -f $Description, $LocalPath)
        }
        catch {
            Write-Log ("Failed to download {0} from {1}: {2}" -f $Description, $Url, $_) "WARNING"
        }
    }
}

#
# Download these files only now that we KNOW McAfee is present
#
Get-LocalFileIfMissing -Url $ServiceUIUrl      -LocalPath $ServiceUIExe       -Description "ServiceUI.exe"
Get-LocalFileIfMissing -Url $McAfeeCleanZipUrl -LocalPath $McAfeeCleanZipPath -Description "mcafeeclean.zip"
Get-LocalFileIfMissing -Url $McCleanupZipUrl   -LocalPath $McCleanupZipPath   -Description "mccleanup.zip"

#
# 2) Cleanup tool function
#
function Start-McAfeeCleanupTool {
    param(
        [string]$ZipPath,
        [string]$ExtractFolder,
        [string]$ToolName
    )
    if (Test-Path $ZipPath) {
        Write-Log ("Extracting {0} from {1}..." -f $ToolName, $ZipPath)
        if (-not (Test-Path $ExtractFolder)) {
            New-Item -ItemType Directory -Path $ExtractFolder | Out-Null
        }
        try {
            Expand-Archive -Path $ZipPath -DestinationPath $ExtractFolder -Force
            $exePath = Join-Path $ExtractFolder "Mccleanup.exe"
            if (Test-Path $exePath) {
                Write-Log ("Running {0} => {1}" -f $ToolName, $exePath)
                Start-Process -FilePath $exePath `
                    -ArgumentList "-p StopServices,MFSY,PEF,MXD,CSP,Sustainability,MOCP,MFP,APPSTATS,Auth,EMproxy,FWdiver,HW,MAS,MAT,MBK,MCPR,McProxy,McSvcHost,VUL,MHN,MNA,MOBK,MPFP,MPFPCU,MPS,SHRED,MPSCU,MQC,MQCCU,MSAD,MSHR,MSK,MSKCU,MWL,NMC,RedirSvc,VS,REMEDIATION,MSC,YAP,TRUEKEY,LAM,PCB,Symlink,SafeConnect,MGS,WMIRemover,RESIDUE -v -s" `
                    -WindowStyle Hidden -Wait
                Write-Log ("{0} completed." -f $ToolName)
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

#
# 3) Uninstall leftover via registry
#
Write-Log "Uninstalling leftover McAfee items from registry..."
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $apps = Get-ChildItem $rp -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*McAfee*" }
        foreach ($app in $apps) {
            $uninstallCmd = $app.UninstallString
            $dispName = $app.DisplayName
            if ($uninstallCmd) {
                Write-Log ("Attempting uninstall of {0}" -f $dispName)
                try {
                    if ($uninstallCmd -match "^msiexec") {
                        $msiArgs = $uninstallCmd -replace "msiexec.exe",""
                        $msiArgs = $msiArgs -replace "/I","/X "
                        if ($msiArgs -notmatch "/quiet") {
                            $msiArgs += " /quiet /norestart"
                        }
                        Start-Process msiexec.exe -ArgumentList $msiArgs -Wait
                    }
                    else {
                        if ($uninstallCmd -notmatch "/quiet") {
                            $uninstallCmd += " /quiet /norestart"
                        }
                        Start-Process cmd.exe -ArgumentList "/c $uninstallCmd" -Wait
                    }
                }
                catch {
                    Write-Log ("Failed uninstall of {0}: {1}" -f $dispName, $_) "WARNING"
                }
            }
        }
    }
}

#
# 4) Remove McAfee Safe Connect
#
Write-Log "Checking for McAfee Safe Connect..."
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
        Write-Log ("Uninstalling McAfee Safe Connect => {0}" -f $sc.UninstallString)
        Start-Process cmd.exe -ArgumentList "/c $($sc.UninstallString) /quiet /norestart" -Wait
    }
}

#
# 5) Remove leftover Start Menu, registry keys, directories
#
Write-Log "Removing McAfee Start Menu folder if present..."
$startMenuPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\McAfee"
if (Test-Path $startMenuPath) {
    Remove-Item $startMenuPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log ("Removed Start Menu path => {0}" -f $startMenuPath)
}

Write-Log "Removing leftover McAfee.WPS registry key..."
$wpsKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee.WPS"
if (Test-Path $wpsKey) {
    Remove-Item $wpsKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log ("Removed registry key => {0}" -f $wpsKey)
}

Write-Log "Removing McAfee AppX package (if present)..."
try {
    $appx = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "McAfeeWPSSparsePackage" }
    if ($appx) {
        Remove-AppxProvisionedPackage -Online -PackageName $appx.PackageName -AllUsers
        Write-Log "Removed McAfee AppX package."
    }
}
catch {
    Write-Log ("Failed removing McAfee AppX package => {0}" -f $_) "WARNING"
}

Write-Log "Removing leftover McAfee registry entries..."
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        Get-ChildItem $rp -ErrorAction SilentlyContinue | ForEach-Object {
            $dn = $_.GetValue("DisplayName")
            if ($dn -and ($dn -like "*McAfee*")) {
                try {
                    $regKeyPath = $_.PSPath
                    Remove-Item -LiteralPath $regKeyPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log ("Removed registry key => {0}" -f $dn)
                }
                catch {
                    Write-Log ("Could not remove registry key for {0}: {1}" -f $dn, $_) "WARNING"
                }
            }
        }
    }
}

Write-Log "Removing known McAfee folders..."
$mcAfeeDirs = @(
    "C:\Program Files\McAfee",
    "C:\Program Files (x86)\McAfee",
    "C:\ProgramData\McAfee"
)
foreach ($dir in $mcAfeeDirs) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $dir) {
            Write-Log ("Forcing removal via cmd.exe => {0}" -f $dir)
            cmd.exe /c "rd /s /q ""$dir"""
        }
    }
}

#
# 6) Remove temporary folders & ZIPs
#
Write-Log "Removing extracted folders & ZIP files..."
$ExtractFolder1 = Join-Path $DebloatFolder "mcafeeclean_extracted"
$ExtractFolder2 = Join-Path $DebloatFolder "mccleanup_extracted"

$extractedFolders = @($ExtractFolder1, $ExtractFolder2)
foreach ($fld in $extractedFolders) {
    if (Test-Path $fld) {
        Remove-Item $fld -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log ("Removed folder => {0}" -f $fld)
    }
}
foreach ($zipFile in @($McAfeeCleanZipPath, $McCleanupZipPath)) {
    if (Test-Path $zipFile) {
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        Write-Log ("Removed ZIP file => {0}" -f $zipFile)
    }
}

#
# 7) Final detection => if still present => show indefinite prompt or forced reboot
#
Write-Log "Final detection check..."
if (-not (Test-McAfeePresence)) {
    Write-Log "No McAfee remnants found. Exiting with code 0."
    # Optionally remove ServiceUI.exe if not needed:
    if (Test-Path $ServiceUIExe) {
        Write-Log "Removing ServiceUI.exe (not needed)."
        Remove-Item $ServiceUIExe -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

Write-Log "McAfee remnants remain => Reboot required..."

Write-Log "Checking for logged-on user with quser..."
$loggedOnUser = (quser.exe | Select-String ">" | ForEach-Object {
    $_.Line.Split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)[0]
})

if (-not $loggedOnUser) {
    Write-Log "No logged-on user found. Forcing immediate reboot."
    shutdown.exe /r /t 0
    exit 0
}
Write-Log ("Detected logged-on user => {0}" -f $loggedOnUser)

if (-not (Test-Path $ServiceUIExe)) {
    Write-Log "ServiceUI.exe not present => fallback forced reboot."
    shutdown.exe /r /t 0
    exit 0
}

Write-Log "Launching indefinite Reboot Prompt with ServiceUI..."
$tempPromptScript = "C:\Windows\Temp\RebootPrompt.ps1"
@'
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null

$continue = $true
while ($continue) {
    $msg = "McAfee removal requires a system reboot to complete.`r`n`r`nYes = Restart Now, No = Snooze 5 minutes."
    $cap = "Reboot Required"
    $btn = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $ico = [System.Windows.Forms.MessageBoxIcon]::Warning

    $res = [System.Windows.Forms.MessageBox]::Show($msg, $cap, $btn, $ico)
    if ($res -eq [System.Windows.Forms.DialogResult]::Yes) {
        shutdown.exe /r /t 0
        # Typically no return
    }
    else {
        Start-Sleep 300
    }
}
'@ > $tempPromptScript

Write-Log ("Executing RebootPrompt.ps1 with ServiceUI => {0}" -f $ServiceUIExe)
Start-Process -FilePath $ServiceUIExe -ArgumentList ("-process:explorer.exe","powershell.exe -ExecutionPolicy Bypass -File `"$tempPromptScript`"") -Wait

Write-Log "ServiceUI prompt ended unexpectedly. Cleaning up."

# Remove the prompt script
if (Test-Path $tempPromptScript) {
    Remove-Item $tempPromptScript -Force -ErrorAction SilentlyContinue
}

# Remove ServiceUI.exe if you wish:
if (Test-Path $ServiceUIExe) {
    Remove-Item $ServiceUIExe -Force -ErrorAction SilentlyContinue
    Write-Log "Removed ServiceUI.exe"
}

Write-Log "Remediation script completed. Exiting with code 0."
exit 0
