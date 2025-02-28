[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

$fileThreshold = 10

Write-Host "=== McAfee Detection Script ==="

$foundRegistry = $false
$totalFiles = 0
$directoryFileCounts = @{}

# Registry Check
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $mcAfeeMatches = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue | Where-Object { 
            $_.DisplayName -like "*McAfee*"
        }
        
        foreach ($match in $mcAfeeMatches) {
            Write-Host "Detected registry entry: $($match.DisplayName)"
            $foundRegistry = $true
        }
    }
}


# Directory Check (with detailed output)
$mcAfeeDirs = @(
    "C:\Program Files\McAfee",
    "C:\Program Files (x86)\McAfee",
    "C:\ProgramData\McAfee"
)
foreach ($dir in $mcAfeeDirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue
        $fileCount = $files.Count
        $directoryFileCounts[$dir] = $fileCount
        Write-Host "Directory found: $dir - File count: $fileCount"
        $totalFiles += $fileCount
    }
    else {
        Write-Host "Directory not found: $dir"
    }
}
Write-Host "Total leftover McAfee files: $totalFiles"

# Check for QcShm.exe process
$qcshmRunning = $null -ne (Get-Process -Name "QcShm" -ErrorAction SilentlyContinue)
if ($qcshmRunning) {
    Write-Host "QcShm.exe is running."
}
else {
    Write-Host "QcShm.exe is not running."
}

# Determine Final State
if ($foundRegistry -or ($totalFiles -gt $fileThreshold)) {
    Write-Host "McAfee appears to be still installed (registry traces found or file count exceeds threshold)."
    Write-Host "Exit Code 1"
    exit 1
}
elseif (($totalFiles -gt 0) -and ($totalFiles -le $fileThreshold)) {
    if ($qcshmRunning) {
        Write-Host "Residual McAfee files detected ($totalFiles files) and QcShm.exe is running."
        Write-Host "McAfee appears to be uninstalled, but a reboot is required to clear file locks."
        Write-Host "Exit Code 0"
        exit 0
    }
    else {
        Write-Host "Residual McAfee files detected ($totalFiles files), but no file-locking process found."
        Write-Host "McAfee appears to be uninstalled."
        Write-Host "Exit Code 0"
        exit 0
    }
}
else {
    Write-Host "No McAfee detected."
    Write-Host "Exit Code 0"
    exit 0
}
