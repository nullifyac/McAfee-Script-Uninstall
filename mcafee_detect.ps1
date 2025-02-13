[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== McAfee Detection Script ==="

# Registry paths to look for McAfee references
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $dn = $_.GetValue("DisplayName")
            if ($dn -and ($dn -like "*McAfee*")) {
                Write-Host "Detected McAfee product in registry: $dn"
                $foundMcAfee = $true
            }
        }
    }
}

# File system paths where McAfee typically resides
$mcAfeeDirs = @(
    "C:\Program Files\McAfee",
    "C:\Program Files (x86)\McAfee",
    "C:\ProgramData\McAfee"
)

foreach ($dir in $mcAfeeDirs) {
    if (Test-Path $dir) {
        Write-Host "Detected McAfee directory: $dir"
        $foundMcAfee = $true
    }
}

if ($foundMcAfee) {
    Write-Host "McAfee is still present. Exiting detection with code 1."
    exit 1
}
else {
    Write-Host "No McAfee detected. Exiting with code 0."
    exit 0
}
