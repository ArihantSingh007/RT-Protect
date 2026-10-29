# tooling/clean.ps1
#
# Cleans transient build artifacts, intermediate object trees, temporary test files,
# and packaging staging directories to prevent workspace bloat.

param(
    [switch]$All = $false  # When set, also removes dist/ packaged archives
)

$ErrorActionPreference = "SilentlyContinue"
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "=========================================================="
Write-Host "             RTProtect Workspace Cleaner                  "
Write-Host "=========================================================="
Write-Host "Repository: $RepoRoot"

$Targets = @()

# Find all build* and build_* directories
$BuildDirs = Get-ChildItem -Path $RepoRoot -Directory | Where-Object { $_.Name -match '^build[-_]?' }
foreach ($d in $BuildDirs) {
    $Targets += $d.FullName
}

# Python caches
$PyCaches = Get-ChildItem -Path $RepoRoot -Recurse -Directory -Filter "__pycache__"
foreach ($d in $PyCaches) {
    $Targets += $d.FullName
}

# Staging directories inside dist/
$DistDir = Join-Path $RepoRoot "dist"
if (Test-Path $DistDir) {
    if ($All) {
        $Targets += $DistDir
    } else {
        $DistStaging = Get-ChildItem -Path $DistDir -Directory
        foreach ($d in $DistStaging) {
            $Targets += $d.FullName
        }
    }
}

# Temp directories
$TempDirs = @("dist_export", "Testing")
foreach ($t in $TempDirs) {
    $p = Join-Path $RepoRoot $t
    if (Test-Path $p) { $Targets += $p }
}

$FreedBytes = 0
foreach ($target in ($Targets | Select-Object -Unique)) {
    if (Test-Path $target) {
        Write-Host "Removing: $target"
        try {
            $size = (Get-ChildItem -Path $target -Recurse -File -Force | Measure-Object -Property Length -Sum).Sum
            if ($size) { $FreedBytes += $size }
            Remove-Item -Path $target -Recurse -Force
        } catch {
            Write-Warning "Could not delete $target : $_"
        }
    }
}

$FreedMB = [math]::Round($FreedBytes / 1MB, 2)
Write-Host "=========================================================="
Write-Host "Cleanup completed successfully. Freed ${FreedMB} MB."
Write-Host "=========================================================="
