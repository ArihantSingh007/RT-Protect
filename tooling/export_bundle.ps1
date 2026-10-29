# tooling/export_bundle.ps1
#
# Generates a lightweight, pristine review / handoff zip bundle.
# Excludes all build directories (build*/), .git history, intermediate binaries,
# Python caches, and temporary staging artifacts to prevent export bloat.

param(
    [string]$OutputPath = "",
    [switch]$IncludeDist,        # Pass -IncludeDist to bundle the 3 prebuilt release zips from dist/
    [switch]$IncludeGit          # Pass -IncludeGit to bundle the repacked .git directory
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

if (-not $OutputPath) {
    $ExportDir = Join-Path $RepoRoot "dist_export"
    if (-not (Test-Path $ExportDir)) {
        New-Item -ItemType Directory -Force -Path $ExportDir | Out-Null
    }
    $Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $OutputPath = Join-Path $ExportDir "rtprotect_handoff_${Timestamp}.zip"
} else {
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path $RepoRoot $OutputPath
    }
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $OutputPath
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
}

Write-Host "=========================================================="
Write-Host "         RTProtect Pristine Handoff Packager              "
Write-Host "=========================================================="
Write-Host "Repository: $RepoRoot"
Write-Host "Destination: $OutputPath"

# 1. Use git archive to export clean tracked source tree
$TempArchive = Join-Path $env:TEMP ("rtprotect_git_archive_" + [System.Guid]::NewGuid().ToString("N") + ".zip")
$TempStage = Join-Path $env:TEMP ("rtprotect_stage_" + [System.Guid]::NewGuid().ToString("N"))

try {
    Write-Host "Creating clean git source archive..."
    git -C $RepoRoot archive --format=zip --output=$TempArchive HEAD
    if ($LASTEXITCODE -ne 0) { throw "git archive failed" }

    Write-Host "Extracting staging snapshot..."
    Expand-Archive -LiteralPath $TempArchive -DestinationPath $TempStage -Force

    # 2. Optionally include latest packaged release distribution archives
    if ($IncludeDist) {
        $DistDir = Join-Path $RepoRoot "dist"
        if (Test-Path $DistDir) {
            $TargetDist = Join-Path $TempStage "dist"
            New-Item -ItemType Directory -Force -Path $TargetDist | Out-Null

            Get-ChildItem -Path $DistDir -Filter "*.zip" | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $TargetDist -Force
            }
            $SumsFile = Join-Path $DistDir "SHA256SUMS.txt"
            if (Test-Path $SumsFile) {
                Copy-Item -LiteralPath $SumsFile -Destination $TargetDist -Force
            }
            Write-Host "Included latest release packages and SHA256SUMS.txt in bundle."
        }
    }

    # 3. If git is requested, copy the repacked .git directory
    if ($IncludeGit) {
        $TargetGit = Join-Path $TempStage ".git"
        Write-Host "Copying repacked .git repository..."
        Copy-Item -Recurse -Force (Join-Path $RepoRoot ".git") $TargetGit
    }

    # Remove any destination file if exists
    if (Test-Path $OutputPath) {
        Remove-Item -Force $OutputPath
    }

    Write-Host "Compressing final pristine handoff bundle..."
    Compress-Archive -Path "$TempStage\*" -DestinationPath $OutputPath -CompressionLevel Optimal

    $FinalSizeMB = [math]::Round((Get-Item $OutputPath).Length / 1MB, 2)
    Write-Host "=========================================================="
    Write-Host "Export complete!"
    Write-Host "Bundle path: $OutputPath"
    Write-Host "Bundle size: ${FinalSizeMB} MB"
    Write-Host "=========================================================="
}
finally {
    if (Test-Path $TempArchive) { Remove-Item -Force $TempArchive -ErrorAction SilentlyContinue }
    if (Test-Path $TempStage) { Remove-Item -Recurse -Force $TempStage -ErrorAction SilentlyContinue }
}
