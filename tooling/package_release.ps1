# tooling/package_release.ps1
#
# Windows equivalent of package_release.sh: builds a Release configuration
# with MSVC, runs the full test suite, and packages the CLI tool plus docs
# into a dated zip under dist/.
#
# NOT EXECUTED IN THIS ENVIRONMENT -- no Windows/MSVC runtime is available
# here. Written to the same documented CMake generator and vcpkg
# invocations as the main README's Windows build instructions, which carry
# the same caveat. Please run this for real on a Windows/MSVC machine and
# confirm it works before relying on it -- this is the one packaging
# script in this delivery that has NOT been verified by actually running
# it, unlike package_release.sh (see docs/ARCHITECTURE.md's Phase 7
# section for the distinction).
#
# Usage: .\tooling\package_release.ps1 [-BuildDir build-release-pkg] [-VcpkgRoot <path>]
# Run from the repository root in a "Developer PowerShell for VS 2022".

param(
    [string]$BuildDir = "build-release-pkg",
    [string]$VcpkgRoot = $env:VCPKG_ROOT
)

$ErrorActionPreference = "Stop"

Write-Host "== rtprotect release packaging (Windows/MSVC) =="
Write-Host "Build directory: $BuildDir"

if (-not $VcpkgRoot) {
    Write-Error "VcpkgRoot not set (pass -VcpkgRoot or set `$env:VCPKG_ROOT) -- needed to locate OpenSSL via vcpkg. See README.md's Windows build instructions."
    exit 1
}
$ToolchainFile = Join-Path $VcpkgRoot "scripts\buildsystems\vcpkg.cmake"
if (-not (Test-Path $ToolchainFile)) {
    Write-Error "vcpkg toolchain file not found at $ToolchainFile"
    exit 1
}

Write-Host "`n-- Configuring (Release, hardening ON) --"
cmake -S . -B $BuildDir -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_TOOLCHAIN_FILE=$ToolchainFile `
    -DCMAKE_BUILD_TYPE=Release `
    -DRTPROTECT_HARDEN_RELEASE=ON
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }

Write-Host "`n-- Building --"
cmake --build $BuildDir --config Release
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

Write-Host "`n-- Running full test suite (packaging aborts on any failure) --"
ctest --test-dir $BuildDir -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "Tests failed -- aborting packaging" }

Write-Host "`n-- Assembling package --"
$Version = Get-Date -Format "yyyyMMdd"
$PkgName = "rtprotect-$Version-windows-x64"
$PkgDir = Join-Path "dist" $PkgName
if (Test-Path $PkgDir) { Remove-Item -Recurse -Force $PkgDir }
New-Item -ItemType Directory -Force -Path (Join-Path $PkgDir "bin") | Out-Null

Copy-Item (Join-Path $BuildDir "tooling\Release\rtprotect-tool.exe") (Join-Path $PkgDir "bin")
$BenchExe = Join-Path $BuildDir "bench\Release\rtprotect-bench.exe"
if (Test-Path $BenchExe) { Copy-Item $BenchExe (Join-Path $PkgDir "bin") }
Copy-Item "README.md" $PkgDir
Copy-Item -Recurse "docs" $PkgDir

Write-Host "`n-- Verifying the packaged tool runs --"
& (Join-Path $PkgDir "bin\rtprotect-tool.exe") 2>&1 | Select-Object -First 1

Write-Host "`n-- Creating archive --"
$ZipPath = Join-Path "dist" "$PkgName.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath }
Compress-Archive -Path $PkgDir -DestinationPath $ZipPath

Write-Host "`nDone: $ZipPath"
Get-Item $ZipPath | Format-List Name, Length
