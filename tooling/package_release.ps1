# tooling/package_release.ps1
#
# Release packaging and distribution script for Windows x64.
# Builds a hardened Release configuration, runs the full test suite,
# packages three distinct zip distributions (Tools, SDK, Server),
# generates cryptographic checksums and build provenance, and executes
# an end-to-end consumer application smoke test against the packaged SDK.

param(
    [string]$BuildDir = "build-release-pkg",
    [string]$VcpkgRoot = $env:VCPKG_ROOT,
    [string]$OpenSslDir = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================================="
Write-Host "   RTProtect Release Packaging & Verification (Win-x64)   "
Write-Host "=========================================================="
Write-Host "Build Directory: $BuildDir"

$RepoRoot = (Get-Item .).FullName
if (-not $OpenSslDir) {
    $LocalOpenSsl = Join-Path $RepoRoot "third_party\openssl"
    if (Test-Path $LocalOpenSsl) {
        $OpenSslDir = $LocalOpenSsl
    }
}

# 1. Configure and Build Release
$CmakeArgs = @("-S", ".", "-B", $BuildDir, "-DCMAKE_BUILD_TYPE=Release", "-DRTPROTECT_HARDEN_RELEASE=ON")

if ($VcpkgRoot) {
    $ToolchainFile = Join-Path $VcpkgRoot "scripts\buildsystems\vcpkg.cmake"
    if (Test-Path $ToolchainFile) {
        Write-Host "Using vcpkg toolchain: $ToolchainFile"
        $CmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$ToolchainFile"
        $CmakeArgs += @("-G", "Visual Studio 17 2022", "-A", "x64")
    }
} elseif ($OpenSslDir) {
    Write-Host "Using OpenSSL from: $OpenSslDir"
    $CmakeArgs += "-DOPENSSL_ROOT_DIR=$OpenSslDir"
    $CmakeArgs += @("-G", "Ninja")
    $env:PATH = "$OpenSslDir\bin;$env:PATH"
}

Write-Host "`n-- [Step 1/6] Configuring Release Build --"
cmake @CmakeArgs
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }

Write-Host "`n-- [Step 2/6] Compiling All Targets --"
cmake --build $BuildDir --config Release
if ($LASTEXITCODE -ne 0) { throw "Compilation failed" }

Write-Host "`n-- [Step 3/6] Running Full Test Suite (strict fail-closed) --"
ctest --test-dir $BuildDir -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "CTest regression detected -- aborting release packaging" }

# Helper to find built files across Ninja and MSVC directory layouts
function Find-BuiltFile ($BaseDir, $SubPath, $FileName) {
    $p1 = Join-Path $BaseDir "$SubPath\$FileName"
    if (Test-Path $p1) { return $p1 }
    $p2 = Join-Path $BaseDir "$SubPath\Release\$FileName"
    if (Test-Path $p2) { return $p2 }
    $matches = Get-ChildItem -Path (Join-Path $BaseDir $SubPath) -Recurse -Filter $FileName -ErrorAction SilentlyContinue
    if ($matches) { return $matches[0].FullName }
    return $null
}

# Setup output directories
$DistDir = Join-Path $RepoRoot "dist"
if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Force -Path $DistDir | Out-Null }

$ToolsPkgDir  = Join-Path $DistDir "rtprotect-windows-x64"
$SdkPkgDir    = Join-Path $DistDir "rtprotect-sdk-windows-x64"
$ServerPkgDir = Join-Path $DistDir "rtprotect-activation-server-windows-x64"

foreach ($dir in @($ToolsPkgDir, $SdkPkgDir, $ServerPkgDir)) {
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Collect metadata and documentation
$CommonDocs = @("README.md", "QUICKSTART.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "VERSION.txt", "SBOM.spdx.json")
foreach ($doc in $CommonDocs) {
    if (Test-Path (Join-Path $RepoRoot $doc)) {
        Copy-Item (Join-Path $RepoRoot $doc) $ToolsPkgDir
        Copy-Item (Join-Path $RepoRoot $doc) $SdkPkgDir
        Copy-Item (Join-Path $RepoRoot $doc) $ServerPkgDir
    }
}

# Generate BUILD_INFO.txt
$GitCommit = "unknown"
try {
    $GitCommit = (git rev-parse HEAD).Trim()
} catch {}
$BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$BuildInfo = @"
================================================================================
RTProtect Release Build Information
================================================================================
Version:        2.0.0
Git Commit:     $GitCommit
Build Date:     $BuildDate
Target Platform: Windows x64
Target Standard: C++20
NOMINMAX:       Enforced
Optimization:   Release (O3, Hardening Enabled)
Dependencies:   OpenSSL 3.4.0 (Crypto & SSL)
================================================================================
"@
$BuildInfo | Out-File -FilePath (Join-Path $ToolsPkgDir "BUILD_INFO.txt") -Encoding utf8
$BuildInfo | Out-File -FilePath (Join-Path $SdkPkgDir "BUILD_INFO.txt") -Encoding utf8
$BuildInfo | Out-File -FilePath (Join-Path $ServerPkgDir "BUILD_INFO.txt") -Encoding utf8

# Helper to copy OpenSSL runtime dependencies
function Copy-OpenSslDlls ($TargetBinDir) {
    if ($OpenSslDir) {
        $cryptoDll = Join-Path $OpenSslDir "bin\libcrypto-3-x64.dll"
        $sslDll    = Join-Path $OpenSslDir "bin\libssl-3-x64.dll"
        if (Test-Path $cryptoDll) { Copy-Item $cryptoDll $TargetBinDir }
        if (Test-Path $sslDll)    { Copy-Item $sslDll $TargetBinDir }
    }
}

Write-Host "`n-- [Step 4/6] Assembling Three Distribution Archives --"

# ---------------------------------------------------------
# A. Package 1: rtprotect-windows-x64 (Tools & Runtime)
# ---------------------------------------------------------
Write-Host "-> Assembling rtprotect-windows-x64 (Tools)..."
$ToolsBin = Join-Path $ToolsPkgDir "bin"
New-Item -ItemType Directory -Force -Path $ToolsBin | Out-Null

$ToolExe = Find-BuiltFile $BuildDir "tooling" "rtprotect-tool.exe"
if ($ToolExe) { Copy-Item $ToolExe $ToolsBin } else { throw "rtprotect-tool.exe not found" }

$GuiExe = Find-BuiltFile $BuildDir "tooling" "rtprotect-gui.exe"
if ($GuiExe) { Copy-Item $GuiExe $ToolsBin }

$BenchExe = Find-BuiltFile $BuildDir "bench" "rtprotect-bench.exe"
if ($BenchExe) { Copy-Item $BenchExe $ToolsBin }

Copy-OpenSslDlls $ToolsBin

if (Test-Path (Join-Path $RepoRoot "docs")) {
    Copy-Item -Recurse (Join-Path $RepoRoot "docs") $ToolsPkgDir
}

# ---------------------------------------------------------
# B. Package 2: rtprotect-sdk-windows-x64 (C++ SDK)
# ---------------------------------------------------------
Write-Host "-> Assembling rtprotect-sdk-windows-x64 (Developer SDK)..."
$SdkInc = Join-Path $SdkPkgDir "include"
$SdkLib = Join-Path $SdkPkgDir "lib"
$SdkCmake = Join-Path $SdkPkgDir "cmake"
New-Item -ItemType Directory -Force -Path $SdkInc | Out-Null
New-Item -ItemType Directory -Force -Path $SdkLib | Out-Null
New-Item -ItemType Directory -Force -Path $SdkCmake | Out-Null

# Copy public headers
$SdkModules = @("crypto", "integrity", "licensing", "antitamper", "bytecode_vm", "obfuscation", "tooling")
foreach ($m in $SdkModules) {
    $targetInc = Join-Path $SdkInc $m
    New-Item -ItemType Directory -Force -Path $targetInc | Out-Null
    Copy-Item (Join-Path $RepoRoot "$m\*.h") $targetInc
}

# Copy compiled static libraries (only RTProtect SDK libraries, excluding tests/demos/import libs)
$SdkLibNames = @("rtprotect_crypto", "rtprotect_integrity", "rtprotect_vm", "rtprotect_licensing", "rtprotect_antitamper", "rtprotect_tooling")
foreach ($libName in $SdkLibNames) {
    # Check for GCC .a or MSVC .lib
    $found = Get-ChildItem -Path $BuildDir -Recurse -File | Where-Object {
        ($_.Name -eq "lib$libName.a" -or $_.Name -eq "$libName.lib") -and
        ($_.FullName -notmatch "CMakeFiles|third_party|Testing")
    }
    if ($found) {
        Copy-Item $found[0].FullName $SdkLib
    } else {
        Write-Warning "Static library for $libName not found in build directory"
    }
}

# Copy CMake config
Copy-Item (Join-Path $RepoRoot "cmake\RTProtectConfig.cmake") $SdkCmake

# Copy consumer sample project
$SampleDest = Join-Path $SdkPkgDir "examples\consumer_sample"
New-Item -ItemType Directory -Force -Path $SampleDest | Out-Null
Copy-Item (Join-Path $RepoRoot "examples\consumer_sample\*") $SampleDest

# Include bundled OpenSSL in SDK for consumer link resolution
if ($OpenSslDir -and (Test-Path $OpenSslDir)) {
    $SdkOpenSsl = Join-Path $SdkPkgDir "third_party\openssl"
    New-Item -ItemType Directory -Force -Path $SdkOpenSsl | Out-Null
    Copy-Item -Recurse (Join-Path $OpenSslDir "*") $SdkOpenSsl
}

# ---------------------------------------------------------
# C. Package 3: rtprotect-activation-server-windows-x64
# ---------------------------------------------------------
Write-Host "-> Assembling rtprotect-activation-server-windows-x64 (Server)..."
$ServerBin = Join-Path $ServerPkgDir "bin"
New-Item -ItemType Directory -Force -Path $ServerBin | Out-Null

$ServerExe = Find-BuiltFile $BuildDir "tooling" "rtprotect-activation-server.exe"
if ($ServerExe) { Copy-Item $ServerExe $ServerBin } else { throw "rtprotect-activation-server.exe not found" }

Copy-OpenSslDlls $ServerBin

# ---------------------------------------------------------
# Smoke Testing SDK against Consumer Sample
# ---------------------------------------------------------
Write-Host "`n-- [Step 5/6] Smoke Testing Packaged SDK with Consumer Sample --"
$SmokeBuildDir = Join-Path $DistDir "smoke_test_consumer_sample"
if (Test-Path $SmokeBuildDir) { Remove-Item -Recurse -Force $SmokeBuildDir }

$SmokeCmakeArgs = @(
    "-S", (Join-Path $SdkPkgDir "examples\consumer_sample"),
    "-B", $SmokeBuildDir,
    "-DCMAKE_PREFIX_PATH=$SdkPkgDir",
    "-DCMAKE_BUILD_TYPE=Release"
)
if ($OpenSslDir) {
    $SmokeCmakeArgs += "-DOPENSSL_ROOT_DIR=$OpenSslDir"
    $SmokeCmakeArgs += @("-G", "Ninja")
}
cmake @SmokeCmakeArgs
if ($LASTEXITCODE -ne 0) { throw "Consumer sample CMake configure failed against packaged SDK" }

cmake --build $SmokeBuildDir --config Release
if ($LASTEXITCODE -ne 0) { throw "Consumer sample build failed against packaged SDK" }

$SmokeExe = Find-BuiltFile $SmokeBuildDir "" "consumer_sample.exe"
if (-not $SmokeExe) { throw "consumer_sample.exe was not produced by smoke build" }

Write-Host "Running consumer sample executable: $SmokeExe"
& $SmokeExe
if ($LASTEXITCODE -ne 0) { throw "Consumer sample execution failed" }
Write-Host "[OK] Consumer sample verified successfully!"

# ---------------------------------------------------------
# Create Zip Archives & SHA256SUMS.txt
# ---------------------------------------------------------
Write-Host "`n-- [Step 6/6] Generating Release Archives and Checksums --"

$Zip1 = Join-Path $DistDir "rtprotect-windows-x64.zip"
$Zip2 = Join-Path $DistDir "rtprotect-sdk-windows-x64.zip"
$Zip3 = Join-Path $DistDir "rtprotect-activation-server-windows-x64.zip"

foreach ($z in @($Zip1, $Zip2, $Zip3)) {
    if (Test-Path $z) { Remove-Item -Force $z }
}

Compress-Archive -Path "$ToolsPkgDir\*" -DestinationPath $Zip1
Compress-Archive -Path "$SdkPkgDir\*" -DestinationPath $Zip2
Compress-Archive -Path "$ServerPkgDir\*" -DestinationPath $Zip3

$Checksums = @()
foreach ($z in @($Zip1, $Zip2, $Zip3)) {
    $hash = (Get-FileHash -Path $z -Algorithm SHA256).Hash.ToLower()
    $name = Split-Path $z -Leaf
    $Checksums += "$hash  $name"
}

$ChecksumFile = Join-Path $DistDir "SHA256SUMS.txt"
$Checksums | Out-File -FilePath $ChecksumFile -Encoding ascii

Write-Host "`n=========================================================="
Write-Host "Package Generation Complete!"
Write-Host "Artifacts produced in ${DistDir}:"
Get-ChildItem -Path $DistDir -Filter *.zip | Select-Object Name, Length
Get-Content $ChecksumFile
Write-Host "=========================================================="
