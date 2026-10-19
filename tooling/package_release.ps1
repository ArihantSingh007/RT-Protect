# tooling/package_release.ps1
#
# Release packaging script for Windows x64.
# Builds a Release configuration, runs the full test suite, verifies the CLI,
# and packages the CLI tool, benchmark runner, headers, libraries, and docs
# into a dated zip archive under dist/.

param(
    [string]$BuildDir = "build-release-pkg",
    [string]$VcpkgRoot = $env:VCPKG_ROOT,
    [string]$OpenSslDir = ""
)

$ErrorActionPreference = "Stop"

Write-Host "== RTProtect Release Packaging (Windows x64) =="
Write-Host "Build directory: $BuildDir"

$RepoRoot = (Get-Item .).FullName
if (-not $OpenSslDir) {
    $LocalOpenSsl = Join-Path $RepoRoot "third_party\openssl"
    if (Test-Path $LocalOpenSsl) {
        $OpenSslDir = $LocalOpenSsl
    }
}

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

Write-Host "`n-- Configuring (Release, hardening ON) --"
cmake @CmakeArgs
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
New-Item -ItemType Directory -Force -Path (Join-Path $PkgDir "lib") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $PkgDir "include") | Out-Null

# Locate built binaries (Ninja vs MSVC multi-config)
$ToolExe = Join-Path $BuildDir "tooling\rtprotect-tool.exe"
if (-not (Test-Path $ToolExe)) {
    $ToolExe = Join-Path $BuildDir "tooling\Release\rtprotect-tool.exe"
}
Copy-Item $ToolExe (Join-Path $PkgDir "bin")

$BenchExe = Join-Path $BuildDir "bench\rtprotect-bench.exe"
if (-not (Test-Path $BenchExe)) {
    $BenchExe = Join-Path $BuildDir "bench\Release\rtprotect-bench.exe"
}
if (Test-Path $BenchExe) { Copy-Item $BenchExe (Join-Path $PkgDir "bin") }

# Include OpenSSL runtime DLL if present
if ($OpenSslDir -and (Test-Path "$OpenSslDir\bin\libcrypto-3-x64.dll")) {
    Copy-Item "$OpenSslDir\bin\libcrypto-3-x64.dll" (Join-Path $PkgDir "bin")
}

# Copy documentation and metadata
Copy-Item "README.md" $PkgDir
Copy-Item "SECURITY_AUDIT.md" $PkgDir
Copy-Item "CHANGELOG.md" $PkgDir
Copy-Item -Recurse "docs" $PkgDir

Write-Host "`n-- Verifying the packaged tool runs --"
& (Join-Path $PkgDir "bin\rtprotect-tool.exe") --version

Write-Host "`n-- Creating archive --"
$ZipPath = Join-Path "dist" "$PkgName.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath }
Compress-Archive -Path $PkgDir -DestinationPath $ZipPath

Write-Host "`nDone: $ZipPath"
Get-Item $ZipPath | Format-List Name, Length
