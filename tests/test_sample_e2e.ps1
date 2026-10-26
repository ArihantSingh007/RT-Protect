param(
    [Parameter(Mandatory = $true)][string]$Tool,
    [Parameter(Mandatory = $true)][string]$SampleSource,
    [Parameter(Mandatory = $true)][string]$RtprotectRoot,
    [Parameter(Mandatory = $true)][string]$BuildRoot,
    [Parameter(Mandatory = $false)][string]$Generator = '',
    [Parameter(Mandatory = $false)][string]$Config = 'Release'
)

$ErrorActionPreference = 'Stop'

if ($Generator) {
    $env:CMAKE_GENERATOR = $Generator
}
if ($Config) {
    $env:CMAKE_BUILD_TYPE = $Config
}

$buildPath = [IO.Path]::GetFullPath($BuildRoot)
$runRoot = Join-Path $buildPath ("rtprotect_sample_e2e_" + [guid]::NewGuid().ToString('N'))
$projectPath = Join-Path $runRoot 'project'
$devKeysPath = Join-Path $runRoot 'dev_keys'
$backupPath = Join-Path $runRoot 'backup'
$tamperedPath = Join-Path $runRoot 'tampered'

try {
    New-Item -ItemType Directory -Path $runRoot | Out-Null
    Copy-Item -LiteralPath $SampleSource -Destination $projectPath -Recurse

    $productId = 'com.rtprotect.sample.e2e.' + [guid]::NewGuid().ToString('N')
    $reportPath = Join-Path $projectPath 'integration-report.json'
    $integrateOutput = & $Tool integrate $projectPath `
        --profile balanced `
        --dev-keys `
        --dev-keys-dir $devKeysPath `
        --backup-dir $backupPath `
        --product $productId `
        --version 1.0.0 `
        --rtprotect-root $RtprotectRoot `
        --non-interactive `
        --report $reportPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "RTProtect integration failed:`n$($integrateOutput -join "`n")"
    }

    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not $report.success -or -not $report.build_succeeded -or -not $report.validation_succeeded) {
        throw 'Integration report did not confirm a successful build and validation.'
    }
    if ($report.virtualized_functions -notcontains 'ComputeProtectedEntitlement') {
        throw 'Integration report does not list ComputeProtectedEntitlement as virtualized.'
    }
    if (($integrateOutput -join "`n") -notmatch 'DEVELOPMENT KEYS - NOT FOR RELEASE') {
        throw 'Development-key integration output was not clearly labeled as non-release.'
    }

    $opensslBin = Join-Path $RtprotectRoot 'third_party/openssl/bin'
    $env:PATH = $opensslBin + ';' + $env:PATH
    $builtDir = Join-Path $projectPath 'build_protected'
    $executable = Join-Path $builtDir 'sample_client_app.exe'
    if (-not (Test-Path -LiteralPath $executable)) {
        if ($Config -and (Test-Path -LiteralPath (Join-Path $builtDir "$Config\sample_client_app.exe"))) {
            $builtDir = Join-Path $builtDir $Config
            $executable = Join-Path $builtDir 'sample_client_app.exe'
        } elseif (Test-Path -LiteralPath (Join-Path $builtDir "Release\sample_client_app.exe")) {
            $builtDir = Join-Path $builtDir 'Release'
            $executable = Join-Path $builtDir 'sample_client_app.exe'
        } elseif (Test-Path -LiteralPath (Join-Path $builtDir "Debug\sample_client_app.exe")) {
            $builtDir = Join-Path $builtDir 'Debug'
            $executable = Join-Path $builtDir 'sample_client_app.exe'
        }
    }

    if (Test-Path -LiteralPath $opensslBin) {
        $dlls = Get-ChildItem -Path $opensslBin -Filter '*.dll'
        foreach ($dll in $dlls) {
            Copy-Item -LiteralPath $dll.FullName -Destination $builtDir -Force
            if (Test-Path -LiteralPath (Join-Path $projectPath 'build_protected')) {
                Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $projectPath 'build_protected') -Force
            }
            if (Test-Path -LiteralPath (Join-Path $projectPath 'build_protected\Release')) {
                Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $projectPath 'build_protected\Release') -Force
            }
            if (Test-Path -LiteralPath (Join-Path $projectPath 'build_protected\Debug')) {
                Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $projectPath 'build_protected\Debug') -Force
            }
        }
    }

    $validOutput = & $executable 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Protected sample exited with ${LASTEXITCODE}:`n$($validOutput -join "`n")"
    }
    if (($validOutput -join "`n") -notmatch 'Virtualized entitlement calculation returned 57\.') {
        throw "Protected sample did not return the expected VM result:`n$($validOutput -join "`n")"
    }

    Copy-Item -LiteralPath $builtDir -Destination $tamperedPath -Recurse
    $tamperedExe = Join-Path $tamperedPath 'sample_client_app.exe'
    if (Test-Path -LiteralPath $opensslBin) {
        Get-ChildItem -Path $opensslBin -Filter '*.dll' | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination $tamperedPath -Force
        }
    }
    $bytes = [IO.File]::ReadAllBytes($tamperedExe)
    if ($bytes.Length -eq 0) {
        throw 'Built executable is empty; cannot perform the tamper check.'
    }
    $lastByte = $bytes.Length - 1
    $bytes[$lastByte] = [byte]($bytes[$lastByte] -bxor 1)
    [IO.File]::WriteAllBytes($tamperedExe, $bytes)

    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $tamperedOutput = & $tamperedExe 2>&1
    $tamperedExitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldEap
    if ($tamperedExitCode -eq 0 -or ($tamperedOutput -join "`n") -notmatch 'Fatal: Integrity or license verification failed') {
        throw "Tampered executable was not rejected at startup (exit $tamperedExitCode):`n$($tamperedOutput -join "`n")"
    }

    Write-Output 'Sample E2E passed: integration, signature/manifest validation, virtualized VM result 57, and tamper rejection.'
}
finally {
    $resolvedBuild = [IO.Path]::GetFullPath($buildPath).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedRun = [IO.Path]::GetFullPath($runRoot)
    if (-not $resolvedRun.StartsWith($resolvedBuild, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing cleanup outside the build directory: $resolvedRun"
    }
    if (Test-Path -LiteralPath $resolvedRun) {
        Remove-Item -LiteralPath $resolvedRun -Recurse -Force
    }
}
