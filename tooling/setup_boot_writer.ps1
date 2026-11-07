<#
.SYNOPSIS
    Registers a Windows Scheduled Task running at startup under NT AUTHORITY\SYSTEM
    to record an authoritative per-boot session GUID into HKLM for RTProtect
    anti-clock-freeze verification.

.PARAMETER ToolPath
    Optional path to the rtprotect-tool.exe binary. If omitted, discovers from build or PATH.
#>
param(
    [string]$ToolPath = ""
)

if (-not $ToolPath) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidate = Join-Path $scriptDir "..\build\tooling\rtprotect-tool.exe"
    if (Test-Path $candidate) {
        $ToolPath = (Resolve-Path $candidate).Path
    } else {
        $ToolPath = "rtprotect-tool.exe"
    }
}

Write-Host "Registering RTProtect Boot Session Writer startup task..."
$Action = New-ScheduledTaskAction -Execute $ToolPath -Argument "register-boot-session"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "RTProtectBootSessionWriter" `
                       -Action $Action `
                       -Trigger $Trigger `
                       -Principal $Principal `
                       -Settings $Settings `
                       -Description "Records an authoritative per-boot session GUID into HKLM for RTProtect anti-clock-freeze verification." `
                       -Force

Write-Host "RTProtectBootSessionWriter scheduled task successfully registered."
