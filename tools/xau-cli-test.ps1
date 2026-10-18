<#
.SYNOPSIS
  Runs XAU headless (XAU.exe --cli) and prints the CLI/Probe lines it logs.
.EXAMPLE
  .\xau-cli-test.ps1 -Exe C:\xau\XAU.exe -Info 328178078,704208617
  .\xau-cli-test.ps1 -Exe C:\xau\XAU.exe -Probe 374923716 -TitleBound -Stop
.NOTES
  Uses the app's own login (Xbox App token, or the saved OAuth session when
  OAuthLogin is on). It never reads or prints tokens and never enters
  credentials. Only one XAU instance can run at a time; -CloseExisting
  asks the running one to close gracefully first.
#>
param(
  [Parameter(Mandatory)] [string] $Exe,
  [string] $Info,
  [string] $Probe,
  [switch] $TitleBound,
  [switch] $Stop,
  [int] $PaceMs = 1500,
  [int] $TimeoutSeconds = 240,
  [switch] $CloseExisting
)
$ErrorActionPreference = 'Stop'
$log = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'XAU\events_debug.log'
if ($CloseExisting) {
  Get-Process XAU -ErrorAction SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
  Start-Sleep 6
}
if (Get-Process XAU -ErrorAction SilentlyContinue) { throw 'XAU is already running (use -CloseExisting).' }
$before = if (Test-Path $log) { (Get-Content $log).Count } else { 0 }
$argList = @('--cli', '--exit', '--pace', $PaceMs)
if ($Info)       { $argList += @('--info', $Info) }
if ($Probe)      { $argList += @('--probe', $Probe) }
if ($TitleBound) { $argList += '--title-bound' }
if ($Stop)       { $argList += '--stop' }
$p = Start-Process -FilePath $Exe -ArgumentList $argList -WorkingDirectory (Split-Path $Exe) -PassThru
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$shown = $before
while ((Get-Date) -lt $deadline) {
  Start-Sleep 2
  $lines = @(Get-Content $log | Select-Object -Skip $shown)
  foreach ($line in $lines) {
    if ($line -match 'CLI |Probe|Presence|Heartbeat|Title-bound|SISU|XSTS|Memory XAUTH|OAuth') { $line }
  }
  $shown += $lines.Count
  if ($lines -match 'CLI done') { break }
  if ($p.HasExited) { break }
}
if (-not $p.HasExited) { [void]$p.CloseMainWindow(); Start-Sleep 5 }
