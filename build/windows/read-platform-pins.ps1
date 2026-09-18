#requires -Version 5.1
<# Resolve Windows pins through the shared Python validator. #>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Repo
)
$ErrorActionPreference = "Stop"
$command = Get-Command python, python3 -CommandType Application -ErrorAction SilentlyContinue |
  Select-Object -First 1
if ($null -eq $command) { throw "Python 3 is required to resolve Windows platform pins" }
$output = @(& $command.Source (Join-Path $Repo "tools\platform_pins.py") --repo $Repo --platform windows --json)
if ($null -eq $LASTEXITCODE -or $LASTEXITCODE -ne 0) {
  throw "Windows platform pin resolution failed (exit $LASTEXITCODE)"
}
$json = $output -join "`n"
if (-not $json.TrimStart().StartsWith("{")) {
  throw "Windows platform pin resolver did not return a JSON object"
}
$resolved = $json | ConvertFrom-Json -ErrorAction Stop
if ($null -eq $resolved -or $resolved -isnot [pscustomobject]) {
  throw "Windows platform pin resolver did not return a JSON object"
}
$pins = @{}
foreach ($property in $resolved.PSObject.Properties) {
  if ($property.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($property.Value)) {
    throw "Windows platform pin resolver returned an invalid value: $($property.Name)"
  }
  $pins[$property.Name] = $property.Value
}
foreach ($key in @("ChromiumVersion", "UngoogledVersion", "UngoogledCommit",
                   "UngoogledWindowsVersion", "UngoogledWindowsCommit")) {
  if (-not $pins.ContainsKey($key)) { throw "Windows platform pin resolver omitted $key" }
}
if ($pins.ChromiumVersion -cnotmatch '\A[0-9]+(?:\.[0-9]+){3}\z') {
  throw "Windows platform pin resolver returned an invalid ChromiumVersion"
}
foreach ($key in @("UngoogledVersion", "UngoogledWindowsVersion")) {
  if ($pins[$key] -cnotmatch '\A[0-9]+(?:\.[0-9]+){3}-[0-9]+(?:\.[0-9]+)*\z' -or
      ($pins[$key] -split "-", 2)[0] -cne $pins.ChromiumVersion) {
    throw "Windows platform pin resolver returned a mismatched $key"
  }
}
if ($pins.UngoogledWindowsVersion -cne $pins.UngoogledVersion -and
    -not $pins.UngoogledWindowsVersion.StartsWith($pins.UngoogledVersion + ".")) {
  throw "Windows platform pin resolver returned a mismatched Windows overlay"
}
foreach ($key in @("UngoogledCommit", "UngoogledWindowsCommit")) {
  if ($pins[$key] -cnotmatch '\A[a-f0-9]{40}\z') {
    throw "Windows platform pin resolver returned an invalid $key"
  }
}
return $pins
