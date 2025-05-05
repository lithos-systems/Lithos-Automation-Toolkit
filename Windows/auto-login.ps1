<#
.SYNOPSIS
  Downloads PsExec.exe from Sysinternals if it’s not already next to this script.
#>

# Determine this script’s folder on disk
$scriptFolder = $PSScriptRoot

# Path where we expect PsExec.exe
$psexecExe = Join-Path $scriptFolder 'PsExec.exe'

# Sysinternals PsExec ZIP URL
$psexecUrl = 'https://download.sysinternals.com/files/PsExec.zip'

if (-not (Test-Path $psexecExe)) {
    Write-Host "Downloading PsExec from Sysinternals…" -ForegroundColor Yellow
    $zip = Join-Path $env:TEMP 'PsExec.zip'

    Invoke-WebRequest `
      -Uri $psexecUrl `
      -OutFile $zip `
      -UseBasicParsing `
      -ErrorAction Stop

    Expand-Archive -LiteralPath $zip -DestinationPath $scriptFolder -Force
    Remove-Item $zip -Force

    if (Test-Path $psexecExe) {
        Write-Host "✅ PsExec.exe downloaded to $scriptFolder" -ForegroundColor Green
    } else {
        Throw "Failed to extract PsExec.exe"
    }
}
