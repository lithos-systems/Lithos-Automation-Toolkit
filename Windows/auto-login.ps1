# ——————————————————————————————————————————————
# ENSURE PSEXEC IS PRESENT (AUTO PULL-THROUGH)
# ——————————————————————————————————————————————
$psexecUrl   = 'https://download.sysinternals.com/files/PsExec.zip'
$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$psexecExe   = Join-Path $scriptDir 'PsExec.exe'
 
if (-not (Test-Path $psexecExe)) {
    Write-Host "Downloading PsExec from Sysinternals..." -ForegroundColor Yellow
    $zipPath = Join-Path $env:TEMP 'PsExec.zip'
    Invoke-WebRequest `
        -Uri $psexecUrl `
        -OutFile $zipPath `
        -UseBasicParsing `
        -ErrorAction Stop

    # Expand and clean up
    Expand-Archive -LiteralPath $zipPath -DestinationPath $scriptDir -Force
    Remove-Item     -Path $zipPath      -Force

    if (Test-Path $psexecExe) {
        Write-Host "PsExec.exe downloaded to $scriptDir" -ForegroundColor Green
    } else {
        Throw "Failed to extract PsExec.exe"
    }
}
