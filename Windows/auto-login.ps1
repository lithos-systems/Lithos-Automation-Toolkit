<#
.SYNOPSIS
  Downloads PsExec from Sysinternals and places PsExec.exe on the current user's Desktop.
.EXAMPLE
  iex (iwr "https://raw.githubusercontent.com/lithos-systems/Lithos-Automation-Toolkit/main/Windows/auto-login.ps1" -UseBasicParsing).Content
#>

param()

# Determine target paths
$desktop  = [Environment]::GetFolderPath('Desktop')
$tempZip  = Join-Path $env:TEMP 'PsExec.zip'
$tempDir  = Join-Path $env:TEMP 'PsExec'

Try {
    Write-Host "Downloading PsExec.zip from Sysinternals..." -ForegroundColor Cyan
    Invoke-WebRequest `
        -Uri 'https://download.sysinternals.com/files/PsExec.zip' `
        -OutFile $tempZip `
        -UseBasicParsing `
        -ErrorAction Stop

    Write-Host "Extracting PsExec.exe to temporary folder..." -ForegroundColor Cyan
    # Use Expand-Archive (built into PS 5.1+)
    Expand-Archive `
        -Path $tempZip `
        -DestinationPath $tempDir `
        -Force `
        -ErrorAction Stop

    $psexecExe = Join-Path $tempDir 'PsExec.exe'
    if (-not (Test-Path $psexecExe)) {
        Throw "Extraction failed: PsExec.exe not found in $tempDir"
    }

    Write-Host "Copying PsExec.exe to your Desktop ($desktop)..." -ForegroundColor Cyan
    Copy-Item `
        -Path $psexecExe `
        -Destination $desktop `
        -Force `
        -ErrorAction Stop

    Write-Host "✓ PsExec.exe successfully placed on your Desktop." -ForegroundColor Green
}
Catch {
    Write-Error "Write Error $($_.Exception.Message)"
}
Finally {
    # Cleanup temporary files
    Remove-Item `
        -Path $tempZip, $tempDir `
        -Recurse -Force `
        -ErrorAction SilentlyContinue
}
