<#
.SYNOPSIS
  Downloads PsExec.exe from Sysinternals and places it on your Desktop.

.DESCRIPTION
  Fetches the PsExec.zip from Sysinternals, extracts only PsExec.exe,
  then copies it to the current user's Desktop folder.
#>

# Where to drop PsExec.exe
$Desktop = [Environment]::GetFolderPath('Desktop')

# Sysinternals PsExec ZIP URL
$Url = 'https://download.sysinternals.com/files/PsExec.zip'

# Temp paths
$TempZip  = Join-Path $env:TEMP 'PsExec.zip'
$TempDir  = Join-Path $env:TEMP 'PsExec_Tmp'

Try {
    Write-Host "Downloading PsExec.zip…" -ForegroundColor Yellow
    Invoke-WebRequest -Uri $Url -OutFile $TempZip -UseBasicParsing -ErrorAction Stop

    Write-Host "Extracting PsExec.exe…" -ForegroundColor Yellow
    # ensure clean temp folder
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    [System.IO.Compression.ZipFile]::ExtractToDirectory($TempZip, $TempDir)

    $ExePath = Join-Path $TempDir 'PsExec.exe'
    if (Test-Path $ExePath) {
        Copy-Item -Path $ExePath -Destination $Desktop -Force -ErrorAction Stop
        Write-Host "✅ PsExec.exe has been placed on your Desktop." -ForegroundColor Green
    } else {
        throw 'PsExec.exe not found in archive!'
    }
}
Catch {
    Write-Error "Failed: $($_.Exception.Message)"
}
Finally {
    # Clean up
    Remove-Item -Path $TempZip, $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
