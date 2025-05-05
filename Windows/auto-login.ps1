# Download AutoLogon.exe to Desktop
$desktop = [Environment]::GetFolderPath("Desktop")
$exePath = Join-Path $desktop 'AutoLogon.exe'
$url = 'https://live.sysinternals.com/Autologon.exe'

try {
    Invoke-WebRequest -Uri $url -OutFile $exePath -UseBasicParsing -ErrorAction Stop
    Write-Host "AutoLogon.exe downloaded to $exePath"
} catch {
    Write-Error "Failed: $($_.Exception.Message)"
}
