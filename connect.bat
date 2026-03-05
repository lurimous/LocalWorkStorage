@echo off
setlocal

set "SERVER_IP=%~1"
set "SERVER_PORT=%~2"
if "%SERVER_PORT%"=="" set "SERVER_PORT=80"

set "PS_TEMP=%TEMP%\lws_conn_%RANDOM%.ps1"

echo.
echo  LocalWorkStorage - Connect
echo  ============================
echo.

if not "%SERVER_IP%"=="" goto :write_wait

:: ── Discovery script (RunspacePool, parallel scan) ─────────────────────────
(
echo $localIP = ^(Get-NetIPAddress -AddressFamily IPv4 ^| Where-Object {
echo     $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown'
echo } ^| Select-Object -First 1^).IPAddress
echo.
echo if ^(-not $localIP^) {
echo     Write-Host '  [ERROR] Could not detect local IP. Are you connected to a network?' -ForegroundColor Red
echo     Write-Host '  Tip: connect.bat ^<server-ip^> skips auto-discovery.' -ForegroundColor Yellow
echo     exit 3
echo }
echo.
echo $octets = $localIP -split '\.'
echo $subnet  = $octets[0] + '.' + $octets[1] + '.' + $octets[2]
echo $port    = %SERVER_PORT%
echo.
echo Write-Host "  Local IP  : $localIP" -ForegroundColor Cyan
echo Write-Host "  Scanning  : $subnet.1 - $subnet.254  port $port" -ForegroundColor Cyan
echo Write-Host ""
echo.
echo $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new^(^)
echo $pool    = [RunspaceFactory]::CreateRunspacePool^(1, 50^)
echo $pool.Open^(^)
echo.
echo $jobs = 1..254 ^| ForEach-Object {
echo     $ip = "$subnet.$_"
echo     $ps = [PowerShell]::Create^(^)
echo     $ps.RunspacePool = $pool
echo     [void]$ps.AddScript^({
echo         param^($ip, $port, $results^)
echo         try {
echo             $r = Invoke-WebRequest -Uri "http://$ip`:$port/api/ping" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
echo             $j = $r.Content ^| ConvertFrom-Json
echo             if ^($j.app -eq 'LocalWorkStorage' -and $j.ok -eq $true^) {
echo                 $results.Add^([PSCustomObject]@{ IP = $ip; Data = $j }^)
echo             }
echo         } catch {}
echo     }^).AddArgument^($ip^).AddArgument^($port^).AddArgument^($results^)
echo     @{ PS = $ps; Handle = $ps.BeginInvoke^(^) }
echo }
echo.
echo Write-Host "  Probing $($jobs.Count) hosts in parallel (up to 50 at a time)..." -ForegroundColor Cyan
echo foreach ^($job in $jobs^) { $job.PS.EndInvoke^($job.Handle^); $job.PS.Dispose^(^) }
echo $pool.Close^(^); $pool.Dispose^(^)
echo.
echo Write-Host ""
echo if ^($results.Count -gt 0^) {
echo     $found = ^($results ^| Select-Object -First 1^).IP
echo     foreach ^($r in $results^) {
echo         $json = $r.Data ^| ConvertTo-Json -Compress
echo         Write-Host "  TRUE - LocalWorkStorage found at $($r.IP):$port" -ForegroundColor Green
echo         Write-Host "         Response: $json" -ForegroundColor Cyan
echo     }
echo     Write-Host ""
echo     Write-Host "  Opening browser..." -ForegroundColor Green
echo     Start-Process "http://$found`:$port"
echo     exit 0
echo }
echo.
echo Write-Host "  FALSE - LocalWorkStorage not found on $subnet.0/24" -ForegroundColor Red
echo Write-Host ""
echo Write-Host "  - Is the server running?  (run start.bat on the host^)" -ForegroundColor Yellow
echo Write-Host "  - Is port $port open in the firewall?" -ForegroundColor Yellow
echo Write-Host "  - Are both PCs on the same subnet?" -ForegroundColor Yellow
echo Write-Host ""
echo $ip = Read-Host "  Server IP to retry (or Enter to exit^)"
echo if ^(-not $ip^) { exit 1 }
echo $url = "http://$ip`:$port"
echo Write-Host ""
echo Write-Host "  Connecting to: $url" -ForegroundColor Cyan
echo Write-Host "  Press Ctrl+C to cancel."
echo Write-Host ""
echo while ^($true^) {
echo     try {
echo         $r = Invoke-WebRequest -Uri "$url/api/ping" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
echo         $j = $r.Content ^| ConvertFrom-Json
echo         if ^($j.app -eq 'LocalWorkStorage' -and $j.ok -eq $true^) {
echo             Write-Host "  [OK] Server is up!  Opening browser..." -ForegroundColor Green
echo             Start-Process $url; exit 0
echo         }
echo         Write-Host "  [..] NOMATCH -- retrying in 2s..." -ForegroundColor Yellow
echo     } catch {
echo         Write-Host "  [..] $^($_.Exception.Message^) -- retrying in 2s..." -ForegroundColor Yellow
echo     }
echo     Start-Sleep -Seconds 2
echo }
) > "%PS_TEMP%"
goto :run

:: ── Wait-loop script for a known IP ────────────────────────────────────────
:write_wait
(
echo $ip   = '%SERVER_IP%'
echo $port = %SERVER_PORT%
echo $url  = "http://$ip`:$port"
echo Write-Host "  Connecting to: $url" -ForegroundColor Cyan
echo Write-Host "  Press Ctrl+C to cancel."
echo Write-Host ""
echo while ^($true^) {
echo     try {
echo         $r = Invoke-WebRequest -Uri "$url/api/ping" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
echo         $j = $r.Content ^| ConvertFrom-Json
echo         if ^($j.app -eq 'LocalWorkStorage' -and $j.ok -eq $true^) {
echo             Write-Host "  [OK] Server is up!  Opening browser..." -ForegroundColor Green
echo             $json = $j ^| ConvertTo-Json -Compress
echo             Write-Host "       Response: $json" -ForegroundColor Cyan
echo             Write-Host ""
echo             Start-Process $url; exit 0
echo         }
echo         Write-Host "  [..] NOMATCH -- retrying in 2s..." -ForegroundColor Yellow
echo     } catch {
echo         Write-Host "  [..] $^($_.Exception.Message^) -- retrying in 2s..." -ForegroundColor Yellow
echo     }
echo     Start-Sleep -Seconds 2
echo }
) > "%PS_TEMP%"

:run
powershell -ExecutionPolicy Bypass -File "%PS_TEMP%"
del "%PS_TEMP%" 2>nul
echo.
pause
