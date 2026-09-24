# Kiosk-side test agent, acknowledged-stream version.
# Usage (PowerShell on the kiosk):  $Token = "live-007"; <paste this file>
# Every POST /send carries ?off=<bytes sent so far> and every GET /recv carries
# &ack=<bytes received so far>, so a request/response that NetFree blocks or
# truncates is retried without losing or duplicating a single byte.
if (-not $Token) { $Token = "live-007" }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Base = "https://sionyx-vnc-relaymain.onrender.com/rt/agent/$Token"
$File = "$env:TEMP\vnc-$Token.bin"
function Log($m, $c = "Gray") { Write-Host ("{0} {1}" -f (Get-Date -Format "HH:mm:ss.fff"), $m) -ForegroundColor $c }

Remove-Item $File -ErrorAction SilentlyContinue
Invoke-RestMethod -Method Post -Uri "$Base/reset" -UseBasicParsing | Out-Null
$tcp = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 5900)
$stream = $tcp.GetStream()
$fs = [System.IO.File]::Open($File, "Create")
$buf = New-Object byte[] 16384
$tx = 0; $rx = 0; $bad = 0; $lastPoll = [Diagnostics.Stopwatch]::StartNew()
Log "READY  token=$Token - now open the browser on your PC" "Green"

try {
  while ($true) {
    if (-not $tcp.Connected) { Log "TightVNC connection closed" "Red"; break }
    while ($stream.DataAvailable) {
      $n = $stream.Read($buf, 0, $buf.Length)
      if ($n -le 0) { break }
      $fs.Write($buf, 0, $n); $fs.Flush()
      $chunk = New-Object byte[] $n; [Array]::Copy($buf, $chunk, $n)
      $sent = $false
      for ($try = 1; $try -le 6 -and -not $sent; $try++) {
        try {
          # Same ?off= on every retry: the relay skips bytes it already has.
          Invoke-WebRequest -Method Post -Uri "$Base/send?off=$tx" -Body $chunk -ContentType "application/octet-stream" -UseBasicParsing -TimeoutSec 30 | Out-Null
          $sent = $true
        } catch {
          Log "TX retry $try ($n bytes @$tx): $($_.Exception.Message)" "Red"
          if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 409) { break }
          Start-Sleep -Milliseconds (150 * $try)
        }
      }
      if (-not $sent) { Log "TX GAVE UP @$tx - stream is desynced, start a new token" "Red"; throw "tx failed" }
      $tx += $n; Log ("TX {0,6} bytes   total={1}" -f $n, $tx) "Cyan"
    }
    if ($lastPoll.ElapsedMilliseconds -ge 200) {
      $lastPoll.Restart()
      try {
        $r = Invoke-RestMethod -Method Get -Uri "$Base/recv?wait=200&ack=$rx" -UseBasicParsing -TimeoutSec 30
        foreach ($m in $r.messages) {
          $b = [Convert]::FromBase64String($m.data)
          if ($b.Length -ne $m.len -or $m.off -ne $rx) { $bad++; Log "RX rejected (off=$($m.off) want $rx, len=$($b.Length) want $($m.len)) - asking again" "Red"; continue }
          $stream.Write($b, 0, $b.Length); $rx += $b.Length
          Log ("RX {0,6} bytes   total={1}" -f $b.Length, $rx) "Yellow"
        }
      } catch { $bad++; Log "RX error (will retry same ack=$rx): $($_.Exception.Message)" "Red" }
    }
    Start-Sleep -Milliseconds 10
  }
} finally { $fs.Close(); $tcp.Close(); Log "STOPPED  TX=$tx  RX=$rx  rejected=$bad  file=$File" "Magenta" }
