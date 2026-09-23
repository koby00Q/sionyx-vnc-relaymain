<#
  SIONYX - manual relay test, KIOSK side (acts as the "agent"), fixed token, HTTP transport.

  What it does: connects to the local TightVNC (127.0.0.1:5900) and bridges it to the relay
  over plain HTTPS long-polling (the transport that gets through NetFree), using a FIXED
  token so the browser side can use the very same one. It prints live logs to this window
  (and to %TEMP%\sionyx-agent-test.log): every POST/poll, and a byte counter + CRC32 of the
  VNC stream at fixed offsets ([tap] lines) so the same numbers can be compared against the
  relay log (Render) and the browser console (vnc.html?debug=1).

  Run in a normal "Windows PowerShell" window (NOT the ISE - it doesn't show console output):
      powershell -ExecutionPolicy Bypass -File .\sionyx-agent-test.ps1
  Stop with Ctrl+C. Every attempt = restart this script, THEN open the browser (one VNC
  session = one TCP connection to TightVNC; a page reload needs a fresh agent).
#>
param(
  [string]$Token   = "manual-test-001",
  [string]$BaseUrl = "https://sionyx-vnc-relaymain.onrender.com",
  [string]$VncHost = "127.0.0.1",
  [int]$VncPort    = 5900
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$cs = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

public static class RelayLog
{
    static readonly object L = new object();
    public static string FilePath;   // optional: every line is also appended here
    public static void Write(string s)
    {
        string line = DateTime.Now.ToString("HH:mm:ss.fff") + "  " + s;
        lock (L)
        {
            Console.WriteLine(line);
            if (!string.IsNullOrEmpty(FilePath))
            {
                try { File.AppendAllText(FilePath, line + Environment.NewLine); } catch (Exception) { }
            }
        }
    }
}

// Running byte counter + CRC32 of one direction of the VNC stream, logged at the
// same offsets as the server ([tap] lines in the Render log) and the browser
// (vnc.html?debug=1): every 64 KiB for the first MiB, then every MiB.
public class StreamTap
{
    static readonly uint[] Table = MakeTable();
    static uint[] MakeTable()
    {
        uint[] t = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++) c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[n] = c;
        }
        return t;
    }

    readonly string label;
    long total;
    uint state = 0xFFFFFFFFu;
    public StreamTap(string label) { this.label = label; }
    public long Total { get { return total; } }

    static long Next(long off)
    {
        if (off < 1048576) return (off / 65536 + 1) * 65536;
        return (off / 1048576 + 1) * 1048576;
    }

    public void Feed(byte[] b, int off, int len)
    {
        int pos = off, end = off + len;
        while (pos < end)
        {
            long next = Next(total);
            int take = (int)Math.Min((long)(end - pos), next - total);
            uint c = state;
            for (int i = pos; i < pos + take; i++) c = Table[(c ^ b[i]) & 0xFF] ^ (c >> 8);
            state = c;
            total += take; pos += take;
            if (total == next)
                RelayLog.Write("[tap] " + label + " @" + total + " crc=" + (state ^ 0xFFFFFFFFu).ToString("x8"));
        }
    }
}

public class SionyxAgentTest
{
    readonly string baseUrl, token, vncHost;
    readonly int vncPort;
    TcpClient tcp;
    NetworkStream ns;
    volatile bool running;
    Thread upThread, downThread;

    // agent -> viewer stream (what TightVNC sent us), viewer -> agent stream (what we wrote to TightVNC)
    readonly StreamTap tapUp = new StreamTap("agent  tightvnc->agent (sent to relay)");
    readonly StreamTap tapDown = new StreamTap("agent  relay->tightvnc (written to VNC)");
    long posts, polls, retries;
    long lastPostMs, lastPollMs;
    bool browserSeen;

    public SionyxAgentTest(string baseUrl, string token, string vncHost, int vncPort)
    {
        this.baseUrl = baseUrl.TrimEnd('/');
        this.token = token;
        this.vncHost = vncHost;
        this.vncPort = vncPort;
    }

    public bool Running { get { return running; } }

    HttpWebRequest NewReq(string path, string method, int timeoutMs)
    {
        HttpWebRequest r = (HttpWebRequest)WebRequest.Create(baseUrl + path);
        r.Method = method;
        r.Timeout = timeoutMs;
        r.ReadWriteTimeout = timeoutMs;
        r.UserAgent = "sionyx-agent-test/1";
        r.ServicePoint.Expect100Continue = false;
        r.Headers.Add("Cache-Control", "no-cache");
        return r;
    }

    static string ReadAll(WebResponse resp)
    {
        using (resp)
        using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            return sr.ReadToEnd();
    }

    static string Describe(Exception e)
    {
        WebException we = e as WebException;
        if (we != null && we.Response != null)
        {
            HttpWebResponse hr = we.Response as HttpWebResponse;
            string code = hr != null ? ((int)hr.StatusCode).ToString() : "?";
            string body = "";
            try { body = ReadAll(we.Response); } catch (Exception) { }
            if (body.Length > 120) body = body.Substring(0, 120);
            return "HTTP " + code + " " + body.Replace("\n", " ");
        }
        return e.GetType().Name + ": " + e.Message;
    }

    public void Start()
    {
        ServicePointManager.DefaultConnectionLimit = 20;
        RelayLog.Write("relay=" + baseUrl + "  token=" + token + "  vnc=" + vncHost + ":" + vncPort);

        try
        {
            string who = ReadAll(NewReq("/whoami", "GET", 15000).GetResponse());
            JavaScriptSerializer js = new JavaScriptSerializer();
            Dictionary<string, object> d = js.Deserialize<Dictionary<string, object>>(who);
            string ip = "?";
            Dictionary<string, object> h = d.ContainsKey("headers") ? d["headers"] as Dictionary<string, object> : null;
            if (h != null && h.ContainsKey("cf-connecting-ip")) ip = Convert.ToString(h["cf-connecting-ip"]);
            else if (d.ContainsKey("ip")) ip = Convert.ToString(d["ip"]);
            RelayLog.Write("whoami OK - the relay sees this PC as " + ip + "  (PC name " + Environment.MachineName + ")");
        }
        catch (Exception e) { RelayLog.Write("whoami FAILED: " + Describe(e)); }

        // Fresh room state: drops stale queued bytes from a previous run with the same token.
        try
        {
            HttpWebRequest rq = NewReq("/rt/agent/" + token + "/reset", "POST", 15000);
            rq.ContentLength = 0;
            ReadAll(rq.GetResponse());
            RelayLog.Write("relay room reset OK");
        }
        catch (Exception e) { RelayLog.Write("reset FAILED (old server? deploy the new server.js first): " + Describe(e)); }

        tcp = new TcpClient();
        tcp.NoDelay = true;
        tcp.Connect(vncHost, vncPort);
        ns = tcp.GetStream();
        RelayLog.Write("connected to local VNC server " + vncHost + ":" + vncPort);

        running = true;
        upThread = new Thread(UpLoop); upThread.IsBackground = true; upThread.Name = "up";
        downThread = new Thread(DownLoop); downThread.IsBackground = true; downThread.Name = "down";
        upThread.Start();
        downThread.Start();
        RelayLog.Write("[READY] kiosk side is up and reached the relay. Waiting for the browser (open it now with the same token)...");
    }

    // TightVNC -> relay. One POST at a time, strictly in order.
    void UpLoop()
    {
        byte[] buf = new byte[65536];
        try
        {
            while (running)
            {
                int n = ns.Read(buf, 0, buf.Length);
                if (n <= 0) { RelayLog.Write("TightVNC closed the connection"); break; }
                MemoryStream ms = new MemoryStream();
                ms.Write(buf, 0, n);
                while (ns.DataAvailable && ms.Length < 262144)
                {
                    n = ns.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    ms.Write(buf, 0, n);
                }
                byte[] body = ms.ToArray();
                tapUp.Feed(body, 0, body.Length);
                if (!Post(body)) break;
            }
        }
        catch (Exception e) { if (running) RelayLog.Write("up loop ended: " + Describe(e)); }
        running = false;
    }

    bool Post(byte[] body)
    {
        for (int attempt = 1; ; attempt++)
        {
            DateTime t0 = DateTime.UtcNow;
            try
            {
                HttpWebRequest rq = NewReq("/rt/agent/" + token + "/send", "POST", 60000);
                rq.ContentType = "application/octet-stream";
                rq.ContentLength = body.Length;
                using (Stream s = rq.GetRequestStream()) s.Write(body, 0, body.Length);
                ReadAll(rq.GetResponse());
                lastPostMs = (long)(DateTime.UtcNow - t0).TotalMilliseconds;
                long id = Interlocked.Increment(ref posts);
                RelayLog.Write("TX #" + id + "  " + body.Length + " bytes  (stream total " + tapUp.Total + ")  " + lastPostMs + " ms");
                return true;
            }
            catch (Exception e)
            {
                Interlocked.Increment(ref retries);
                RelayLog.Write("TX FAILED attempt " + attempt + ": " + Describe(e) + (attempt < 4 ? "  - retrying (a retry can duplicate bytes if the first one actually arrived)" : ""));
                if (attempt >= 4 || !running) return false;
                Thread.Sleep(300 * attempt);
            }
        }
    }

    // relay -> TightVNC. One long-poll in flight, re-issued immediately.
    void DownLoop()
    {
        JavaScriptSerializer js = new JavaScriptSerializer();
        js.MaxJsonLength = int.MaxValue;
        int failures = 0;
        while (running)
        {
            DateTime t0 = DateTime.UtcNow;
            try
            {
                string json = ReadAll(NewReq("/rt/agent/" + token + "/recv?wait=20000", "GET", 35000).GetResponse());
                failures = 0;
                lastPollMs = (long)(DateTime.UtcNow - t0).TotalMilliseconds;
                Interlocked.Increment(ref polls);
                Dictionary<string, object> d = js.Deserialize<Dictionary<string, object>>(json);
                ArrayList msgs = d.ContainsKey("messages") ? d["messages"] as ArrayList : null;
                int count = 0; long bytes = 0;
                if (msgs != null)
                {
                    foreach (object o in msgs)
                    {
                        Dictionary<string, object> m = o as Dictionary<string, object>;
                        if (m == null) continue;
                        byte[] data = Convert.FromBase64String(Convert.ToString(m["data"]));
                        bool binary = !m.ContainsKey("binary") || Convert.ToBoolean(m["binary"]);
                        if (!binary) { RelayLog.Write("RX text message ignored: " + Encoding.UTF8.GetString(data)); continue; }
                        tapDown.Feed(data, 0, data.Length);
                        ns.Write(data, 0, data.Length);
                        count++; bytes += data.Length;
                    }
                }
                if (count > 0 && !browserSeen)
                {
                    browserSeen = true;
                    RelayLog.Write("[CONNECTED] the browser is talking to this kiosk (first bytes received from the viewer)");
                }
                if (count > 0) RelayLog.Write("RX " + count + " msg  " + bytes + " bytes  (stream total " + tapDown.Total + ")  poll " + lastPollMs + " ms");
                if (d.ContainsKey("closed") && Convert.ToBoolean(d["closed"]))
                {
                    RelayLog.Write("relay says the viewer side closed (waiting for it to come back)");
                    Thread.Sleep(1000);
                }
            }
            catch (Exception e)
            {
                if (!running) break;
                failures++;
                RelayLog.Write("RECV FAILED (" + failures + "/6): " + Describe(e));
                if (failures >= 6) { RelayLog.Write("giving up"); break; }
                Thread.Sleep(Math.Min(2000, 300 * failures));
            }
        }
        running = false;
    }

    public void PrintStats()
    {
        RelayLog.Write("STAT  up=" + tapUp.Total + "B  down=" + tapDown.Total + "B  posts=" + Interlocked.Read(ref posts)
            + "  polls=" + Interlocked.Read(ref polls) + "  retries=" + Interlocked.Read(ref retries)
            + "  lastPostMs=" + lastPostMs + "  running=" + running);
    }

    public void Stop()
    {
        bool wasRunning = running;
        running = false;
        try { if (tcp != null) tcp.Close(); } catch (Exception) { }
        try
        {
            HttpWebRequest rq = NewReq("/rt/agent/" + token + "/close", "POST", 5000);
            rq.ContentLength = 0;
            ReadAll(rq.GetResponse());
        }
        catch (Exception) { }
        RelayLog.Write("stopped" + (wasRunning ? "" : " (it had already stopped by itself)"));
    }
}
'@

if (-not ('SionyxAgentTest' -as [type])) {
  Add-Type -TypeDefinition $cs -ReferencedAssemblies System.Web.Extensions, System.Core
}
[RelayLog]::FilePath = Join-Path $env:TEMP "sionyx-agent-test.log"
"---- new run $(Get-Date -Format s) ----" | Out-File -FilePath ([RelayLog]::FilePath) -Append -Encoding ascii

$agent = New-Object SionyxAgentTest -ArgumentList $BaseUrl, $Token, $VncHost, $VncPort
try {
  $agent.Start()
  while ($agent.Running) {
    Start-Sleep -Seconds 5
    $agent.PrintStats()
  }
  Write-Host "Agent stopped by itself - see the last log lines above."
}
catch {
  Write-Host "START FAILED: $($_.Exception.Message)" -ForegroundColor Red
  if ($_.Exception.InnerException) { Write-Host $_.Exception.InnerException.Message -ForegroundColor Red }
  Write-Host "Is TightVNC listening on ${VncHost}:${VncPort}?  Check:  Get-NetTCPConnection -LocalPort $VncPort -State Listen"
}
finally {
  $agent.Stop()
  Write-Host "Log file: $([RelayLog]::FilePath)"
}
