sionyx-vnc-relay
A tiny WebSocket relay (same job as `websockify`) plus a static
noVNC viewer page, used to remote-control
SIONYX kiosks over VNC even though:
the kiosks have no public IP / inbound port (they're behind normal NAT), and
the site's NetFree content filter does full TLS interception and blocks
every commercial remote-control tool that pins its own certificate
(RustDesk, AnyDesk, TeamViewer, the MeshCentral agent, ...).
Both sides of this relay talk plain `wss://` using the OS/browser trust
store (no pinning), the same way the kiosk's existing Firebase and
Understood-bridge traffic already does - which is why it gets through
NetFree where the others didn't.
`vnc.html` imports noVNC's `core/rfb.js` directly - it's vendored into
`public/novnc/core/` (copied as-is from `@novnc/novnc@1.7.0`, MPL-2.0,
https://github.com/novnc/noVNC) rather than pulled from a third-party CDN,
so there's no external dependency at serve time.
How it works
```
 Kiosk (SionyxKiosk.VncRelayService)          Admin's browser (vnc.html)
   TightVNC on 127.0.0.1:5900                        noVNC (RFB.js)
            │  raw VNC bytes                                │  RFB protocol
            ▼                                               ▼
     wss://.../agent/<token>   ───── this relay ─────  wss://.../viewer/<token>
```
`server.js` does not speak VNC at all - it just pairs the `agent` and
`viewer` WebSocket connections that share the same `<token>` and pipes
whatever bytes arrive on one straight to the other.
`<token>` is a one-time random string the dashboard generates per remote
session (see `sionyx-web`'s `requestVncSession`) and delivers to the kiosk
via Firebase and to the browser via the `vnc.html?token=...` link. It's a
shared room key, not a real auth system - treat each token as single-use
and short-lived.
Deploy (Render)
New Web Service on Render, connect this repo, Free plan.
Build command: `npm install` · Start command: `npm start`.
No environment variables required.
Once deployed, note the service URL (`https://<name>.onrender.com`) and
put it in `sionyx-web`'s VNC relay config and the kiosk's
`VncRelayUrl` setting.
Free-tier services on Render spin down after 15 minutes idle and take
about a minute to wake on the next connection - the same cold-start delay
SIONYX already handles for the Understood payment bridge.
Local dev
```
npm install
npm start   # listens on :3000
```

Transport fallback (NetFree)
Behind NetFree, `wss://` upgrades to this relay often get `418 Blocked by NetFree`
(or open and then carry no data), while plain HTTPS requests work. Both the kiosk
and `vnc.html` therefore try WebSocket first and fall back to HTTP long-polling
(`/rt/<role>/<token>/send|recv|close`) automatically - same rooms, same tokens,
and one side may be on WebSocket while the other is on HTTP.
Probe: a WebSocket is only trusted after `__relay_probe__` -> `__relay_probe_ack__`
round-trips. Clients opt in with `?probe=1`; until the probe succeeds the relay
routes/flushes nothing to that socket and lets a newcomer replace it (a "ghost"
connection NetFree ate can neither swallow data nor block the retry).
Clients without `?probe=1` (old builds, local relay) behave exactly as before.
Kiosk: `HttpRelayWebSocket.cs` implements `WebSocket` over HTTP so the existing
pump code is unchanged. Registry `VncRelayTransport` = `auto` (default) | `ws` | `http`.
Viewer: `public/relay-transport.js`. Append `?transport=http` (or `ws`) to
`vnc.html?token=...` to force one; the status line says "(HTTP - slower)" when on HTTP.
