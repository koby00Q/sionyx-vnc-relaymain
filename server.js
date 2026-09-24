// SIONYX VNC relay
//
// Purpose: let the org dashboard view/control a kiosk's screen via VNC even
// though the kiosk has no public IP and NetFree (the site's TLS-inspecting
// content filter) blocks every commercial remote-control tool that pins its
// own certificate (RustDesk, AnyDesk, TeamViewer, MeshCentral agent, etc).
//
// This service does NOT implement the VNC protocol itself - it is a plain
// byte pipe (the same job "websockify" does), same shape as the existing
// SIONYX Understood payment bridge:
//   - the kiosk (SionyxKiosk's VncRelayService) opens an outbound
//     WebSocket to /agent/<token> and forwards raw bytes to/from a local
//     VNC server (TightVNC) on 127.0.0.1:5900
//   - the admin's browser (noVNC, served from /vnc.html) opens a WebSocket
//     to /viewer/<token> and speaks the VNC protocol directly over it
//   - this server just pairs the two sockets with the same <token> and
//     relays whatever bytes arrive on one side to the other, unmodified
//
// Because both sides use plain WebSocket-over-TLS with the OS/browser
// trust store (no certificate pinning anywhere in this chain), the
// connection *should* ride through NetFree the same way the kiosk's
// existing Firebase/Render traffic already does. In practice (diagnosed
// 23/09/2026) NetFree returns "418 Blocked by NetFree" for many wss://
// upgrade attempts to this exact host, even though this server answered
// them with a normal 101 Switching Protocols - i.e. NetFree is rewriting
// the response on the way back, not blocking the request from reaching us.
// Plain HTTPS requests (POST/GET, including a 20s-held long-poll) to this
// same host were NOT blocked. So this file now offers two parallel
// transports for the exact same <token> room:
//   - WebSocket, unchanged, at /agent|viewer|controlAgent|controlViewer/<token>
//   - HTTP long-poll, new, at /rt/<role>/<token>/{send,recv,close}
// Clients that connect with ?probe=1 must pass a liveness probe before they
// are routed anything (see PROBE_MESSAGE) - this is what makes the fallback
// safe when NetFree hands the client a 418 for an upgrade we accepted.
// One side of a room can be on WebSocket while the other is on HTTP -
// the room-pairing logic below doesn't care which transport either side
// used, only the <token> and role.
//
// <token> is a one-time random string the dashboard generates per session
// (see computerService.js:requestVncSession) - it is not itself an auth
// system, just a shared room key. Whoever holds the token (delivered to
// the kiosk via Firebase, and to the admin via the dashboard link) can
// join that one session. Tokens are meant to be short-lived - open a new
// one each time you want to connect.

const http = require('http');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');

const app = express();
// Render sits behind Cloudflare + its own proxy. Without this, req.ip is the
// proxy's address ("::1"), which made every client look identical in the logs.
app.set('trust proxy', true);

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------
// Every log line gets an ISO timestamp with milliseconds, since Render's own
// timestamp column is per-line and coarser than we sometimes need when
// several events land within the same second.
function ts() { return new Date().toISOString(); }

// Room names/tokens are never logged in full (they're bearer credentials -
// whoever holds one can join that VNC session). We log a short, still-
// disambiguating label instead: first 6 chars of the token + a 4-char hash
// of the *whole* token, so two tokens that happen to share a 6-char prefix
// don't get confused with each other in the logs.
function roomLabel(token) {
  const hash = crypto.createHash('sha256').update(token).digest('hex').slice(0, 4);
  return `${token.slice(0, 6)}-#${hash}`;
}

console.log(`[relay] ${ts()} booting (node ${process.version}, pid ${process.pid})`);
process.on('SIGTERM', () => console.log(`[relay] ${ts()} SIGTERM received, shutting down`));
process.on('uncaughtException', (err) => console.error(`[relay] ${ts()} uncaughtException:`, err));
process.on('unhandledRejection', (err) => console.error(`[relay] ${ts()} unhandledRejection:`, err));

// ---------------------------------------------------------------------------
// /whoami - diagnostic only. Shows exactly what this server sees from your
// request: the IP it thinks you're connecting from and every header that
// arrived. Used to tell "NetFree blocked this before it reached us" (you get
// a 418 straight from NetFree, no line ever appears in Render's logs) apart
// from "it reached us but something else is wrong" (a request line DOES
// appear here). Safe to delete once the NetFree issue is resolved.
// ---------------------------------------------------------------------------
app.get('/whoami', (req, res) => {
  console.log(`[relay] ${ts()} /whoami from ip=${req.ip} xff=${req.headers['x-forwarded-for'] || '-'}`);
  res.json({
    time: new Date().toISOString(),
    uptimeSeconds: Math.round(process.uptime()),
    ip: req.headers['cf-connecting-ip'] || req.ip,
    ips: req.ips,
    headers: req.headers,
  });
});

// The manual kiosk-side test script (public/agent-test.ps1), served as plain text
// so the kiosk can fetch it with iwr/irm (express.static would label .ps1 as
// application/octet-stream, which PowerShell hands back as bytes, not text).
app.get('/agent-test.ps1', (_req, res) => {
  res.type('text/plain; charset=utf-8').sendFile(path.join(__dirname, 'public', 'agent-test.ps1'));
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (_req, res) => res.status(200).send('SIONYX VNC Relay is up'));
app.get('/health', (_req, res) => res.send('ok'));

const server = http.createServer(app);
// perMessageDeflate is ON by default in `ws`. VNC's Tight encoding is
// already compressed, so re-compressing every frame with zlib here just
// burns CPU for no size benefit - on Render's free tier (a sliver of a
// shared vCPU) that zlib work runs on the same single thread as every
// other room's message routing, so one active session can stall the
// whole relay: connections open fine, then everything freezes within
// seconds. Disabling it is a pure byte-pipe with no compression tradeoff.
const wss = new WebSocketServer({ server, perMessageDeflate: false });

// Log every WebSocket upgrade *attempt* before the `ws` library decides
// whether to accept it. If a browser/agent reports "connection failed" and
// no matching "upgrade attempt" line shows up here, the request never
// reached this process at all - it was blocked upstream (NetFree, a proxy,
// a firewall), not by anything in this file. This listener runs alongside
// (not instead of) the WebSocketServer's own internal 'upgrade' listener,
// so it doesn't change connection handling - it's purely observational.
server.on('upgrade', (req) => {
  console.log(
    `[relay] ${ts()} upgrade attempt path=${req.url} ip=${req.socket.remoteAddress} `
    + `xff=${req.headers['x-forwarded-for'] || '-'} origin=${req.headers.origin || '-'} `
    + `ua=${req.headers['user-agent'] || '-'}`
  );
});

/**
 * token -> {
 *   agent, viewer, controlAgent, controlViewer: WebSocket|null,
 *   pending: { <role>: Array<{data, isBinary}> },   // queued for a role that hasn't received it yet
 *   httpSeen: { <role>: number|undefined },          // last time this role was active over HTTP (ms epoch)
 * }
 */
const rooms = new Map();

// Two independent pairs share the same room-by-token mechanism:
//  - agent/viewer: the existing raw VNC byte-pipe (TightVNC <-> noVNC).
//  - controlAgent/controlViewer: a separate, JSON-only side channel added
//    2026-09-14 for "elevated click" - see vnc.html and VncRelayService's
//    RunControlChannelAsync. It never touches the VNC byte stream, so it
//    can't corrupt or double-inject anything on that path even if this
//    new code has bugs - worst case the elevated-click button just doesn't
//    work, the normal VNC session is unaffected either way.
const ROLE_PAIRS = {
  agent: 'viewer',
  viewer: 'agent',
  controlAgent: 'controlViewer',
  controlViewer: 'controlAgent',
};
const ROLES = Object.keys(ROLE_PAIRS);

// The very first bytes an agent sends (the VNC handshake, e.g. "RFB 003.008\n")
// often arrive before the browser/viewer has finished loading noVNC and
// joining the room. With no buffering those bytes were silently dropped -
// the viewer would never see the handshake and would hang on "connecting"
// forever, even though the agent and relay were both working correctly.
// This buffer holds messages sent to a peer that hasn't joined yet, and
// flushes them in order the moment that peer connects (WebSocket) or polls
// (HTTP /recv).
const MAX_PENDING_MESSAGES = 200; // per room, per role - generous for a VNC handshake burst
const MAX_PENDING_BYTES = 5 * 1024 * 1024; // 5MB safety cap per room/role

// Once a peer's own outgoing buffer holds more than this much unsent data,
// stop reading more from the source side until it drains. Without this,
// a slow receiver (capped Render free instance, or the kiosk's uplink)
// never gets an error - the relay just keeps queuing screen updates into
// memory faster than they can be sent, and the session looks frozen once
// the backlog is big enough to matter. Only applies to the WebSocket path -
// the HTTP path has no persistent socket to back up, so pending/MAX_PENDING_*
// is the only cap that matters there.
const BACKPRESSURE_THRESHOLD_BYTES = 1 * 1024 * 1024; // 1MB

// An HTTP-side role is considered "connected" if it has sent or polled
// within this window. Below this, messages for it are delivered straight
// into its pending queue as usual. Above it (or if it's never been seen),
// behavior is the same either way - the difference only matters for logging
// ("joined" vs silently queuing for a room nobody is polling any more).
const HTTP_ACTIVE_WINDOW_MS = 30000;

// Liveness probe for WebSocket clients that connect with ?probe=1 (the new
// kiosk build and vnc.html). NetFree can hand the client a 418 (or silently
// swallow traffic) while this server has already accepted the upgrade - a
// "ghost" connection that looks perfectly healthy from here. A probing client
// sends PROBE right after connecting; the server answers ACK. Only once the
// client has seen the ACK (i.e. the connection provably works in BOTH
// directions) is the socket treated as usable: before that, nothing is routed
// or flushed to it and a newcomer may replace it. Clients that don't ask for
// probing (old builds, the local relay) behave exactly as before.
const PROBE_MESSAGE = '__relay_probe__';
const PROBE_ACK = '__relay_probe_ack__';


// ---------------------------------------------------------------------------
// Stream taps (diagnostics)
// ---------------------------------------------------------------------------
// A VNC session is ONE ordered byte stream per direction. If a single byte is
// lost, duplicated or reordered anywhere on the way, noVNC fails with garbage
// like "Unsupported encoding: 214103812". To find WHERE the stream breaks, each
// hop keeps a running byte counter + CRC32 and logs it at fixed offsets
// (every 64 KiB for the first MiB, then every MiB). The kiosk test script, this
// server and the browser (vnc.html?debug=1) use the same offsets, so the first
// offset where two hops print a different crc is where the stream was damaged.
const TAP_FINE_LIMIT = 1024 * 1024;
const TAP_FINE_STEP = 8 * 1024;
const TAP_COARSE_STEP = 1024 * 1024;
function tapNextCheckpoint(off) {
  return off < TAP_FINE_LIMIT
    ? (Math.floor(off / TAP_FINE_STEP) + 1) * TAP_FINE_STEP
    : (Math.floor(off / TAP_COARSE_STEP) + 1) * TAP_COARSE_STEP;
}
const zlibCrc32 = require('zlib').crc32; // Node >= 20.15 / 22.2; taps are skipped on older Node
class StreamTap {
  constructor(label) { this.label = label; this.total = 0; this.crc = 0; }
  feed(buf) {
    if (!zlibCrc32) { this.total += buf.length; return; }
    let pos = 0;
    while (pos < buf.length) {
      const next = tapNextCheckpoint(this.total);
      const take = Math.min(buf.length - pos, next - this.total);
      this.crc = zlibCrc32(buf.subarray(pos, pos + take), this.crc);
      this.total += take; pos += take;
      if (this.total === next) {
        console.log(`[tap] ${ts()} ${this.label} @${this.total} crc=${(this.crc >>> 0).toString(16).padStart(8, '0')}`);
      }
    }
  }
}
function tapOf(room, role, kind) {
  const key = `${role}.${kind}`;
  if (!room.taps[key]) room.taps[key] = new StreamTap(`${roomLabel(room.token)} ${key}`);
  return room.taps[key];
}
const asBuf = (d) => (Buffer.isBuffer(d) ? d : Buffer.from(d));
function isByteStreamRole(role) { return role === 'agent' || role === 'viewer'; }

function httpActive(room, role) {
  const seen = room.httpSeen[role];
  return !!seen && (Date.now() - seen) < HTTP_ACTIVE_WINDOW_MS;
}

// A WebSocket that is open and (if it asked for probing) proved it works.
function wsUsable(ws) {
  return !!ws && ws.readyState === WebSocket.OPEN && ws._ready !== false;
}

function wakeWaiters(room, role) {
  const list = room.waiters[role];
  if (!list || !list.length) return;
  room.waiters[role] = [];
  for (const fn of list) fn();
}

// Resolves when something is queued/changed for <role>, or after ms.
function waitForWake(room, role, ms) {
  return new Promise((resolve) => {
    let timer;
    const done = () => { clearTimeout(timer); resolve(); };
    timer = setTimeout(() => {
      room.waiters[role] = (room.waiters[role] || []).filter((f) => f !== done);
      resolve();
    }, ms);
    (room.waiters[role] = room.waiters[role] || []).push(done);
  });
}

function getRoom(token) {
  let room = rooms.get(token);
  if (!room) {
    room = { token, taps: {}, pending: {}, httpSeen: {}, peerClosed: {}, waiters: {} };
    for (const role of ROLES) {
      room[role] = null; room.pending[role] = []; room.peerClosed[role] = false; room.waiters[role] = [];
    }
    rooms.set(token, room);
  }
  return room;
}

function cleanupIfEmpty(token, room) {
  const anyWs = ROLES.some((role) => !!room[role]);
  const anyHttp = ROLES.some((role) => httpActive(room, role));
  if (!anyWs && !anyHttp) rooms.delete(token);
}

function pendingByteLength(queue) {
  return queue.reduce((sum, item) => sum + item.data.length, 0);
}

// VNC (agent/viewer) is a byte stream: dropping ANY queued chunk silently
// shifts every later byte and noVNC dies with "Unsupported encoding". The old
// code dropped the OLDEST chunks whenever a slow HTTP poller let more than
// 200 messages / 5 MB pile up (an easy thing to hit: the very first full-screen
// frame is several MB). Now a byte-stream queue is never trimmed. Instead:
//   - /send makes the sender wait (backpressure) while the peer's queue is big,
//   - and if the queue still grows past HARD_CAP the session is closed loudly
//     (both sides see a disconnect) rather than delivering a corrupted stream.
// Control channels (JSON messages, occasional) keep the old drop-oldest cap.
// Max raw bytes per /recv response (see the NetFree note in the recv handler).
const RECV_MAX_BYTES = 16000;
const STREAM_HARD_CAP_BYTES = 64 * 1024 * 1024;
const STREAM_HIGH_WATER_BYTES = 2 * 1024 * 1024; // /send stalls above this
const STREAM_LOW_WATER_BYTES = 512 * 1024;       // ...until it drains below this

function bufferForPeer(room, peerRole, data, isBinary) {
  const queue = room.pending[peerRole];
  queue.push({ data, isBinary });
  if (isByteStreamRole(peerRole)) {
    if (pendingByteLength(queue) > STREAM_HARD_CAP_BYTES) {
      console.error(`[relay] ${ts()} OVERFLOW room ${roomLabel(room.token)}: ${peerRole} is not draining (>${STREAM_HARD_CAP_BYTES} bytes queued). Closing the session instead of dropping bytes.`);
      queue.length = 0;
      room.peerClosed[peerRole] = true;
      const ws = room[peerRole];
      if (ws) { try { ws.close(1011, 'relay overflow'); } catch { /* ignore */ } }
    }
  } else {
    while (queue.length > MAX_PENDING_MESSAGES || pendingByteLength(queue) > MAX_PENDING_BYTES) {
      queue.shift();
    }
  }
  wakeWaiters(room, peerRole);
}

function flushPending(room, role, ws) {
  const queue = room.pending[role];
  if (!queue.length) return;
  for (const { data, isBinary } of queue) {
    ws.send(data, { binary: isBinary });
    if (isByteStreamRole(role) && isBinary) tapOf(room, ROLE_PAIRS[role], 'out').feed(asBuf(data));
  }
  console.log(`[relay] ${ts()} flushed ${queue.length} buffered message(s) to newly-joined ${role}`);
  queue.length = 0;
}

// Shared by both transports: deliver one message that <role> just produced
// to its peer. If the peer is a live WebSocket, send directly (and apply
// backpressure). Otherwise queue it - a live WebSocket peer will get it via
// flushPending() on connect, an HTTP peer will get it via GET /recv.
function routeMessage(room, role, data, isBinary) {
  const peerRole = ROLE_PAIRS[role];
  const peer = room[peerRole];
  const tapped = isByteStreamRole(role) && isBinary;
  if (tapped) tapOf(room, role, 'in').feed(asBuf(data));
  // Prefer HTTP if the peer is currently talking to us over HTTP: a ghost
  // WebSocket (see PROBE_MESSAGE) may still be registered for that role, and
  // anything sent into it would vanish.
  if (wsUsable(peer) && !httpActive(room, peerRole)) {
    peer.send(data, { binary: isBinary });
    if (tapped) tapOf(room, role, 'out').feed(asBuf(data));
    if (peer.bufferedAmount > BACKPRESSURE_THRESHOLD_BYTES) {
      return 'peer-backpressured'; // caller decides what to do (WS path pauses; HTTP path ignores - no socket to pause)
    }
    return 'sent';
  }
  bufferForPeer(room, peerRole, data, isBinary);
  return 'buffered';
}

// Render's proxy silently kills idle WebSocket connections after ~20-25s
// of no traffic. A dashboard viewer can sit for 20+ seconds waiting for
// the kiosk agent to finish signing in to Firebase and connecting - long
// enough to get killed before the agent ever joins. A periodic ping/pong
// keeps the connection classified as "active" so it survives that wait.
// Browsers and .NET's ClientWebSocket both answer ping frames automatically
// at the protocol level - no client-side code changes needed on either
// the noVNC viewer or the kiosk's VncRelayService.
const HEARTBEAT_INTERVAL_MS = 15000;

// How long a connection can go without any traffic (message or pong)
// before a NEW connection for the same role is allowed to evict it. Below
// this threshold the existing connection is assumed to still be genuinely
// in use, so a second connect attempt for the same role is treated as a
// spurious duplicate (e.g. a client-side retry/fallback race - see
// VncRelayService's manual-handshake fallback, which can end up racing
// against a still-pending primary attempt) rather than a real reconnect,
// and is rejected instead of killing the working session.
const STALE_CONNECTION_MS = 10000;

function startHeartbeat(ws) {
  ws.isAlive = true;
  ws.lastActivity = Date.now();
  ws.on('pong', () => { ws.isAlive = true; ws.lastActivity = Date.now(); });
  const interval = setInterval(() => {
    if (ws.readyState !== WebSocket.OPEN) {
      clearInterval(interval);
      return;
    }
    if (!ws.isAlive) {
      ws.terminate();
      clearInterval(interval);
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }, HEARTBEAT_INTERVAL_MS);
  ws.on('close', () => clearInterval(interval));
}

wss.on('connection', (ws, req) => {
  let url;
  try {
    url = new URL(req.url, 'http://relay.local');
  } catch {
    ws.close(1008, 'bad request');
    return;
  }

  // Expected paths: /agent/<token>, /viewer/<token>, /controlAgent/<token>,
  // or /controlViewer/<token>.
  const parts = url.pathname.split('/').filter(Boolean);
  const role = parts[0];
  const token = parts[1];

  if (!ROLE_PAIRS[role] || !token || token.length < 8) {
    console.log(`[relay] ${ts()} rejecting bad path=${url.pathname} reason="expected /agent|viewer|controlAgent|controlViewer/<token>"`);
    ws.close(1008, 'expected /agent|viewer|controlAgent|controlViewer/<token>');
    return;
  }

  const room = getRoom(token);
  const label = roomLabel(token);
  const wantProbe = url.searchParams.get('probe') === '1';

  console.log(`[relay] ${ts()} responding to upgrade with 101 for ${role} in room ${label}${wantProbe ? ' (probe requested)' : ''}`);

  // A new connection for a role replaces a STALE one (e.g. a page reload,
  // or the kiosk's WS reconnecting after a real network blip). But if the
  // existing connection for this role has had real traffic recently, it's
  // still genuinely in use - unconditionally closing it here was causing
  // working sessions to drop the moment a second, spurious connection
  // attempt showed up for the same role (e.g. a client-side retry racing
  // a still-pending primary attempt). In that case reject the newcomer
  // instead and let the existing session keep running.
  const existing = room[role];
  if (existing) {
    // An existing probing connection that never passed its probe is a ghost
    // (NetFree ate the handshake response) - always replaceable.
    const isStale = existing.readyState !== WebSocket.OPEN
      || existing._ready === false
      || (Date.now() - (existing.lastActivity || 0)) > STALE_CONNECTION_MS;
    if (!isStale) {
      console.log(`[relay] ${ts()} rejecting duplicate ${role} connection for room ${label} - existing connection still active`);
      ws.close(4009, 'role already active');
      return;
    }
    try { existing.close(); } catch { /* ignore */ }
  }
  room[role] = ws;
  ws._role = role;
  ws._token = token;
  ws._msgsIn = 0;
  ws._openedAt = Date.now();
  ws._ready = !wantProbe; // false until the probe arrives (probing clients only)
  room.peerClosed[ROLE_PAIRS[role]] = false; // this role is (re)joining
  startHeartbeat(ws);

  console.log(`[relay] ${ts()} ${role} joined room ${label} (${ROLES.map((r) => `${r}=${!!room[r]}`).join(' ')})`);

  // Send anything that arrived for this role before it joined (e.g. the
  // agent's initial VNC handshake bytes sent before the viewer loaded).
  // Probing clients get this only after their probe succeeds (see below).
  if (ws._ready) flushPending(room, role, ws);

  ws.on('message', (data, isBinary) => {
    ws.lastActivity = Date.now();
    ws._msgsIn += 1;
    const r = rooms.get(token);
    if (!r) return;

    if (!isBinary && data.length === PROBE_MESSAGE.length && data.toString() === PROBE_MESSAGE) {
      // Liveness probe: never routed to the peer.
      const first = !ws._ready;
      ws._ready = true;
      ws.send(PROBE_ACK, { binary: false });
      console.log(`[relay] ${ts()} ${role} probe ok in room ${label}${first ? ' - now active' : ''}`);
      if (first) flushPending(r, role, ws);
      return;
    }
    if (!ws._ready) return; // data from a probing client that hasn't proven itself yet
    const outcome = routeMessage(r, role, data, isBinary);
    if (outcome === 'peer-backpressured') {
      // Backpressure: while the screen is static there's almost no traffic,
      // so this never triggers - which is why a fresh connection looks
      // fine. The moment real use starts (mouse move, typing, a window
      // redrawing) TightVNC starts streaming framebuffer updates
      // continuously. If the peer's socket (browser on a capped Render
      // free instance, or the kiosk's uplink) can't drain as fast as the
      // other side produces, peer.send() just keeps queuing into Node's
      // memory with no limit - nothing ever errors, it just falls further
      // and further behind until the session looks completely frozen.
      // Pausing the source stops reading (and relaying) more data until
      // the peer's outgoing buffer has drained, pushing the slowdown back
      // to whichever side is actually behind instead of piling it up here.
      const peer = r[ROLE_PAIRS[role]];
      ws.pause();
      const resumeWhenDrained = () => {
        if (!peer || peer.readyState !== WebSocket.OPEN || peer.bufferedAmount <= BACKPRESSURE_THRESHOLD_BYTES) {
          if (ws.readyState === WebSocket.OPEN) ws.resume();
        } else {
          setTimeout(resumeWhenDrained, 50);
        }
      };
      setTimeout(resumeWhenDrained, 50);
    }
  });

  ws.on('close', (code, reason) => {
    const lifetimeMs = Date.now() - ws._openedAt;
    console.log(
      `[relay] ${ts()} ${role} closed room ${label} code=${code} reason=${reason || '-'} `
      + `lifetimeMs=${lifetimeMs} msgsIn=${ws._msgsIn}`
    );
    const r = rooms.get(token);
    if (!r) return;
    if (r[role] === ws) {
      r[role] = null;
      // Tell an HTTP-side peer that this side is gone (a ghost that never
      // passed its probe doesn't count, nor does a role still active over HTTP).
      if (ws._ready && !httpActive(r, role)) {
        r.peerClosed[ROLE_PAIRS[role]] = true;
        wakeWaiters(r, ROLE_PAIRS[role]);
      }
    }
    cleanupIfEmpty(token, r);
  });

  ws.on('error', (err) => {
    console.error(`[relay] ${ts()} ${role} socket error in room ${label}:`, err.message);
    // 'close' fires right after - cleanup happens there
  });
});

// ---------------------------------------------------------------------------
// HTTP long-poll fallback transport
// ---------------------------------------------------------------------------
// For networks where NetFree (or anything else) mangles the WebSocket
// upgrade response but leaves plain HTTPS alone. Same rooms, same
// ROLE_PAIRS, same pending-queue plumbing as the WebSocket path above - the
// only difference is that "the connection" is just a sequence of ordinary
// requests instead of one held-open socket.
//
//   POST /rt/<role>/<token>/send?t=1   body = the message (raw bytes, or
//                                      text if ?t=1 is present)
//   GET  /rt/<role>/<token>/recv?wait=20000   long-polls up to `wait` ms
//                                      (default 20000, capped at 25000 to
//                                      stay under Render's own idle-request
//                                      limits) and returns whatever
//                                      messages are waiting, as JSON:
//                                      { messages: [{data: base64, binary: bool}, ...] }
//                                      or an empty array on timeout - the
//                                      client is expected to call recv again
//                                      immediately after.
//   POST /rt/<role>/<token>/close      marks this role as gone, same as a
//                                      WebSocket close.
//
// A room doesn't care which transport either side is using - an agent on
// WebSocket can talk to a viewer on HTTP and vice versa, because both paths
// end up going through the same room[role]/room.pending[role] state.

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

function parseRoleToken(req, res) {
  const { role, token } = req.params;
  if (!ROLE_PAIRS[role] || !token || token.length < 8) {
    res.status(400).json({ error: 'expected /rt/<role>/<token>/... with role in agent|viewer|controlAgent|controlViewer' });
    return null;
  }
  return { role, token };
}

app.post('/rt/:role/:token/send', express.raw({ type: () => true, limit: '10mb' }), async (req, res) => {
  const parsed = parseRoleToken(req, res);
  if (!parsed) return;
  const { role, token } = parsed;
  const room = getRoom(token);
  const label = roomLabel(token);
  const isText = req.query.t === '1';
  const body = req.body && req.body.length ? req.body : Buffer.alloc(0);

  room.httpSeen[role] = Date.now();
  room.peerClosed[ROLE_PAIRS[role]] = false;
  console.log(`[relay] ${ts()} http-send ${role} room ${label} bytes=${body.length} text=${isText}`);

  const outcome = routeMessage(room, role, body, !isText);

  // Backpressure for byte streams: the sender posts strictly one chunk at a
  // time, so holding this response while the peer's queue is big stalls the
  // sender (and, on the kiosk, its reads from TightVNC) instead of letting the
  // queue grow without bound. Nothing is dropped; it just waits for the peer.
  const peerRole = ROLE_PAIRS[role];
  if (outcome === 'buffered' && isByteStreamRole(role) && pendingByteLength(room.pending[peerRole]) > STREAM_HIGH_WATER_BYTES) {
    const t0 = Date.now();
    while (rooms.has(token) && pendingByteLength(room.pending[peerRole]) > STREAM_LOW_WATER_BYTES && Date.now() - t0 < 20000) {
      await waitForWake(room, `${role}:drained`, 250);
    }
    console.log(`[relay] ${ts()} http-send ${role} room ${label} held ${Date.now() - t0}ms for backpressure (peer backlog=${pendingByteLength(room.pending[peerRole])})`);
  }
  res.json({ ok: true, outcome });
});

app.get('/rt/:role/:token/recv', async (req, res) => {
  const parsed = parseRoleToken(req, res);
  if (!parsed) return;
  const { role, token } = parsed;
  const room = getRoom(token);
  const label = roomLabel(token);

  const wasActive = httpActive(room, role);
  room.httpSeen[role] = Date.now();
  room.peerClosed[ROLE_PAIRS[role]] = false;
  if (!wasActive) {
    console.log(`[relay] ${ts()} ${role} joined room ${label} over HTTP`);
  }

  const requestedWait = parseInt(req.query.wait, 10);
  const waitMs = Number.isFinite(requestedWait) ? Math.min(Math.max(requestedWait, 0), 25000) : 20000;

  // If the client hangs up mid-poll (its own timeout, a network blip), we
  // must not hand the messages we were about to deliver to nobody - for a VNC
  // byte stream that would corrupt the session. Track it and re-queue below.
  let clientGone = false;
  res.on('close', () => {
    if (!res.writableEnded) { clientGone = true; wakeWaiters(room, role); }
  });

  const deadline = Date.now() + waitMs;
  let messages = [];
  let closed = false;
  while (true) {
    const queue = room.pending[role];
    if (queue.length) {
      messages = queue.splice(0, queue.length);
      wakeWaiters(room, `${ROLE_PAIRS[role]}:drained`); // release a /send held by backpressure
      break;
    }
    if (room.peerClosed[role]) { closed = true; break; }
    const remaining = deadline - Date.now();
    if (remaining <= 0 || clientGone) break;
    await waitForWake(room, role, remaining);
    // The room may have been garbage-collected while we waited.
    if (!rooms.has(token)) break;
  }

  if (clientGone) {
    if (messages.length) room.pending[role].unshift(...messages);
    return;
  }

  room.httpSeen[role] = Date.now();

  // VNC byte streams don't care about message boundaries, so merge a backlog
  // into one message: far fewer base64 items and round trips.
  if (messages.length > 1 && messages.every((m) => m.isBinary) && (role === 'agent' || role === 'viewer')) {
    messages = [{ data: Buffer.concat(messages.map((m) => Buffer.from(m.data))), isBinary: true }];
  }

  // NetFree (TLS interception) truncates large /recv responses: measured from
  // the kiosk, up to 21,336 base64 chars arrive intact (16,000 bytes) but
  // anything bigger comes back cut at ~29,398 chars with the JSON tail still
  // in place, i.e. corrupt base64 and a corrupted VNC stream. So never answer
  // with more than RECV_MAX_BYTES of a byte stream; the rest goes back to the
  // front of the queue and the client's next poll (issued immediately) gets it.
  if (isByteStreamRole(role) && messages.length === 1 && messages[0].isBinary && messages[0].data.length > RECV_MAX_BYTES) {
    const whole = Buffer.from(messages[0].data);
    messages = [{ data: whole.subarray(0, RECV_MAX_BYTES), isBinary: true }];
    room.pending[role].unshift({ data: whole.subarray(RECV_MAX_BYTES), isBinary: true });
    wakeWaiters(room, role);
  }

  if (messages.length) {
    let bytes = 0;
    for (const m of messages) {
      bytes += m.data.length;
      if (isByteStreamRole(role) && m.isBinary) tapOf(room, ROLE_PAIRS[role], 'out').feed(asBuf(m.data));
    }
    console.log(`[relay] ${ts()} http-recv ${role} room ${label} delivering=${messages.length} bytes=${bytes}`);
  }

  res.json({
    messages: messages.map(({ data, isBinary }) => ({
      data: Buffer.from(data).toString('base64'),
      len: Buffer.from(data).length,
      binary: isBinary,
    })),
    ...(closed ? { closed: true } : {}),
  });
});

app.post('/rt/:role/:token/close', (req, res) => {
  const parsed = parseRoleToken(req, res);
  if (!parsed) return;
  const { role, token } = parsed;
  const room = rooms.get(token);
  const label = roomLabel(token);
  console.log(`[relay] ${ts()} http-close ${role} room ${label}`);
  if (room) {
    delete room.httpSeen[role];
    const ws = room[role];
    if (!(ws && wsUsable(ws))) {
      room.peerClosed[ROLE_PAIRS[role]] = true;
      wakeWaiters(room, ROLE_PAIRS[role]);
    }
    cleanupIfEmpty(token, room);
  }
  res.json({ ok: true });
});

// POST /rt/<role>/<token>/reset - forget everything queued for this role AND its
// peer, and restart the stream counters. A new VNC session (the kiosk agent
// opening a fresh TCP connection to TightVNC) is a brand-new byte stream, so
// bytes left over from a previous session under the same token must not be
// delivered in front of it. Used by the manual test script, which reuses a
// fixed token; harmless for normal one-time tokens.
app.post('/rt/:role/:token/reset', (req, res) => {
  const parsed = parseRoleToken(req, res);
  if (!parsed) return;
  const { role, token } = parsed;
  const room = getRoom(token);
  for (const r of [role, ROLE_PAIRS[role]]) {
    room.pending[r].length = 0;
    room.peerClosed[r] = false;
    wakeWaiters(room, r);
  }
  room.taps = {};
  room.httpSeen[role] = Date.now();
  console.log(`[relay] ${ts()} http-reset ${role} room ${roomLabel(token)} (queues and stream counters cleared)`);
  res.json({ ok: true });
});

// HTTP-only rooms have no socket 'close' event to clean them up, so sweep
// rooms nobody has touched recently (WebSocket rooms clean up on close).
setInterval(() => {
  for (const [token, room] of rooms) cleanupIfEmpty(token, room);
}, 60000).unref();

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`[relay] ${ts()} listening on ${PORT} (node ${process.version}, pid ${process.pid})`));
