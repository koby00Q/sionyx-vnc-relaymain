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
// connection rides through NetFree the same way the kiosk's existing
// Firebase/Render traffic already does.
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

// ---- Logging helpers -------------------------------------------------------
// Every line gets an ISO timestamp with milliseconds (Render's own column is
// only second-resolution). Tokens are never logged in full: a room is shown
// as "<first 6 chars>#<4 hex of sha1>", so two rooms that share a prefix
// (diag7-a / diag7-b) still look different in the logs.
const log = (...args) => console.log(new Date().toISOString(), '[relay]', ...args);
const roomLabel = (token) =>
  `${String(token).slice(0, 6)}#${crypto.createHash('sha1').update(String(token)).digest('hex').slice(0, 4)}`;
const clientIp = (req) =>
  String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();
const short = (v, n = 90) => (v == null ? '-' : String(v).slice(0, n));
// "/viewer/abcdef123456" -> "/viewer/abcdef#1a2b" (never log a full token)
const maskPath = (rawUrl) => {
  try {
    const parts = new URL(rawUrl, 'http://relay.local').pathname.split('/').filter(Boolean);
    return parts.length >= 2 ? `/${parts[0]}/${roomLabel(parts[1])}` : `/${parts.join('/')}`;
  } catch { return '(unparseable url)'; }
};

const app = express();

// Plain HTTP request log (skips /health so Render's health checks don't spam).
app.use((req, res, next) => {
  if (req.path === '/health' || req.path.startsWith('/rt/')) return next();
  const t0 = Date.now();
  res.on('finish', () => {
    log(`http ${req.method} ${maskPath(req.originalUrl)} -> ${res.statusCode} ${Date.now() - t0}ms ip=${clientIp(req)} ua="${short(req.headers['user-agent'])}"`);
  });
  next();
});

// Echoes what the server actually sees for the caller's own request. Open it
// from the browser: if it loads, plain HTTPS from that browser reaches the
// relay; the JSON shows the IP / Origin / User-Agent the relay receives.
app.get('/whoami', (req, res) => {
  const { cookie, authorization, ...headers } = req.headers;
  res.json({ time: new Date().toISOString(), uptimeSeconds: Math.round(process.uptime()), ip: clientIp(req), headers });
});

// Plain-HTTPS transport (no WebSocket upgrade) - see the "HTTP transport"
// section further down. Same rooms/roles as the WebSocket path.
app.use((req, res, next) => (req.path.startsWith('/rt/') ? handleRt(req, res) : next()));

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (_req, res) => res.status(200).send('SIONYX VNC Relay is up'));
app.get('/health', (_req, res) => res.send('ok'));

const server = http.createServer(app);

// Logged BEFORE the ws library handles the handshake. If a browser attempt
// never produces one of these lines, the request did not reach this server
// at all (blocked upstream: NetFree, proxy, extension...). `ws` registers its
// own 'upgrade' listener; this one is an additional read-only observer.
server.on('upgrade', (req) => {
  log(`upgrade ${maskPath(req.url)} ip=${clientIp(req)} origin=${short(req.headers.origin)} ua="${short(req.headers['user-agent'])}" ver=${short(req.headers['sec-websocket-version'])} up=${Math.round(process.uptime())}s`);
  // Full request headers exactly as the relay received them (after any proxy /
  // TLS-inspecting filter on the way). Comparing a browser attempt with a
  // PowerShell attempt shows what differs. Secrets and the WebSocket key are dropped.
  const { cookie, authorization, 'sec-websocket-key': _key, ...hdrs } = req.headers;
  log(`upgrade headers ${maskPath(req.url)} http/${req.httpVersion}: ${JSON.stringify(hdrs)}`);
});

// Malformed HTTP on a connection. Adding this listener replaces Node's
// default handler, so replicate it: answer 400 and close.
server.on('clientError', (err, socket) => {
  log(`clientError ${err.code || ''} ${err.message}`);
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  else socket.destroy();
});
// perMessageDeflate is ON by default in `ws`. VNC's Tight encoding is
// already compressed, so re-compressing every frame with zlib here just
// burns CPU for no size benefit - on Render's free tier (a sliver of a
// shared vCPU) that zlib work runs on the same single thread as every
// other room's message routing, so one active session can stall the
// whole relay: connections open fine, then everything freezes within
// seconds. Disabling it is a pure byte-pipe with no compression tradeoff.
const wss = new WebSocketServer({ server, perMessageDeflate: false });

/** token -> { <role>: WebSocket|null, pending: { <role>: Array } } */
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
// flushes them in order the moment that peer connects.
const MAX_PENDING_MESSAGES = 200; // per room, per role - generous for a VNC handshake burst
const MAX_PENDING_BYTES = 5 * 1024 * 1024; // 5MB safety cap per room/role

// Once a peer's own outgoing buffer holds more than this much unsent data,
// stop reading more from the source side until it drains. Without this,
// a slow receiver (capped Render free instance, or the kiosk's uplink)
// never gets an error - the relay just keeps queuing screen updates into
// memory faster than they can be sent, and the session looks frozen once
// the backlog is big enough to matter.
const BACKPRESSURE_THRESHOLD_BYTES = 1 * 1024 * 1024; // 1MB

function getRoom(token) {
  let room = rooms.get(token);
  if (!room) {
    room = { pending: {} };
    for (const role of ROLES) { room[role] = null; room.pending[role] = []; }
    rooms.set(token, room);
  }
  return room;
}

function cleanupIfEmpty(token, room) {
  if (ROLES.every((role) => !room[role])) rooms.delete(token);
}

function pendingByteLength(queue) {
  return queue.reduce((sum, item) => sum + item.data.length, 0);
}

function bufferForPeer(room, peerRole, data, isBinary) {
  const queue = room.pending[peerRole];
  queue.push({ data, isBinary });
  while (queue.length > MAX_PENDING_MESSAGES || pendingByteLength(queue) > MAX_PENDING_BYTES) {
    queue.shift();
  }
}

function flushPending(room, role, ws) {
  const queue = room.pending[role];
  if (!queue.length) return;
  for (const { data, isBinary } of queue) {
    ws.send(data, { binary: isBinary });
    ws.msgsOut += 1;
  }
  log(`flushed ${queue.length} buffered message(s) to newly-joined ${role}`);
  queue.length = 0;
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
      log(`heartbeat timeout, terminating ${ws.logName || 'connection'} (no pong for ${HEARTBEAT_INTERVAL_MS}ms)`);
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
    log(`closing: unparseable url ${short(req.url)}`);
    ws.close(1008, 'bad request');
    return;
  }

  // Expected paths: /agent/<token>, /viewer/<token>, /controlAgent/<token>,
  // or /controlViewer/<token>.
  const parts = url.pathname.split('/').filter(Boolean);
  const role = parts[0];
  const token = parts[1];

  if (!ROLE_PAIRS[role] || !token || token.length < 8) {
    log(`rejecting bad path ${maskPath(req.url)} (role=${role} tokenLength=${token ? token.length : 0}, need role in [${ROLES.join('|')}] and token >= 8 chars)`);
    ws.close(1008, 'expected /agent|viewer|controlAgent|controlViewer/<token>');
    return;
  }

  const label = roomLabel(token);
  ws.logName = `${role}@${label}`;
  ws.joinedAt = Date.now();
  ws.msgsIn = 0;
  ws.bytesIn = 0;
  ws.msgsOut = 0;
  ws.pauses = 0;

  const peerRole = ROLE_PAIRS[role];
  const room = getRoom(token);

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
    const isStale = existing.readyState !== WebSocket.OPEN
      || (Date.now() - (existing.lastActivity || 0)) > STALE_CONNECTION_MS;
    if (!isStale) {
      log(`rejecting duplicate ${role} connection for room ${label} - existing connection still active (idle ${Date.now() - (existing.lastActivity || 0)}ms < ${STALE_CONNECTION_MS}ms)`);
      ws.close(4009, 'role already active');
      return;
    }
    log(`replacing stale ${role} connection in room ${label} (readyState=${existing.readyState}, idle ${Date.now() - (existing.lastActivity || 0)}ms)`);
    try { existing.close(); } catch { /* ignore */ }
  }
  room[role] = ws;
  startHeartbeat(ws);

  log(`${role} joined room ${label} (${ROLES.map((r) => `${r}=${!!room[r]}`).join(' ')}) origin=${short(req.headers.origin)} ip=${clientIp(req)}`);

  // Send anything that arrived for this role before it joined (e.g. the
  // agent's initial VNC handshake bytes sent before the viewer loaded).
  flushPending(room, role, ws);

  // Resolve the peer lazily on every message (not captured at connect time)
  // so it doesn't matter which side joins first, and a mid-session
  // reconnect on either side keeps working.
  ws.on('message', (data, isBinary) => {
    ws.lastActivity = Date.now();
    ws.msgsIn += 1;
    ws.bytesIn += data.length;
    if (ws.msgsIn === 1) log(`${ws.logName} first message: ${data.length} bytes ${isBinary ? 'binary' : 'text'} (${Date.now() - ws.joinedAt}ms after joining)`);
    const r = rooms.get(token);
    const peer = r?.[peerRole];
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(data, { binary: isBinary });
      peer.msgsOut = (peer.msgsOut || 0) + 1;
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
      if (peer.bufferedAmount > BACKPRESSURE_THRESHOLD_BYTES) {
        ws.pauses += 1;
        if (ws.pauses === 1 || ws.pauses % 100 === 0) log(`backpressure: pausing ${ws.logName} (peer ${peerRole} buffered ${peer.bufferedAmount} bytes, pause #${ws.pauses})`);
        ws.pause();
        const resumeWhenDrained = () => {
          if (peer.readyState !== WebSocket.OPEN || peer.bufferedAmount <= BACKPRESSURE_THRESHOLD_BYTES) {
            if (ws.readyState === WebSocket.OPEN) ws.resume();
          } else {
            setTimeout(resumeWhenDrained, 50);
          }
        };
        setTimeout(resumeWhenDrained, 50);
      }
    } else if (r) {
      // Peer hasn't joined yet (or reconnecting) - buffer instead of dropping.
      if (r.pending[peerRole].length === 0) log(`${ws.logName}: peer ${peerRole} not connected, buffering messages for it`);
      bufferForPeer(r, peerRole, data, isBinary);
    }
  });

  ws.on('close', (code, reasonBuf) => {
    log(`${ws.logName} closed code=${code} reason="${short(reasonBuf && reasonBuf.toString())}" lived=${Date.now() - ws.joinedAt}ms msgsIn=${ws.msgsIn} bytesIn=${ws.bytesIn} msgsOut=${ws.msgsOut} pauses=${ws.pauses}`);
    const r = rooms.get(token);
    if (!r) return;
    if (r[role] === ws) r[role] = null;
    cleanupIfEmpty(token, r);
  });

  ws.on('error', (err) => {
    // 'close' fires right after - cleanup happens there.
    log(`${ws.logName} socket error: ${err.code || ''} ${err.message}`);
  });
});

// ---- HTTP transport (no WebSocket) ------------------------------------------
// Why this exists: NetFree answers WebSocket upgrade requests to this host with
// "418 Blocked by NetFree" even though the relay accepts them (the relay logs
// "responding to ...: 101 Switching Protocols" for the very same requests). Plain
// HTTPS requests to the same host do pass. So a client can take part in a room
// using ordinary requests instead of an upgrade:
//
//   POST /rt/<role>/<token>/send            body = one message (raw bytes)
//        add ?t=1 to mark it as a text message (default: binary)
//   GET  /rt/<role>/<token>/recv?wait=20000 long-poll: returns as soon as a
//        message is waiting for this role, or after `wait` ms with an empty list
//        -> 200 {"m":[{"b":1,"d":"<base64>"}],"closed":false}
//   POST /rt/<role>/<token>/close           leave the room
//
// <role> and <token> are exactly the same as in /agent/<token> etc., and an
// HTTP client and a WebSocket client can be the two sides of the same room.
// The WebSocket path above is untouched.
const HTTP_PEER_IDLE_MS = 45000;          // no request at all for this long -> session ends
const MAX_HTTP_QUEUE_BYTES = 20 * 1024 * 1024;
const MAX_POST_BYTES = 1024 * 1024;
const MAX_POLL_WAIT_MS = 25000;
const POLL_MAX_BYTES = 2 * 1024 * 1024;   // per poll response, raw bytes

// Stands in for a WebSocket in room[role]: it has the few members the WS code
// touches on a *peer* (readyState, send, bufferedAmount, lastActivity, msgsOut, close).
class HttpPeer {
  constructor(token, role) {
    this.isHttp = true;
    this.token = token;
    this.role = role;
    this.readyState = WebSocket.OPEN;
    this.queue = [];
    this.queuedBytes = 0;
    this.waiter = null;
    this.lastActivity = Date.now();
    this.joinedAt = Date.now();
    this.msgsIn = 0;
    this.bytesIn = 0;
    this.msgsOut = 0;
    this.logName = `${role}(http)@${roomLabel(token)}`;
    this.timer = setInterval(() => {
      if (Date.now() - this.lastActivity > HTTP_PEER_IDLE_MS) this.close('idle');
    }, 5000);
  }

  get bufferedAmount() { return this.queuedBytes; }

  send(data, opts) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (this.queuedBytes + buf.length > MAX_HTTP_QUEUE_BYTES) {
      log(`${this.logName} queue overflow (${this.queuedBytes} bytes waiting) - ending session`);
      this.close('queue overflow');
      return;
    }
    this.queue.push({ b: opts && opts.binary ? 1 : 0, d: buf.toString('base64'), n: buf.length });
    this.queuedBytes += buf.length;
    this.wake();
  }

  wake() {
    if (!this.waiter) return;
    const w = this.waiter;
    this.waiter = null;
    w();
  }

  // close(reason): the session ended by itself (idle / overflow / client 'close').
  // close() with no argument is how the WebSocket code evicts a stale role holder;
  // in that case the caller is about to put its own socket in room[role], so leave
  // the room bookkeeping alone.
  close(reason) {
    if (this.readyState !== WebSocket.OPEN) return;
    this.readyState = WebSocket.CLOSED;
    clearInterval(this.timer);
    this.wake();
    log(`${this.logName} closed (${reason || 'replaced'}) lived=${Date.now() - this.joinedAt}ms msgsIn=${this.msgsIn} bytesIn=${this.bytesIn} msgsOut=${this.msgsOut}`);
    if (reason === undefined) return;
    const r = rooms.get(this.token);
    if (r && r[this.role] === this) { r[this.role] = null; cleanupIfEmpty(this.token, r); }
  }
}

// Returns the live HttpPeer for this role, creating it (and joining the room) if
// needed. Returns null if a different, still-active connection holds the role.
function getHttpPeer(role, token, req) {
  const room = getRoom(token);
  const existing = room[role];
  if (existing && existing.isHttp && existing.readyState === WebSocket.OPEN) return existing;
  if (existing) {
    const idle = Date.now() - (existing.lastActivity || 0);
    if (existing.readyState === WebSocket.OPEN && idle <= STALE_CONNECTION_MS) {
      log(`rejecting http ${role} for room ${roomLabel(token)} - existing connection still active (idle ${idle}ms)`);
      return null;
    }
    log(`replacing stale ${role} in room ${roomLabel(token)} with an http session (idle ${idle}ms)`);
    try { existing.close(); } catch { /* ignore */ }
  }
  const peer = new HttpPeer(token, role);
  room[role] = peer;
  log(`${role}(http) joined room ${roomLabel(token)} (${ROLES.map((r) => `${r}=${!!room[r]}`).join(' ')}) ip=${clientIp(req)} ua="${short(req.headers['user-agent'])}"`);
  flushPending(room, role, peer);
  return peer;
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

function pollRespond(peer, res) {
  const items = [];
  let bytes = 0;
  while (peer.queue.length && bytes < POLL_MAX_BYTES) {
    const it = peer.queue.shift();
    peer.queuedBytes -= it.n;
    bytes += it.n;
    items.push({ b: it.b, d: it.d });
  }
  sendJson(res, 200, { m: items, closed: peer.readyState !== WebSocket.OPEN });
}

function handleRt(req, res) {
  const url = new URL(req.url, 'http://relay.local');
  // req.path may or may not include the "/rt" prefix depending on how it was mounted;
  // parse from the full original URL so it never matters.
  const parts = new URL(req.originalUrl || req.url, 'http://relay.local').pathname.split('/').filter(Boolean);
  const [, role, token, action] = parts; // ['rt', role, token, action]
  if (!ROLE_PAIRS[role] || !token || token.length < 8 || !['send', 'recv', 'close'].includes(action)) {
    log(`http rt: bad path (role=${role} tokenLength=${token ? token.length : 0} action=${action})`);
    return sendJson(res, 400, { error: 'expected /rt/<role>/<token>/send|recv|close' });
  }
  const peerRole = ROLE_PAIRS[role];

  if (action === 'recv') {
    if (req.method !== 'GET') return sendJson(res, 405, { error: 'use GET' });
    const peer = getHttpPeer(role, token, req);
    if (!peer) return sendJson(res, 409, { error: 'role already active' });
    peer.lastActivity = Date.now();
    peer.wake(); // release an older poll that is still waiting, if any
    const waitMs = Math.max(0, Math.min(Number(url.searchParams.get('wait')) || 0, MAX_POLL_WAIT_MS));
    if (peer.queue.length || peer.readyState !== WebSocket.OPEN || waitMs === 0) return pollRespond(peer, res);
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (peer.waiter === finish) peer.waiter = null;
      peer.lastActivity = Date.now();
      pollRespond(peer, res);
    };
    const timer = setTimeout(finish, waitMs);
    peer.waiter = finish;
    res.on('close', () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (peer.waiter === finish) peer.waiter = null;
    });
    return undefined;
  }

  if (req.method !== 'POST') return sendJson(res, 405, { error: 'use POST' });

  if (action === 'close') {
    const r = rooms.get(token);
    const cur = r && r[role];
    if (cur && cur.isHttp) cur.close('client close');
    return sendJson(res, 200, { ok: true });
  }

  // action === 'send'
  const isBinary = url.searchParams.get('t') !== '1';
  const chunks = [];
  let size = 0;
  let tooBig = false;
  req.on('data', (c) => {
    size += c.length;
    if (size > MAX_POST_BYTES) { tooBig = true; return; }
    chunks.push(c);
  });
  req.on('end', () => {
    if (tooBig) return sendJson(res, 413, { error: `message over ${MAX_POST_BYTES} bytes` });
    const sender = getHttpPeer(role, token, req);
    if (!sender) return sendJson(res, 409, { error: 'role already active' });
    sender.lastActivity = Date.now();
    const data = Buffer.concat(chunks);
    sender.msgsIn += 1;
    sender.bytesIn += data.length;
    if (sender.msgsIn === 1) log(`${sender.logName} first message: ${data.length} bytes ${isBinary ? 'binary' : 'text'} (${Date.now() - sender.joinedAt}ms after joining)`);

    const r = rooms.get(token);
    const other = r && r[peerRole];
    if (other && other.readyState === WebSocket.OPEN) {
      other.send(data, { binary: isBinary });
      other.msgsOut = (other.msgsOut || 0) + 1;
      // Backpressure for an HTTP sender: hold the response until the receiver
      // has drained (the sender's next POST then naturally waits too).
      const t0 = Date.now();
      const waitDrain = () => {
        if (other.readyState !== WebSocket.OPEN || other.bufferedAmount <= BACKPRESSURE_THRESHOLD_BYTES || Date.now() - t0 > 5000) {
          return sendJson(res, 200, { ok: true, delivered: true });
        }
        return setTimeout(waitDrain, 50);
      };
      return waitDrain();
    }
    if (r) {
      if (r.pending[peerRole].length === 0) log(`${sender.logName}: peer ${peerRole} not connected, buffering messages for it`);
      bufferForPeer(r, peerRole, data, isBinary);
    }
    return sendJson(res, 200, { ok: true, delivered: false });
  });
  return undefined;
}

// Fires only when the relay ACCEPTS a handshake, right before it writes the
// "101 Switching Protocols" response. If this line appears for an attempt
// but the client reports a different status (e.g. 418), something between
// the relay and the client replaced the response.
wss.on('headers', (headers, req) => {
  log(`responding to ${maskPath(req.url)}: ${headers.filter((h) => !/^sec-websocket-accept/i.test(h)).join(' | ')}`);
});

wss.on('error', (err) => log(`wss error: ${err.message}`));

// Restarts / crashes are the other thing worth ruling out on Render's free tier.
process.on('SIGTERM', () => { log(`SIGTERM received (Render is stopping/redeploying this instance), uptime=${Math.round(process.uptime())}s rooms=${rooms.size}`); process.exit(0); });
process.on('uncaughtException', (err) => { log(`uncaughtException: ${err.stack || err}`); process.exit(1); });
process.on('unhandledRejection', (err) => log(`unhandledRejection: ${err && err.stack || err}`));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => log(`listening on ${PORT} (node ${process.version}, pid ${process.pid})`));
