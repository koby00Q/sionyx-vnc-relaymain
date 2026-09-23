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
    ip: req.ip,
    ips: req.ips,
    headers: req.headers,
  });
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

function getRoom(token) {
  let room = rooms.get(token);
  if (!room) {
    room = { pending: {}, httpSeen: {} };
    for (const role of ROLES) { room[role] = null; room.pending[role] = []; }
    rooms.set(token, room);
  }
  return room;
}

function cleanupIfEmpty(token, room) {
  const anyWs = ROLES.some((role) => !!room[role]);
  const anyHttp = ROLES.some((role) => {
    const seen = room.httpSeen[role];
    return seen && (Date.now() - seen) < HTTP_ACTIVE_WINDOW_MS;
  });
  if (!anyWs && !anyHttp) rooms.delete(token);
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
  if (peer && peer.readyState === WebSocket.OPEN) {
    peer.send(data, { binary: isBinary });
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

  console.log(`[relay] ${ts()} responding to upgrade with 101 for ${role} in room ${label}`);

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
  startHeartbeat(ws);

  console.log(`[relay] ${ts()} ${role} joined room ${label} (${ROLES.map((r) => `${r}=${!!room[r]}`).join(' ')})`);

  // Send anything that arrived for this role before it joined (e.g. the
  // agent's initial VNC handshake bytes sent before the viewer loaded).
  flushPending(room, role, ws);

  ws.on('message', (data, isBinary) => {
    ws.lastActivity = Date.now();
    ws._msgsIn += 1;
    const r = rooms.get(token);
    if (!r) return;
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
    if (r[role] === ws) r[role] = null;
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

app.post('/rt/:role/:token/send', express.raw({ type: '*/*', limit: '10mb' }), (req, res) => {
  const parsed = parseRoleToken(req, res);
  if (!parsed) return;
  const { role, token } = parsed;
  const room = getRoom(token);
  const label = roomLabel(token);
  const isText = req.query.t === '1';
  const body = req.body && req.body.length ? req.body : Buffer.alloc(0);

  room.httpSeen[role] = Date.now();
  console.log(`[relay] ${ts()} http-send ${role} room ${label} bytes=${body.length} text=${isText}`);

  const outcome = routeMessage(room, role, body, !isText);
  res.json({ ok: true, outcome });
});

app.get('/rt/:role/:token/recv', async (req, res) => {
  const parsed = parseRoleToken(req, res);
  if (!parsed) return;
  const { role, token } = parsed;
  const room = getRoom(token);
  const label = roomLabel(token);

  const wasActive = room.httpSeen[role] && (Date.now() - room.httpSeen[role]) < HTTP_ACTIVE_WINDOW_MS;
  room.httpSeen[role] = Date.now();
  if (!wasActive) {
    console.log(`[relay] ${ts()} ${role} joined room ${label} over HTTP`);
  }

  const requestedWait = parseInt(req.query.wait, 10);
  const waitMs = Number.isFinite(requestedWait) ? Math.min(Math.max(requestedWait, 0), 25000) : 20000;

  const deadline = Date.now() + waitMs;
  let messages = [];
  while (Date.now() < deadline) {
    const queue = room.pending[role];
    if (queue.length) {
      messages = queue.slice();
      queue.length = 0;
      break;
    }
    await sleep(150);
    // The room may have been garbage-collected (cleanupIfEmpty) if this poll
    // has been running a very long time with everyone else gone - bail out
    // rather than trust a closed-over reference to a room that no longer
    // exists in the map.
    if (!rooms.has(token)) break;
  }

  if (messages.length) {
    console.log(`[relay] ${ts()} http-recv ${role} room ${label} delivering=${messages.length}`);
  }

  res.json({
    messages: messages.map(({ data, isBinary }) => ({
      data: Buffer.from(data).toString('base64'),
      binary: isBinary,
    })),
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
    cleanupIfEmpty(token, room);
  }
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`[relay] ${ts()} listening on ${PORT} (node ${process.version}, pid ${process.pid})`));
