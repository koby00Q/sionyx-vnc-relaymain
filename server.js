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
const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');

const app = express();
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
  }
  console.log(`[relay] flushed ${queue.length} buffered message(s) to newly-joined ${role}`);
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

function startHeartbeat(ws) {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
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
    ws.close(1008, 'expected /agent|viewer|controlAgent|controlViewer/<token>');
    return;
  }

  const peerRole = ROLE_PAIRS[role];
  const room = getRoom(token);

  // A new connection for a role replaces any stale one (e.g. a page reload
  // or the kiosk's WS reconnecting after a network blip).
  if (room[role]) {
    try { room[role].close(); } catch { /* ignore */ }
  }
  room[role] = ws;
  startHeartbeat(ws);

  console.log(`[relay] ${role} joined room ${token.slice(0, 6)}... (${ROLES.map((r) => `${r}=${!!room[r]}`).join(' ')})`);

  // Send anything that arrived for this role before it joined (e.g. the
  // agent's initial VNC handshake bytes sent before the viewer loaded).
  flushPending(room, role, ws);

  // Resolve the peer lazily on every message (not captured at connect time)
  // so it doesn't matter which side joins first, and a mid-session
  // reconnect on either side keeps working.
  ws.on('message', (data, isBinary) => {
    const r = rooms.get(token);
    const peer = r?.[peerRole];
    if (peer && peer.readyState === WebSocket.OPEN) {
      peer.send(data, { binary: isBinary });
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
      bufferForPeer(r, peerRole, data, isBinary);
    }
  });

  ws.on('close', () => {
    const r = rooms.get(token);
    if (!r) return;
    if (r[role] === ws) r[role] = null;
    cleanupIfEmpty(token, r);
  });

  ws.on('error', () => { /* 'close' fires right after - cleanup happens there */ });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`[relay] listening on ${PORT}`));
