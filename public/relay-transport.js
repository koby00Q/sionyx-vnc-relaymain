// Browser-side relay transport with automatic fallback.
//
// connectRelayChannel(role, token) tries a WebSocket first and, if it can't
// be established or doesn't provably carry data (NetFree returns "418 Blocked
// by NetFree" for many wss upgrades, or opens the socket but swallows the
// traffic), falls back to plain HTTPS long-polling (/rt/<role>/<token>/...).
// Either way the caller gets the same RelayChannel object, which has the
// exact shape noVNC's Websock.attach() expects from a raw channel.
//
// The WebSocket is only trusted after a probe round trip: we send
// "__relay_probe__" and the server must answer "__relay_probe_ack__". That
// proves the connection works in both directions - a plain "open" event does
// not (a "ghost" connection can open on the server while the browser sees a
// block page).

const PROBE = '__relay_probe__';
const PROBE_ACK = '__relay_probe_ack__';
const WS_CONNECT_TIMEOUT_MS = 6000;
const PROBE_TIMEOUT_MS = 3000;
const HTTP_WAIT_MS = 20000;
const HTTP_RECV_TIMEOUT_MS = 35000;
const HTTP_MAX_FAILURES = 6;


// ---- optional stream tap (vnc.html?debug=1) --------------------------------
// Logs a running byte count + CRC32 of the VNC byte stream at fixed offsets
// (every 64 KiB for the first MiB, then every MiB) - the same offsets the
// server ([tap] lines in the Render log) and the kiosk test script print. The
// first offset where two hops disagree on the crc is where the stream broke.
const DEBUG = new URLSearchParams(location.search).get('debug') === '1';
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function tapNext(off) {
  return off < 1048576 ? (Math.floor(off / 8192) + 1) * 8192 : (Math.floor(off / 1048576) + 1) * 1048576;
}
class StreamTap {
  constructor(label) { this.label = label; this.total = 0; this.c = 0xFFFFFFFF; }
  feed(u8) {
    let pos = 0;
    while (pos < u8.length) {
      const next = tapNext(this.total);
      const end = pos + Math.min(u8.length - pos, next - this.total);
      let c = this.c;
      for (let i = pos; i < end; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
      this.c = c;
      this.total += end - pos; pos = end;
      if (this.total === next) {
        console.log(`[tap] ${new Date().toISOString()} ${this.label} @${this.total} crc=${((this.c ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0')}`);
      }
    }
  }
}

// readyState values match WebSocket.* (CONNECTING/OPEN/CLOSING/CLOSED).
const CONNECTING = 0, OPEN = 1, CLOSED = 3;

// Channel remembered per page load: once WebSocket has proven unusable, don't
// waste ~9s re-probing it for the control channel.
let wsKnownBad = false;

// One class (no subclasses) on purpose: noVNC checks that the required
// properties exist on the object or its immediate prototype.
export class RelayChannel {
  constructor(backend, transportName, role) {
    this.binaryType = 'arraybuffer';
    // Only the main VNC stream (role 'viewer') is tapped, and only in debug mode.
    this._tapIn = DEBUG && role === 'viewer' ? new StreamTap('browser viewer.in (agent->browser)') : null;
    this._rec = DEBUG && role === 'viewer' ? [] : null; // first 256 KiB received, for the byte-exact diff on close
    this._recLen = 0;
    this._tapOut = DEBUG && role === 'viewer' ? new StreamTap('browser viewer.sent (browser->agent)') : null;
    this.protocol = '';
    this.onopen = null;
    this.onclose = null;
    this.onerror = null;
    this.transport = transportName; // 'ws' | 'http' (informational)
    this._backend = backend;
    this._state = CONNECTING;
    this._onmessage = null;
    // Messages that arrive before the consumer sets onmessage are held, not
    // dropped: noVNC attaches to its channel asynchronously, and the server
    // flushes the agent's "RFB 003.008" greeting the moment we're active.
    this._rq = [];
  }
  get readyState() { return this._state; }
  get onmessage() { return this._onmessage; }
  set onmessage(fn) {
    this._onmessage = fn;
    if (fn && this._rq.length) setTimeout(() => this._drain(), 0);
  }
  send(data) {
    if (this._tapOut && typeof data !== 'string') this._tapOut.feed(new Uint8Array(data.buffer || data, data.byteOffset || 0, data.byteLength));
    this._backend.send(data);
  }
  close() { this._backend.close(); }

  _deliver(data) {
    if (this._tapIn && typeof data !== 'string') this._tapIn.feed(new Uint8Array(data));
    if (this._rec && typeof data !== 'string' && this._recLen < 262144) {
      const part = new Uint8Array(data).slice(0, 262144 - this._recLen);
      this._rec.push(part); this._recLen += part.length;
    }
    this._rq.push(data); this._drain();
  }
  _drain() {
    while (this._onmessage && this._rq.length) this._onmessage({ data: this._rq.shift() });
  }
  async _compareWithServer() {
    const lines = [];
    const say = (t) => { lines.push(t); };
    try {
      const token = new URLSearchParams(location.search).get('token');
      const mine = new Uint8Array(this._recLen);
      let o = 0; for (const p of this._rec) { mine.set(p, o); o += p.length; }
      const get = async (k) => {
        const r = await fetch(`/dump/${encodeURIComponent(token)}/${k}`, { cache: 'no-store' });
        if (!r.ok) return null;
        return { bytes: new Uint8Array(await r.arrayBuffer()), total: r.headers.get('X-Total') };
      };
      const srvOut = await get('agent.out');
      const srvIn = await get('agent.in');
      const hex = (u, i) => Array.from(u.slice(Math.max(0, i - 6), i + 10)).map((b) => b.toString(16).padStart(2, '0')).join(' ');
      const firstDiff = (a, b) => { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i; return a.length === b.length ? -1 : n; };
      say(`browser received: ${this._recLen} bytes (first 256KiB kept)`);
      if (!srvOut) say('relay has no agent.out dump for this token');
      else {
        say(`relay delivered to viewer (agent.out): total=${srvOut.total}, kept=${srvOut.bytes.length}`);
        const m = Math.min(mine.length, srvOut.bytes.length);
        const d = firstDiff(mine.slice(0, m), srvOut.bytes.slice(0, m));
        if (d === -1) say(`browser vs relay-out: IDENTICAL over first ${m} bytes`);
        else say(`browser vs relay-out: FIRST DIFF at offset ${d}\n   browser: ${hex(mine, d)}\n   relay  : ${hex(srvOut.bytes, d)}`);
      }
      if (srvIn && srvOut) {
        const m = Math.min(srvIn.bytes.length, srvOut.bytes.length);
        const d = firstDiff(srvIn.bytes.slice(0, m), srvOut.bytes.slice(0, m));
        say(`relay agent.in=${srvIn.total} bytes; in vs out: ${d === -1 ? 'IDENTICAL over ' + m + ' bytes' : 'FIRST DIFF at ' + d}`);
      }
    } catch (e) { say('compare error: ' + e.message); }
    const text = 'RELAY BYTE COMPARE\n' + lines.join('\n');
    console.log(text);
    const div = document.createElement('pre');
    div.textContent = text;
    div.style.cssText = 'position:fixed;left:8px;right:8px;bottom:8px;z-index:99999;background:#000c;color:#7dff9b;padding:10px;font:14px Consolas,monospace;white-space:pre-wrap;max-height:50vh;overflow:auto;border:1px solid #7dff9b';
    document.body.appendChild(div);
  }
  _setOpen() {
    this._state = OPEN;
    if (this.onopen) this.onopen({ type: 'open' });
  }
  _setClosed(clean = true) {
    if (this._state === CLOSED) return;
    this._state = CLOSED;
    if (this._rec) setTimeout(() => this._compareWithServer(), 400);
    if (this.onclose) this.onclose({ type: 'close', wasClean: clean, code: clean ? 1000 : 1006, reason: '' });
  }
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- WebSocket path -------------------------------------------------------

function tryWebSocket(role, token) {
  return new Promise((resolve) => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${location.host}/${role}/${encodeURIComponent(token)}?probe=1`;
    let ws;
    let settled = false;
    const timers = [];
    const fail = (why) => {
      if (settled) return;
      settled = true;
      timers.forEach(clearTimeout);
      console.warn(`[relay] WebSocket ${role} unusable (${why}) - falling back to HTTP`);
      try { ws.close(); } catch { /* ignore */ }
      resolve(null);
    };
    try { ws = new WebSocket(url); } catch (e) { fail('constructor threw'); return; }
    ws.binaryType = 'arraybuffer';

    const connectTimer = setTimeout(() => fail('connect timeout'), WS_CONNECT_TIMEOUT_MS);
    timers.push(connectTimer);
    ws.onerror = () => fail('error');
    ws.onclose = () => fail('closed before probe');
    ws.onopen = () => {
      // Connected. Now prove data flows both ways.
      clearTimeout(connectTimer);
      timers.push(setTimeout(() => fail('probe timeout (traffic swallowed?)'), PROBE_TIMEOUT_MS));
      try { ws.send(PROBE); } catch { fail('send threw'); }
    };

    const channel = new RelayChannel({
      send: (d) => ws.send(d),
      close: () => { try { ws.close(); } catch { /* ignore */ } },
    }, 'ws', role);

    ws.onmessage = (e) => {
      if (!settled) {
        if (e.data === PROBE_ACK) {
          settled = true;
          timers.forEach(clearTimeout);
          ws.onclose = () => channel._setClosed(true);
          ws.onerror = () => { if (channel.onerror) channel.onerror({ type: 'error' }); };
          ws.onmessage = (m) => channel._deliver(m.data);
          channel._setOpen();
          resolve(channel);
        }
        return; // anything else before the ack is not ours
      }
    };
  });
}

// ---- HTTP long-poll path --------------------------------------------------

async function httpChannel(role, token) {
  const base = `${location.origin}/rt/${role}/${encodeURIComponent(token)}`;
  let closed = false;
  let recvAbort = null;
  let failures = 0;

  // Cheap reachability check so we fail here (and can report it) instead of
  // handing back a channel that silently does nothing.
  const check = await fetch(`${base}/recv?wait=0`, { cache: 'no-store' });
  if (!check.ok) throw new Error(`HTTP relay check failed: ${check.status}`);
  const first = await check.json();

  // Outgoing: chunks are queued and sent strictly one POST at a time, in
  // order. Consecutive binary chunks are merged into one POST (one network
  // round trip per burst instead of per RFB message) - safe for VNC because
  // it's a byte stream. Text (control JSON) is never merged: boundaries matter.
  const outq = [];
  let sending = false;
  async function pumpSend() {
    if (sending) return;
    sending = true;
    try {
      while (outq.length && !closed) {
        const head = outq[0];
        let body, isText = false;
        if (typeof head === 'string') {
          body = outq.shift(); isText = true;
        } else {
          const parts = [];
          while (outq.length && typeof outq[0] !== 'string') parts.push(outq.shift());
          const total = parts.reduce((n, p) => n + p.length, 0);
          body = new Uint8Array(total);
          let off = 0;
          for (const p of parts) { body.set(p, off); off += p.length; }
        }
        let attempt = 0;
        for (;;) {
          try {
            const r = await fetch(`${base}/send${isText ? '?t=1' : ''}`, {
              method: 'POST',
              headers: { 'Content-Type': isText ? 'text/plain' : 'application/octet-stream' },
              body,
              cache: 'no-store',
            });
            if (!r.ok) throw new Error(`send ${r.status}`);
            break;
          } catch (e) {
            if (closed) return;
            if (++attempt >= 4) { fatal(`send failed: ${e.message}`); return; }
            await new Promise((res) => setTimeout(res, 300 * attempt));
          }
        }
      }
    } finally {
      sending = false;
      if (outq.length && !closed) pumpSend();
    }
  }

  const backend = {
    send(data) {
      if (closed) return;
      // Copy: noVNC hands us a view over a buffer it reuses immediately.
      outq.push(typeof data === 'string' ? data : new Uint8Array(data).slice());
      pumpSend();
    },
    close() {
      if (closed) return;
      closed = true;
      if (recvAbort) recvAbort.abort();
      // Best effort: tell the other side we're gone.
      fetch(`${base}/close`, { method: 'POST', keepalive: true }).catch(() => {});
      channel._setClosed(true);
    },
  };
  const channel = new RelayChannel(backend, 'http', role);

  function fatal(msg) {
    if (closed) return;
    console.warn(`[relay] HTTP transport ${role}: ${msg}`);
    closed = true;
    if (recvAbort) recvAbort.abort();
    if (channel.onerror) channel.onerror({ type: 'error' });
    channel._setClosed(false);
  }

  function handle(payload) {
    for (const m of payload.messages || []) {
      const bytes = b64ToBytes(m.data);
      channel._deliver(m.binary ? bytes.buffer : new TextDecoder().decode(bytes));
    }
  }

  // Incoming: strictly one long-poll in flight, re-issued immediately.
  (async () => {
    handle(first);
    while (!closed) {
      recvAbort = new AbortController();
      const timer = setTimeout(() => recvAbort.abort(), HTTP_RECV_TIMEOUT_MS);
      try {
        const r = await fetch(`${base}/recv?wait=${HTTP_WAIT_MS}`, { signal: recvAbort.signal, cache: 'no-store' });
        if (!r.ok) throw new Error(`recv ${r.status}`);
        const payload = await r.json();
        failures = 0;
        handle(payload);
        if (payload.closed) { closed = true; channel._setClosed(true); return; }
      } catch (e) {
        if (closed) return;
        if (++failures >= HTTP_MAX_FAILURES) { fatal(`recv failed repeatedly: ${e.message}`); return; }
        await new Promise((res) => setTimeout(res, Math.min(2000, 300 * failures)));
      } finally {
        clearTimeout(timer);
      }
    }
  })();

  channel._setOpen();
  return channel;
}

// ---- public entry point ---------------------------------------------------

/**
 * @param {'viewer'|'controlViewer'} role
 * @param {string} token
 * @param {{transport?: 'auto'|'ws'|'http'}} [opts]  ?transport=http|ws forces one
 */
export async function connectRelayChannel(role, token, opts = {}) {
  const mode = opts.transport || 'auto';
  if (mode !== 'http' && !wsKnownBad) {
    const ws = await tryWebSocket(role, token);
    if (ws) return ws;
    if (mode === 'ws') throw new Error('WebSocket unavailable and transport=ws was forced');
    wsKnownBad = true;
  } else if (mode === 'ws') {
    throw new Error('WebSocket previously failed on this page');
  }
  return httpChannel(role, token);
}
