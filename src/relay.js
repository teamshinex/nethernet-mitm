// relay.js — nethernet-mitm relay/rendezvous server
//
// Role: a public WebSocket + HTTP server. Hosts register an id (+secret) on
// /host, joiners connect on /join, the relay forwards raw bytes between the
// two WebSockets. It only needs a single forwarded TCP port (default 7000).

import { parseArgs } from "node:util";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { EventEmitter } from "node:events";
import { WebSocket, WebSocketServer } from "ws";

const ID_RE = /^[a-z0-9][a-z0-9-]{2,31}$/;
const SECRET_HASH_RE = /^[0-9a-f]{64}$/;
const MAX_BUFFERED = 16777216; // 16 MiB; back-pressure limit per consumer

function normalizeId(id) {
  return String(id ?? "").trim().toLowerCase();
}

function sha256hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function sendJson(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function str(v, max = 64) {
  return typeof v === "string" ? v.slice(0, max) : undefined;
}

function int(v) {
  return Number.isFinite(v) ? Math.trunc(v) : undefined;
}

// Keep only the known, length-limited fields of a host's advertised info.
function cleanInfo(info) {
  if (!info || typeof info !== "object") return null;
  const out = {
    name: str(info.name),
    protocol: int(info.protocol),
    version: str(info.version, 32),
    level: str(info.level),
    players: int(info.players),
    maxPlayers: int(info.maxPlayers),
    gameType: int(info.gameType),
  };
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined));
}

export class RelayServer extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.port = opts.port ?? 7000;
    this.host = opts.host ?? "0.0.0.0";
    this.idsFile = opts.idsFile ?? "./relay-ids.json";
    this.token = opts.token ?? null;
    this.tls = opts.tls ?? null;
    this.maxHosts = opts.maxHosts ?? 200;
    this.maxIds = opts.maxIds ?? 2000;
    this.maxSessions = opts.maxSessions ?? 500;
    this.maxSessionsPerHost = opts.maxSessionsPerHost ?? 16;
    this.maxConnections = opts.maxConnections ?? 2000;
    this.handshakeMs = opts.handshakeMs ?? 10000;
    this.acceptMs = opts.acceptMs ?? 20000;
    this.heartbeatMs = opts.heartbeatMs ?? 20000;
    this.idTtlDays = opts.idTtlDays ?? 90;
    this.log = opts.log ?? console.log;

    this.ids = new Map();      // id -> { salt, hash, created, lastSeen }
    this.hosts = new Map();    // id -> host record (online)
    this.pending = new Map();  // sid -> session (waiting/setup)
    this.live = new Set();     // live sessions
    this.failures = new Map(); // ip -> { count, first, blockedUntil }
    this.startedAt = Date.now();
    this.server = null;
    this.wss = null;
    this.timer = null;
  }

  // ---- persisted host ids ------------------------------------------------

  #loadIds() {
    if (!this.idsFile) return;
    try {
      const raw = fs.readFileSync(this.idsFile, "utf8");
      const obj = JSON.parse(raw);
      const cutoff = Date.now() - this.idTtlDays * 86400000;
      for (const [id, rec] of Object.entries(obj)) {
        const seen = rec.lastSeen ?? rec.created ?? 0;
        if (seen >= cutoff) this.ids.set(id, rec);
      }
    } catch (e) {
      if (e.code !== "ENOENT") this.log(`[relay] could not read ${this.idsFile}: ${e.message}`);
    }
  }

  #saveIds() {
    if (!this.idsFile) return;
    try {
      const tmp = `${this.idsFile}.${process.pid}.tmp`;
      const dir = path.dirname(path.resolve(this.idsFile));
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.ids), null, 2));
      fs.renameSync(tmp, this.idsFile);
    } catch (e) {
      this.log(`[relay] could not save ${this.idsFile}: ${e.message}`);
    }
  }

  // ---- secret / id auth --------------------------------------------------

  #hash(salt, secret) {
    return sha256hex(`${salt}:${secret}`);
  }

  #secretOk(rec, secret) {
    const a = Buffer.from(this.#hash(rec.salt, secret));
    const b = Buffer.from(rec.hash);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  // ---- per-ip failure throttle ------------------------------------------

  #blocked(ip) {
    const rec = this.failures.get(ip);
    return !!rec && rec.blockedUntil > Date.now();
  }

  #fail(ip) {
    const now = Date.now();
    let rec = this.failures.get(ip);
    if (!rec || now - rec.first > 60000) rec = { count: 0, first: now, blockedUntil: 0 };
    rec.count += 1;
    if (rec.count >= 10) {
      rec.blockedUntil = now + 60000;
      this.log(`[relay] ${ip}: too many failed attempts, blocked for 60 s`);
    }
    this.failures.set(ip, rec);
    if (this.failures.size > 5000) {
      for (const [k, v] of this.failures) {
        if (now - v.first > 60000 && v.blockedUntil < now) this.failures.delete(k);
      }
    }
  }

  // ---- HTTP (health + host lookup) --------------------------------------

  #http(req, res) {
    const json = (code, obj) => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    const url = new URL(req.url, "http://x");
    if (req.method !== "GET") return json(405, { error: "method not allowed" });

    if (url.pathname === "/health") {
      return json(200, {
        ok: true,
        hosts: this.hosts.size,
        sessions: this.live.size,
        pending: this.pending.size,
        uptimeSec: Math.round((Date.now() - this.startedAt) / 1000),
      });
    }

    const m = /^\/api\/hosts\/([^/]+)$/.exec(url.pathname);
    if (m) {
      if (this.#blocked(req.socket.remoteAddress)) return json(429, { error: "too many requests" });
      const id = normalizeId(decodeURIComponent(m[1]));
      const known = this.ids.has(id);
      const host = this.hosts.get(id);
      if (!known) {
        this.#fail(req.socket.remoteAddress);
        return json(404, { id, online: false, error: "unknown id" });
      }
      return json(200, {
        id,
        online: !!host,
        info: host?.info ?? null,
        sessions: host?.sessions.size ?? 0,
        maxSessions: host?.maxSessions ?? 0,
        passwordRequired: !!host?.joinKey,
      });
    }

    return json(404, { error: "not found" });
  }

  // ---- WebSocket upgrade / connection -----------------------------------

  #upgrade(req, socket, head) {
    const refuse = (statusLine) => {
      try {
        socket.write(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\n\r\n`);
      } catch {}
      socket.destroy();
    };
    const url = new URL(req.url, "http://x");
    const pathname = url.pathname;
    const ip = req.socket.remoteAddress;

    if (!["/host", "/accept", "/join"].includes(pathname)) return refuse("404 Not Found");
    if (this.#blocked(ip)) return refuse("429 Too Many Requests");
    if (this.wss.clients.size >= this.maxConnections) return refuse("503 Service Unavailable");

    this.wss.handleUpgrade(req, socket, head, (ws) => this.#onConnection(ws, pathname, ip));
  }

  #onConnection(ws, pathname, ip) {
    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });
    ws.on("error", () => {});

    const timer = setTimeout(() => ws.close(1008, "handshake timeout"), this.handshakeMs);

    ws.once("message", (data, isBinary) => {
      clearTimeout(timer);
      let msg;
      try {
        if (isBinary) throw new Error("binary");
        msg = JSON.parse(data.toString());
      } catch {
        return this.#reject(ws, ip, "protocol", "first message must be JSON", false);
      }
      if (!msg || typeof msg !== "object") {
        return this.#reject(ws, ip, "protocol", "bad message", false);
      }
      if (pathname === "/host") this.#onHost(ws, ip, msg);
      else if (pathname === "/accept") this.#onAccept(ws, ip, msg);
      else this.#onJoin(ws, ip, msg);
    });
    ws.once("close", () => clearTimeout(timer));
  }

  #reject(ws, ip, code, message, countFail = true) {
    if (countFail) this.#fail(ip);
    sendJson(ws, { t: "error", code, message });
    setTimeout(() => ws.close(1008, code), 50);
  }

  #heartbeat() {
    for (const ws of this.wss.clients) {
      if (!ws.isAlive) { ws.terminate(); continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch {}
    }
  }

  // ---- /host : a host registers / comes online ---------------------------

  #onHost(ws, ip, msg) {
    const id = normalizeId(msg.id);
    if (msg.t !== "register" || !ID_RE.test(id)) {
      return this.#reject(ws, ip, "bad-id", 'id must be 3-32 chars of a-z, 0-9 and "-"');
    }
    if (this.token && msg.token !== this.token) {
      return this.#reject(ws, ip, "bad-token", "this relay requires a host token");
    }
    if (typeof msg.secret !== "string" || msg.secret.length < 8 || msg.secret.length > 128) {
      return this.#reject(ws, ip, "bad-secret", "secret must be 8-128 characters");
    }

    let rec = this.ids.get(id);
    if (rec) {
      if (!this.#secretOk(rec, msg.secret)) {
        return this.#reject(ws, ip, "id-taken", `id "${id}" belongs to someone else (wrong secret)`);
      }
    } else {
      if (this.ids.size >= this.maxIds) {
        return this.#reject(ws, ip, "relay-full", "too many registered ids", false);
      }
      const salt = crypto.randomBytes(8).toString("hex");
      rec = { salt, hash: this.#hash(salt, msg.secret), created: Date.now(), lastSeen: Date.now() };
      this.ids.set(id, rec);
      this.log(`[relay] new id "${id}" registered`);
    }
    rec.lastSeen = Date.now();
    this.#saveIds();

    const prev = this.hosts.get(id);
    if (!prev && this.hosts.size >= this.maxHosts) {
      return this.#reject(ws, ip, "relay-full", "too many hosts online", false);
    }
    if (prev) {
      this.hosts.delete(id);
      try { prev.ws.close(4000, "replaced by a newer connection"); } catch {}
    }

    const maxSessions = Math.max(1, Math.min(int(msg.maxSessions) ?? 8, this.maxSessionsPerHost));
    const host = {
      id,
      ws,
      since: Date.now(),
      ip,
      sessions: new Set(),
      info: cleanInfo(msg.info),
      joinKey: (typeof msg.joinKey === "string" && SECRET_HASH_RE.test(msg.joinKey)) ? msg.joinKey : null,
      maxSessions,
    };
    this.hosts.set(id, host);
    this.log(`[relay] host "${id}" online from ${ip} (max ${host.maxSessions} players${host.joinKey ? ", password" : ""})`);

    sendJson(ws, { t: "registered", id, maxSessions: host.maxSessions });

    ws.on("message", (data, isBinary) => {
      if (isBinary) return;
      let m;
      try { m = JSON.parse(data.toString()); } catch { return; }
      if (m?.t === "info") host.info = cleanInfo(m.info) ?? host.info;
    });
    ws.once("close", () => {
      if (this.hosts.get(id) === host) {
        this.hosts.delete(id);
        this.log(`[relay] host "${id}" offline`);
        for (const s of Array.from(this.pending.values())) {
          if (s.host !== host) continue;
          if (s.state !== "waiting") continue;
          this.#end(s, "host-offline");
        }
      }
    });
  }

  // ---- /accept : host accepts a pending joiner ---------------------------

  #onAccept(ws, ip, msg) {
    const id = normalizeId(msg.id);
    const rec = this.ids.get(id);
    if (msg.t !== "accept" || !rec || typeof msg.secret !== "string" || !this.#secretOk(rec, msg.secret)) {
      return this.#reject(ws, ip, "id-taken", "bad id or secret");
    }
    const sid = String(msg.sid);
    const session = this.pending.get(sid);
    if (!session || session.host.id !== id || session.state !== "waiting") {
      return this.#reject(ws, ip, "no-such-session", "unknown or expired session", false);
    }

    session.state = "setup";
    session.hostWs = ws;
    clearTimeout(session.timer);
    session.timer = setTimeout(() => this.#end(session, "host-timeout"), this.acceptMs);
    sendJson(ws, { t: "ok" });

    ws.on("message", (data, isBinary) => {
      if (session.state === "live") {
        return this.#forward(session, ws, session.joinWs, data, isBinary, "down");
      }
      if (isBinary || session.state !== "setup") return;
      let m;
      try { m = JSON.parse(data.toString()); } catch { return; }
      if (m?.t === "ready") {
        clearTimeout(session.timer);
        session.state = "live";
        session.liveSince = Date.now();
        this.live.add(session);
        session.host.sessions.add(session);
        sendJson(session.joinWs, { t: "ready" });
        this.log(`[relay] session ${session.sid} live: ${session.ip} -> "${id}" (${session.host.sessions.size} on this host)`);
      } else if (m?.t === "fail") {
        sendJson(session.joinWs, {
          t: "error",
          code: str(m.code, 32) ?? "host-unreachable",
          message: str(m.message, 200),
        });
        this.#end(session, `host reported failure: ${m.code ?? "?"}`);
      }
    });
    ws.once("close", () => this.#end(session, "host side closed"));
  }

  // ---- /join : a player joins a host ------------------------------------

  #onJoin(ws, ip, msg) {
    const id = normalizeId(msg.id);
    const host = this.hosts.get(id);
    if (msg.t !== "join" || !ID_RE.test(id)) {
      return this.#reject(ws, ip, "no-such-host", "bad id");
    }
    if (!host) {
      return this.#reject(ws, ip, "no-such-host", `no host "${id}" is online`);
    }
    if (host.joinKey) {
      const given = sha256hex(msg.password ?? "");
      if (given !== host.joinKey) {
        return this.#reject(ws, ip, "bad-password", "wrong password");
      }
    }

    const pendingForHost = Array.from(this.pending.values()).filter((s) => s.host === host);
    if (host.sessions.size + pendingForHost.length >= host.maxSessions) {
      return this.#reject(ws, ip, "host-full", "this host has no free slots", false);
    }
    if (this.live.size + this.pending.size >= this.maxSessions) {
      return this.#reject(ws, ip, "relay-full", "relay is full", false);
    }

    const sid = crypto.randomBytes(8).toString("hex");
    const session = {
      sid, host, joinWs: ws, hostWs: null, state: "waiting",
      ip, up: 0, down: 0, created: Date.now(), timer: null,
    };
    session.timer = setTimeout(() => {
      sendJson(ws, { t: "error", code: "host-timeout", message: "the host did not answer in time" });
      this.#end(session, "host-timeout");
    }, this.acceptMs);
    this.pending.set(sid, session);

    const player = (msg.player && typeof msg.player === "object")
      ? { xuid: str(msg.player.xuid, 32), name: str(msg.player.name, 32) }
      : undefined;
    sendJson(host.ws, { t: "incoming", sid, player, from: ip });

    ws.on("message", (data, isBinary) => {
      if (session.state === "live") {
        return this.#forward(session, ws, session.hostWs, data, isBinary, "up");
      }
      this.#end(session, "joiner sent data before ready");
    });
    ws.once("close", () => this.#end(session, "joiner closed"));
  }

  // ---- byte forwarding ---------------------------------------------------

  #forward(session, fromWs, toWs, data, isBinary, dir) {
    if (!toWs || toWs.readyState !== WebSocket.OPEN) return;
    if (toWs.bufferedAmount > MAX_BUFFERED) {
      return this.#end(session, "slow consumer");
    }
    const n = data.length ?? data.byteLength ?? 0;
    if (dir === "up") session.up += n;
    else session.down += n;
    toWs.send(data, { binary: isBinary });
  }

  // ---- session teardown --------------------------------------------------

  #end(session, reason) {
    if (session.ended) return;
    session.ended = true;
    clearTimeout(session.timer);
    this.pending.delete(session.sid);
    this.live.delete(session);
    session.host.sessions.delete(session);

    if (session.state === "waiting" && session.host.ws.readyState === WebSocket.OPEN) {
      sendJson(session.host.ws, { t: "cancel", sid: session.sid });
    }

    for (const sock of [session.joinWs, session.hostWs]) {
      try { sock?.close(1000); } catch {}
      setTimeout(() => { try { sock?.terminate(); } catch {} }, 2000).unref();
    }

    if (session.liveSince) {
      this.log(`[relay] session ${session.sid} ended (${reason}) after ${Math.round((Date.now() - session.liveSince) / 1000)} s, up ${session.up} B / down ${session.down} B`);
    } else {
      this.log(`[relay] session ${session.sid} never went live (${reason})`);
    }
    this.emit("session-end", session, reason);
  }

  // ---- lifecycle ---------------------------------------------------------

  async start() {
    this.#loadIds();

    const handler = (req, res) => this.#http(req, res);
    if (this.tls) {
      this.server = https.createServer(
        { cert: fs.readFileSync(this.tls.cert), key: fs.readFileSync(this.tls.key) },
        handler,
      );
    } else {
      this.server = http.createServer(handler);
    }

    this.wss = new WebSocketServer({ noServer: true, maxPayload: 1048576, perMessageDeflate: false });
    this.server.on("upgrade", (req, socket, head) => this.#upgrade(req, socket, head));
    this.server.on("clientError", (err, socket) => { try { socket.destroy(); } catch {} });

    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.port, this.host, resolve);
    });
    this.port = this.server.address().port;

    this.timer = setInterval(() => this.#heartbeat(), this.heartbeatMs);
    this.timer.unref();

    this.log(`[relay] listening on ${this.host}:${this.port} (${this.tls ? "wss/https" : "ws/http"}), ${this.ids.size} known id(s)${this.token ? ", host token required" : ""}`);
  }

  async stop() {
    clearInterval(this.timer);
    for (const ws of this.wss?.clients ?? []) ws.terminate();
    await new Promise((resolve) => {
      if (this.server) this.server.close(resolve);
      else resolve();
    });
  }
}

// ---- CLI -----------------------------------------------------------------

async function main() {
  const { values } = parseArgs({
    options: {
      port: { type: "string" },
      host: { type: "string" },
      token: { type: "string" },
      "ids-file": { type: "string" },
      "tls-cert": { type: "string" },
      "tls-key": { type: "string" },
      "max-hosts": { type: "string" },
      "max-sessions": { type: "string" },
      "max-per-host": { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });

  if (values.help) {
    console.log(
`relay-server — the only program that needs a port-forward (TCP, default 7000)

  --port <n>               TCP port (default 7000)
  --host <ip>              bind address (default 0.0.0.0)
  --token <text>           hosts must present this to register (recommended on a public relay; joiners don't need it)
  --ids-file <path>        where host ids are remembered (default ./relay-ids.json)
  --tls-cert <pem> --tls-key <pem>   serve wss/https instead of ws/http
  --max-hosts <n>          hosts online at once (default 200)
  --max-sessions <n>       players relayed at once (default 500)
  --max-per-host <n>       cap for a host's player limit (default 16)

Check from outside:  http://<public ip>:7000/health`);
    process.exit(0);
  }

  if (!!values["tls-cert"] !== !!values["tls-key"]) {
    console.error("error: --tls-cert and --tls-key go together");
    process.exit(1);
  }

  const opts = {
    port: values.port != undefined ? Number(values.port) : 7000,
    host: values.host != undefined ? values.host : "0.0.0.0",
    token: values.token != undefined ? values.token : (process.env.RELAY_TOKEN ?? null),
    idsFile: values["ids-file"] != undefined ? values["ids-file"] : "./relay-ids.json",
    tls: values["tls-cert"] ? { cert: values["tls-cert"], key: values["tls-key"] } : null,
    ...(values["max-hosts"] ? { maxHosts: Number(values["max-hosts"]) } : {}),
    ...(values["max-sessions"] ? { maxSessions: Number(values["max-sessions"]) } : {}),
    ...(values["max-per-host"] ? { maxSessionsPerHost: Number(values["max-per-host"]) } : {}),
  };

  const relay = new RelayServer(opts);
  await relay.start();
}

main().catch((e) => { console.error(e?.stack ?? e); process.exit(1); });

process.on("SIGINT", () => { console.log("[exit] SIGINT"); process.exit(130); });
process.on("uncaughtException", (e) => { console.log("[exit] uncaught exception:", e?.stack ?? e); process.exit(1); });
