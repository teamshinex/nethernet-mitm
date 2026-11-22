// nethernet/tunnel.js — relay WebSocket client
//
// A TunnelPeer wraps the relay WebSocket and emits decoded packets; connectWs
// opens the socket, firstJson/openJoin run the /join handshake, and relayUrls
// turns a user-supplied relay address into ws/http base URLs.

import { EventEmitter } from "node:events";
import { WebSocket } from "ws";
import { sendJson, firstJson, normalizeId } from "./util.js";
import { encodeFrame, decodeFrame } from "./frame.js";

export const DEFAULT_RELAY_PORT = 7000;

// Relay error code -> HTTP-ish status used by TunnelError.
const STATUS_BY_CODE = {
  "bad-password": 403,
  "no-such-host": 503,
  "host-offline": 503,
  "host-timeout": 503,
  "host-full": 503,
  "relay-full": 503,
  "host-unreachable": 503,
  "connect": 503,
  "timeout": 503,
};

function defaultLog() {}

export class TunnelError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.code = code;
    this.status = STATUS_BY_CODE[code] ?? 502;
  }
}

export class TunnelPeer extends EventEmitter {
  constructor(ws, opts = {}) {
    super();
    const name = opts.name ?? "tunnel";
    const log = opts.log ?? defaultLog;
    const maxBuffered = opts.maxBuffered ?? 16777216;
    Object.assign(this, { ws, name, log, maxBuffered });
    this.closed = false;
    this.opened = true;
    this.stats = { sentMsgs: 0, sentBytes: 0, recvMsgs: 0, recvBytes: 0 };

    ws.on("message", (data, isBinary) => {
      if (!isBinary) return;
      const frame = decodeFrame(data);
      if (!frame) {
        this.close(new Error("bad tunnel frame"));
        return;
      }
      this.stats.recvMsgs += 1;
      this.stats.recvBytes += frame.payload.length;
      this.emit("packet", frame.kind, frame.payload);
    });
    ws.once("close", (code) => this.close(new Error(`tunnel closed (${code})`)));
    ws.on("error", (err) => this.close(err));
    process.nextTick(() => {
      if (!this.closed) this.emit("open");
    });
  }

  send(kind, payload) {
    if (this.closed || payload.length === 0 || this.ws.readyState !== WebSocket.OPEN) {
      return;
    }
    if (this.ws.bufferedAmount > this.maxBuffered) {
      this.close(new Error("tunnel too slow (backpressure)"));
      return;
    }
    this.stats.sentMsgs += 1;
    this.stats.sentBytes += payload.length;
    this.ws.send(encodeFrame(kind, payload), { binary: true });
  }

  close(err) {
    if (this.closed) return;
    this.closed = true;
    try {
      this.ws.close(1000);
    } catch {}
    setTimeout(() => {
      try {
        this.ws.terminate();
      } catch {}
    }, 2000).unref();
    this.emit("close", err);
  }
}

export function connectWs(url, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 10000;
  const handshakeTimeout = opts.handshakeTimeout ?? timeoutMs;
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { handshakeTimeout, maxPayload: 1048576, perMessageDeflate: false });
    const onErr = (err) => {
      reject(new TunnelError("connect", `cannot reach the relay (${err.message})`));
    };
    ws.once("error", onErr);
    ws.once("open", () => {
      ws.off("error", onErr);
      resolve(ws);
    });
  });
}

export async function openJoin(opts) {
  const { relay, id, password, player, log } = opts;
  const timeoutMs = opts.timeoutMs ?? 25000;

  const urls = relayUrls(relay);
  const ws = await connectWs(`${urls.ws}/join`);
  try {
    sendJson(ws, { t: "join", id: normalizeId(id), password, player });
    const reply = await firstJson(ws, timeoutMs);
    if (reply.t === "ready") {
      return new TunnelPeer(ws, { name: "join-tunnel", log });
    }
    throw new TunnelError(
      reply.code ?? "relay-error",
      reply.message ?? reply.code ?? "relay refused the connection",
    );
  } catch (e) {
    try {
      ws.close();
    } catch {}
    throw e;
  }
}

export function relayUrls(relay) {
  let s = String(relay ?? "").trim();
  if (!s) throw new Error("relay address is empty");
  if (!/^[a-z]+:\/\//.test(s)) {
    s = `ws://${s}`;
  }
  const u = new URL(s);
  const secure = u.protocol === "wss:" || u.protocol === "https:";
  if (!["ws:", "wss:", "http:", "https:"].includes(u.protocol)) {
    throw new Error(`unsupported relay scheme ${u.protocol}`);
  }
  if (!u.port && !secure) {
    u.port = String(DEFAULT_RELAY_PORT);
  }
  return {
    ws: `${secure ? "wss" : "ws"}://${u.host}`,
    http: `${secure ? "https" : "http"}://${u.host}`,
  };
}
