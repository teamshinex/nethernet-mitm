// nethernet/signaling.js — NetherNet signaling layer
//
// Role:
//  - createHttpSignalingServer: an HTTP endpoint the game's client hits to
//    fetch the advertised server info (GET /v1/join) and to POST an SDP
//    offer (POST /v1/join/{id}), receiving an SDP answer back.
//  - parseSignal / formatSignal: the wire form of a NetherNet signal,
//    "<TYPE> <connectionId> <data>".
//  - LanSignaling: UDP (dgram) broadcast discovery + message exchange on
//    port 7551, the NetherNet LAN transport.
//
// createHttpSignalingServer is shared by host.js and join.js. The LAN discovery
// codec and LanSignaling are host-only.

import crypto from "node:crypto";
import dgram from "node:dgram";
import os from "node:os";
import http from "node:http";
import { EventEmitter } from "node:events";

// ---- signal / packet constants -------------------------------------------

export const SignalType = {
  OFFER: "CONNECTREQUEST",
  ANSWER: "CONNECTRESPONSE",
  CANDIDATE: "CANDIDATEADD",
  ERROR: "CONNECTERROR",
};

export const PacketID = {
  REQUEST: 0,
  RESPONSE: 1,
  MESSAGE: 2,
};

const DISCOVERY_PORT = 7551;
const MAX_DECLARED_SIGNAL_LENGTH = 1140;

// AES-256-ECB / HMAC-SHA256 key for the NetherNet LAN discovery frames:
// sha256 of the bytes 0xEF 0xBE 0xAD 0xDE 0x00 0x00 0x00 0x00.
const DISCOVERY_KEY = crypto
  .createHash("sha256")
  .update(Buffer.from("efbeadde00000000", "hex"))
  .digest();

// ---- signal wire format ----------------------------------------------------

export function parseSignal(message) {
  const firstSpace = message.indexOf(" ");
  const secondSpace = firstSpace < 0 ? -1 : message.indexOf(" ", firstSpace + 1);
  if (firstSpace < 0 || secondSpace < 0) {
    throw new Error("signal: expected 3 space-separated segments");
  }
  const type = message.slice(0, firstSpace);
  const connectionIdMatch = /^\d+/.exec(message.slice(firstSpace + 1, secondSpace));
  if (!connectionIdMatch) {
    throw new Error("signal: bad connection id");
  }
  const data = message.slice(secondSpace + 1);
  if (!Object.values(SignalType).includes(type)) {
    throw new Error(`signal: unknown type ${type}`);
  }
  return {
    type,
    connectionId: BigInt(connectionIdMatch[0]),
    data,
  };
}

export function formatSignal(signal) {
  return `${signal.type} ${BigInt(signal.connectionId).toString()} ${signal.data}`;
}

// ---- LAN discovery packet codec --------------------------------------------

function encodePacket(packetId, senderId, body = Buffer.alloc(0)) {
  const header = Buffer.alloc(20);
  header.writeUInt16LE(header.length + body.length, 0);
  header.writeUInt16LE(packetId, 2);
  header.writeBigUInt64LE(BigInt(senderId), 4);
  const payload = Buffer.concat([header, body]);
  const checksum = crypto.createHmac("sha256", DISCOVERY_KEY).update(payload).digest();
  const cipher = crypto.createCipheriv("aes-256-ecb", DISCOVERY_KEY, null);
  return Buffer.concat([checksum, cipher.update(payload), cipher.final()]);
}

function decodePacket(datagram) {
  if (datagram.length < 48) {
    throw new Error("discovery: datagram too short");
  }
  const decipher = crypto.createDecipheriv("aes-256-ecb", DISCOVERY_KEY, null);
  const payload = Buffer.concat([decipher.update(datagram.subarray(32)), decipher.final()]);
  const checksum = crypto.createHmac("sha256", DISCOVERY_KEY).update(payload).digest();
  if (!crypto.timingSafeEqual(checksum, datagram.subarray(0, 32))) {
    throw new Error("discovery: checksum mismatch");
  }
  if (payload.length < 20) {
    throw new Error("discovery: payload too short");
  }
  const packetId = payload.readUInt16LE(2);
  const senderId = payload.readBigUInt64LE(4);
  const body = payload.subarray(20);
  switch (packetId) {
    case PacketID.REQUEST:
      return { packetId, senderId };
    case PacketID.RESPONSE: {
      const length = body.readUInt32LE(0);
      const hex = body.subarray(4, 4 + length).toString("ascii");
      return { packetId, senderId, applicationData: Buffer.from(hex, "hex") };
    }
    case PacketID.MESSAGE: {
      const recipientId = body.readBigUInt64LE(0);
      const declaredLength = body.readUInt32LE(8);
      const end = declaredLength >= MAX_DECLARED_SIGNAL_LENGTH ? body.length : 12 + declaredLength;
      return { packetId, senderId, recipientId, data: body.subarray(12, end).toString("utf8") };
    }
  }
  throw new Error(`discovery: unknown packet id ${packetId}`);
}

function encodeMessage(senderId, recipientId, data) {
  const dataBuffer = Buffer.from(data, "utf8");
  const header = Buffer.alloc(12);
  header.writeBigUInt64LE(BigInt(recipientId), 0);
  header.writeUInt32LE(Math.min(dataBuffer.length, MAX_DECLARED_SIGNAL_LENGTH), 8);
  return encodePacket(PacketID.MESSAGE, senderId, Buffer.concat([header, dataBuffer]));
}

function encodeResponse(senderId, applicationData) {
  const hexBuffer = Buffer.from(applicationData.toString("hex"), "ascii");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(hexBuffer.length);
  return encodePacket(PacketID.RESPONSE, senderId, Buffer.concat([header, hexBuffer]));
}

function encodeRequest(senderId) {
  return encodePacket(PacketID.REQUEST, senderId);
}

export function randomId64() {
  const bytes = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[7] = bytes[7] & 127;
  return bytes.readBigUInt64LE(0);
}

// Every IPv4 broadcast address reachable from this machine, plus the fallback.
function broadcastTargets(broadcast = "255.255.255.255") {
  const targets = new Set([broadcast]);
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const iface of addresses ?? []) {
      if (iface.family !== "IPv4" || iface.internal || !iface.netmask) continue;
      const address = iface.address.split(".").map(Number);
      const netmask = iface.netmask.split(".").map(Number);
      targets.add(address.map((octet, i) => octet | (~netmask[i] & 255)).join("."));
    }
  }
  return Array.from(targets);
}

// ---- LAN (UDP) signaling ---------------------------------------------------

export class LanSignaling extends EventEmitter {
  constructor(opts) {
    super();
    this.networkId = BigInt(opts.networkId);
    this.port = opts.port ?? DISCOVERY_PORT;
    this.address = opts.address;
    this.broadcast = opts.broadcast ?? "255.255.255.255";
    this.signalBroadcast = opts.signalBroadcast ?? false;
    this.log = opts.log ?? (() => {});
    this.serverData = null;
    this.aliases = new Set();
    this.peers = new Map();
    this.responses = new Map();
    this.socket = null;
    this.badCount = 0;
  }

  async start() {
    this.socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    this.socket.on("message", (msg, rinfo) => this.#onDatagram(msg, rinfo));
    this.socket.on("error", (err) => this.log("lan socket error:", err.message));
    await new Promise((resolve, reject) => {
      this.socket.once("error", reject);
      const done = () => {
        this.socket.off("error", reject);
        resolve();
      };
      if (this.address) {
        this.socket.bind(this.port, this.address, done);
      } else {
        this.socket.bind(this.port, done);
      }
    });
    this.socket.setBroadcast(true);
    this.port = this.socket.address().port;
  }

  stop() {
    try {
      this.socket?.close();
    } catch {}
  }

  signal(recipientId, signal) {
    const target = this.peers.get(BigInt(recipientId)) ?? this.responses.get(BigInt(recipientId));
    if (!target) {
      throw new Error(`lan: unknown recipient ${recipientId}`);
    }
    const packet = encodeMessage(this.networkId, recipientId, formatSignal(signal));
    this.log(
      `[lan:${this.port}] -> ${signal.type} conn ${signal.connectionId} to ${target.address}:${DISCOVERY_PORT}` +
        `${target.port === DISCOVERY_PORT ? "" : ` and :${target.port}`} (${packet.length}B)`,
    );
    this.socket.send(packet, DISCOVERY_PORT, target.address);
    if (target.port !== DISCOVERY_PORT) {
      this.socket.send(packet, target.port, target.address);
    }

    const all = this.responses.get(BigInt(recipientId))?.all ?? [];
    for (const [address] of all) {
      if (address === target.address) continue;
      this.log(`[lan:${this.port}]    (+ copy to ${address}:${DISCOVERY_PORT})`);
      this.socket.send(packet, DISCOVERY_PORT, address, () => {});
    }

    if (this.signalBroadcast) {
      for (const address of broadcastTargets(this.broadcast)) {
        this.socket.send(packet, DISCOVERY_PORT, address, () => {});
      }
      this.log(`[lan:${this.port}]    (+ broadcast copy to ${broadcastTargets(this.broadcast).join(", ")})`);
    }
  }

  async discover(opts = {}) {
    const address = opts.address;
    const timeoutMs = opts.timeoutMs ?? 5000;
    const filter = opts.filter ?? (() => true);

    const request = encodeRequest(this.networkId);
    const send = () => {
      if (address) {
        this.socket.send(request, DISCOVERY_PORT, address);
      } else {
        for (const target of broadcastTargets(this.broadcast)) {
          this.socket.send(request, DISCOVERY_PORT, target, () => {});
        }
      }
    };

    send();
    const timer = setInterval(send, 1000);
    try {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        for (const [networkId, response] of this.responses) {
          if (address && response.address !== address) continue;
          if (!filter({ networkId, ...response })) continue;
          return { networkId, ...response };
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    } finally {
      clearInterval(timer);
    }
    throw new Error("lan: no server answered discovery");
  }

  #onDatagram(msg, rinfo) {
    let packet;
    try {
      packet = decodePacket(msg);
    } catch (err) {
      if (this.badCount++ < 5) {
        this.log(
          `[lan:${this.port}] undecodable ${msg.length}B from ${rinfo.address}:${rinfo.port}: ${err.message}`,
        );
      }
      return;
    }

    if (packet.senderId === this.networkId) return;
    this.peers.set(packet.senderId, { address: rinfo.address, port: rinfo.port });

    switch (packet.packetId) {
      case PacketID.REQUEST: {
        if (this.serverData) {
          const response = encodeResponse(this.networkId, this.serverData);
          this.socket.send(response, DISCOVERY_PORT, rinfo.address);
          if (rinfo.port !== DISCOVERY_PORT) {
            this.socket.send(response, rinfo.port, rinfo.address);
          }
        }
        break;
      }
      case PacketID.RESPONSE: {
        const existing = this.responses.get(packet.senderId);
        const all = existing?.all ?? new Map();
        all.set(rinfo.address, rinfo.port);
        // Keep a previously stored non-link-local address, else adopt this
        // datagram's source.
        const preferred =
          existing && !existing.address.startsWith("169.254.")
            ? existing
            : { address: rinfo.address, port: rinfo.port };
        this.responses.set(packet.senderId, {
          address: preferred.address,
          port: preferred.port,
          applicationData: packet.applicationData,
          all,
        });
        this.log(
          `[lan:${this.port}] discovery response from ${rinfo.address}:${rinfo.port} (network ${packet.senderId})`,
        );
        break;
      }
      case PacketID.MESSAGE: {
        const forUs =
          packet.recipientId === this.networkId || this.aliases.has(packet.recipientId);
        this.log(
          `[lan:${this.port}] message "${packet.data.slice(0, 40).replace(/\s+/, " ")}" ` +
            `(${packet.data.length} chars) from ${rinfo.address}:${rinfo.port} ` +
            `sender=${packet.senderId} recipient=${packet.recipientId}` +
            `${forUs ? "" : " (NOT FOR US, dropped)"}`,
        );
        if (!forUs) return;
        try {
          this.emit("signal", {
            senderId: packet.senderId,
            signal: parseSignal(packet.data),
            from: rinfo,
          });
        } catch (err) {
          this.log("bad signal:", err.message);
        }
        break;
      }
    }
  }
}

// ---- HTTP signaling server -------------------------------------------------
// Identical in join.cjs and host.cjs.

export function createHttpSignalingServer(opts) {
  const port = opts.port;
  const host = opts.host ?? "0.0.0.0";
  const getInfo = opts.getInfo;
  const onOffer = opts.onOffer;
  const log = opts.log ?? (() => {});

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://x");
      const pathname = url.pathname.replace(/\/+$/, "");
      log(
        `[http] ${req.method} ${req.url} from ${req.socket.remoteAddress} ` +
          `(${req.headers["user-agent"] ?? "no UA"})`,
      );

      if (req.method === "GET") {
        if (pathname === "/v1/join") {
          res.writeHead(200, { "content-type": "application/json" });
          return res.end(JSON.stringify(getInfo()));
        }
      }

      const match = /^\/v1\/join\/([^/]+)$/.exec(pathname);
      if (req.method === "POST") {
        if (match) {
          const chunks = [];
          let total = 0;
          for await (const chunk of req) {
            total += chunk.length;
            if (total > 1048576) {
              res.writeHead(413);
              return res.end();
            }
            chunks.push(chunk);
          }
          const id = decodeURIComponent(match[1]);
          const body = Buffer.concat(chunks).toString("utf8");
          const answer = await onOffer(id, body);
          res.writeHead(200, { "content-type": "application/sdp" });
          return res.end(answer);
        }
      }

      log(`[http] -> 404 (unknown route ${req.method} ${req.url})`);
      res.writeHead(404);
      res.end();
    } catch (err) {
      log("http signaling error:", err.message);
      if (!res.headersSent) {
        res.writeHead(Number.isInteger(err.status) ? err.status : 502, { "content-type": "text/plain" });
      }
      res.end(String(err.message));
    }
  });

  server.on("tlsClientError", () => {});
  server.on("clientError", (err, socket) => {
    log(
      `[http] bad request from ${socket.remoteAddress}: ${err.code ?? err.message}` +
        ` (a TLS/HTTPS handshake to this plain-HTTP port shows up here)`,
    );
    try {
      socket.destroy();
    } catch {}
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve(server));
  });
}
