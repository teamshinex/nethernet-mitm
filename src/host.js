// host.js — nethernet-mitm host agent
//
// Role: exposes a NetherNet "server" to remote joiners. It registers an id on a
// relay, accepts tunnelled joiner connections, bridges each one to a WebRTC
// upstream (a LAN world or an HTTP/BDS server), and — when not in raw mode —
// speaks the Bedrock protocol to the local game: handshake, network settings,
// encryption and Login re-signing.

import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { EventEmitter } from "node:events";

import { NetherNetPeer } from "./nethernet/peer.js";
import {
  ServerIdentity,
  createServerHandshake,
  parseServerHandshake,
  deriveSecretKey,
  encodeServerData,
  decodeServerData,
  inspectIdentity,
} from "./nethernet/identity.js";
import { createHttpSignalingServer, LanSignaling, randomId64 } from "./nethernet/signaling.js";
import { TunnelPeer, TunnelError, connectWs, relayUrls } from "./nethernet/tunnel.js";
import { normalizeId, sendJson, firstJson } from "./nethernet/util.js";
import {
  packetTools,
  BatchCodec,
  BedrockClient,
  buildLoginRequest,
  parsePlayerLogin,
  buildRelayedLogin,
  goStyleClientData,
  defaultClientData,
  writeVaruint,
  readVaruint,
  generateKeyPair,
  signClientOffer,
  formatLocalCandidate,
} from "./proto/client.js";

// ---- constants -----------------------------------------------------------

const GAME_VERSION = "1.26.60";
const ID_RE = /^[a-z0-9][a-z0-9-]{2,31}$/;
const FATAL_CODES = new Set(["bad-id", "bad-token", "bad-secret", "id-taken"]);

// NOTE: SignalType / ErrorCode are kept inline rather than imported from
// signaling.js; the string/number values are the contract.
const SignalType = {
  OFFER: "CONNECTREQUEST",
  ANSWER: "CONNECTRESPONSE",
  CANDIDATE: "CANDIDATEADD",
  ERROR: "CONNECTERROR",
};
const ErrorCode = {
  NONE: 0,
  NEGOTIATION_TIMEOUT: 2,
  FAILED_TO_CREATE_PEER_CONNECTION: 4,
  INCOMING_CONNECTION_IGNORED: 16,
  GENERIC_FAILURE: 35,
  FAILED_TO_CREATE_IDENTITY_ASSERTION: 36,
  IDENTITY_NOT_ALLOWED: 37,
};

// Bedrock packet ids used by the host bridge.
const PACKET = {
  LOGIN: 1,
  PLAY_STATUS: 2,
  SERVER_TO_CLIENT_HANDSHAKE: 3,
  CLIENT_TO_SERVER_HANDSHAKE: 4,
  DISCONNECT: 5,
  RESOURCE_PACKS_INFO: 6,
  PACKET_VIOLATION_WARNING: 156,
  NETWORK_SETTINGS: 143,
  REQUEST_NETWORK_SETTINGS: 193,
};
const PACKET_NAMES = {
  [PACKET.LOGIN]: "Login",
  [PACKET.PLAY_STATUS]: "PlayStatus",
  [PACKET.SERVER_TO_CLIENT_HANDSHAKE]: "ServerToClientHandshake",
  [PACKET.CLIENT_TO_SERVER_HANDSHAKE]: "ClientToServerHandshake",
  [PACKET.DISCONNECT]: "Disconnect",
  [PACKET.RESOURCE_PACKS_INFO]: "ResourcePacksInfo",
  [PACKET.NETWORK_SETTINGS]: "NetworkSettings",
  [PACKET.PACKET_VIOLATION_WARNING]: "PacketViolationWarning",
  [PACKET.REQUEST_NETWORK_SETTINGS]: "RequestNetworkSettings",
};

const DEFAULT_INFO = {
  name: "NetherNet Proxy",
  protocol: 2225,
  version: "1.26.60",
  level: "Proxy",
  players: 0,
  maxPlayers: 10,
  gameType: 0,
};

// ---- small helpers -------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function sha256hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function randomSecret() {
  return crypto.randomBytes(24).toString("base64url");
}

async function httpJoin(baseUrl, networkId, offer, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 30000;
  const url = `${String(baseUrl).replace(/\/+$/, "")}/v1/join/${encodeURIComponent(networkId)}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/sdp" },
    body: offer,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`POST /v1/join -> HTTP ${res.status}: ${text.slice(0, 200)}`);
  return text;
}

async function httpInfo(baseUrl, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 5000;
  const res = await fetch(`${String(baseUrl).replace(/\/+$/, "")}/v1/join`, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`GET /v1/join -> HTTP ${res.status} (NetherNet not supported?)`);
  return res.json();
}

function safeTools(version) {
  try {
    return packetTools(version);
  } catch {
    return packetTools(GAME_VERSION);
  }
}

function packetName(id, version) {
  return safeTools(version ?? GAME_VERSION).name(id) ?? PACKET_NAMES[id] ?? `#${id}`;
}

// ---- hook packet wrapper -------------------------------------------------

class HookPacket {
  constructor(id, payload, header, tools) {
    this.id = id;
    this.payload = payload;
    this.header = header;
    Object.defineProperty(this, "_tools", { value: tools });
    Object.defineProperty(this, "_params", { value: undefined, writable: true });
  }

  get name() {
    return this._tools.name(this.id) ?? PACKET_NAMES[this.id] ?? `#${this.id}`;
  }

  get buffer() {
    return this.payload;
  }

  get params() {
    if (this._params == undefined) this._params = this._tools.decode(this.id, this.payload);
    return this._params;
  }

  get json() {
    return this.params;
  }

  with(params) {
    return this._tools.encode(this.name, params);
  }

  encode() {
    return this.with(this.params);
  }

  stringify(indent = 2) {
    return JSON.stringify(
      this.params,
      (k, v) => {
        if (typeof v === "bigint") return v.toString();
        if (Buffer.isBuffer(v) || v?.type === "Buffer") return `<${v?.data?.length ?? v.length} bytes>`;
        return v;
      },
      indent,
    );
  }

  toJSON() {
    return { id: this.id, name: this.name, size: this.payload.length };
  }
}

// ---- per-session Bedrock bridge (host <-> game) --------------------------

class MitmSession extends EventEmitter {
  constructor(opts) {
    super();
    const hooks = opts.hooks ?? {};
    const dump = opts.dump ?? false;
    const log = opts.log ?? console.log;
    const getHostNonce = opts.getHostNonce;
    const hostEncrypt = opts.hostEncrypt ?? "off";
    const playerEncrypt = opts.playerEncrypt ?? "auto";
    const gameVersion = opts.gameVersion ?? GAME_VERSION;
    const playerFrameHeader = opts.playerFrameHeader ?? false;
    const hostFrameHeader = opts.hostFrameHeader ?? false;
    const playerHandshake = opts.playerHandshake ?? "mirror";
    const legacyLogin = opts.legacyLogin ?? false;

    Object.assign(this, {
      id: opts.id,
      client: opts.client,
      upstream: opts.upstream,
      proxyKey: opts.proxyKey,
      hooks,
      dump,
      log,
      getHostNonce,
      hostEncrypt,
      playerEncrypt,
      playerHandshake,
      legacyLogin,
    });

    this.tools = safeTools(gameVersion);
    this.playerCodec = new BatchCodec({ header: playerFrameHeader });
    this.hostCodec = new BatchCodec({ header: hostFrameHeader });
    this.playerHandshakeSent = false;
    this.clientProtocol = null;
    this.player = null;
    this.playerKey = null;
    this.awaitPlayerHandshake = false;
    this.playerGate = true;
    this.outbox = [];
    this.chain = Promise.resolve();
    this.closed = false;
  }

  start() {
    this.client.on("packet", (kind, data) => {
      if (this.closed) return;
      if (kind === "reliable") {
        this.chain = this.chain.then(() => this.#fromPlayer(data)).catch((e) => this.#fail("player", e));
      } else {
        this.#rawPass("serverbound", kind, data, this.upstream);
      }
    });
    this.upstream.on("packet", (kind, data) => {
      if (this.closed) return;
      if (kind === "reliable") {
        try {
          this.#fromHost(data);
        } catch (e) {
          this.#fail("host", e);
        }
      } else {
        this.#rawPass("clientbound", kind, data, this.client);
      }
    });
    this.client.once("close", (e) => this.close(e));
    this.upstream.once("close", (e) => this.close(e));
    this.client.resume?.();
    return this;
  }

  close(err) {
    if (this.closed) return;
    this.closed = true;
    this.client.close(err);
    this.upstream.close(err);
    this.emit("close", err);
  }

  #fail(side, err) {
    this.log(`[#${this.id}] ${side} side error: ${err.message}`);
    this.close(err);
  }

  #writePlayerNow(packets) {
    this.client.send("reliable", this.playerCodec.encode(packets));
  }

  #writePlayer(packets) {
    if (!this.playerGate) {
      // Buffer until the player gate opens.
      this.outbox.push(...packets);
      return;
    }
    this.#writePlayerNow(packets);
  }

  #writeHost(packets) {
    this.upstream.send("reliable", this.hostCodec.encode(packets));
  }

  #rawPass(dir, kind, data, target) {
    if (this.dump) {
      this.log(
        `[#${this.id}] ${dir === "serverbound" ? "C→S" : "S→C"} ${kind.padEnd(10)} ${String(data.length).padStart(6)}B ${data.subarray(0, 16).toString("hex")}`,
      );
    }
    target.send(kind, data);
  }

  #asPacket(idOrName, params) {
    if (typeof idOrName === "string") return this.tools.encode(idOrName, params);
    return { id: idOrName, payload: params };
  }

  #ctx(dir) {
    return {
      session: this,
      dir,
      kind: "reliable",
      packets: this.tools,
      decode: (id, buf) => this.tools.decode(id, buf),
      encode: (id, params) => this.tools.encode(id, params),
      sendToClient: (id, params) => this.#writePlayer([this.#asPacket(id, params)]),
      sendToServer: (id, params) => this.#writeHost([this.#asPacket(id, params)]),
    };
  }

  #hooked(dir, packet, out) {
    if (this.dump) {
      this.log(
        `[#${this.id}] ${dir === "serverbound" ? "C→S" : "S→C"} ${packetName(packet.id).padEnd(26)} ${String(packet.payload.length).padStart(6)}B ${packet.payload.subarray(0, 16).toString("hex")}`,
      );
    }
    if (!this.hooks[dir]) {
      out.push(packet);
      return;
    }
    let r;
    try {
      const hp = new HookPacket(packet.id, packet.payload, packet.header, this.tools);
      r = this.hooks[dir](hp, this.#ctx(dir));
    } catch (e) {
      this.log(`[#${this.id}] hook ${dir} threw: ${e.message}`);
      out.push(packet);
      return;
    }
    if (r == null) return; // null => drop the packet
    if (!r) {
      out.push(packet); // false => pass the original
      return;
    }
    try {
      for (let item of Array.isArray(r) ? r : [r]) {
        if (Buffer.isBuffer(item)) {
          out.push({ id: packet.id, header: packet.header, payload: item });
          continue;
        }
        if (item.payload == undefined && item.name != undefined && item.params != undefined) {
          item = this.tools.encode(item.name, item.params);
        }
        out.push({
          id: item.id,
          header:
            item.header != undefined
              ? item.header
              : item.id === packet.id
                ? packet.header
                : undefined,
          payload: item.payload,
        });
      }
    } catch (e) {
      this.log(`[#${this.id}] hook ${dir} returned an unusable packet (${e.message}); passing the original`);
      out.push(packet);
    }
  }

  #offerPlayerHandshake() {
    if (this.playerHandshakeSent) return;
    this.playerHandshakeSent = true;
    const { jwt, key } = createServerHandshake(this.proxyKey.privateKey, this.player.publicKey);
    const jwtBuf = Buffer.from(jwt);
    this.playerKey = key;
    this.playerGate = false;
    this.awaitPlayerHandshake = true;
    this.#writePlayerNow([
      {
        id: PACKET.SERVER_TO_CLIENT_HANDSHAKE,
        payload: Buffer.concat([writeVaruint(jwtBuf.length), jwtBuf]),
      },
    ]);
    if (this.playerEncrypt === "on") this.playerCodec.enableEncryption(key);
    this.log(`[#${this.id}] sent handshake to player (player AES: ${this.playerEncrypt})`);
  }

  #onHostHandshake(packet) {
    if (!this.player) throw new Error("host sent a handshake before the player logged in");
    const [len, off] = readVaruint(packet.payload, 0);
    const jwt = packet.payload.toString("utf8", off, off + len);
    const { serverPublicKey, salt } = parseServerHandshake(jwt);
    if (this.hostEncrypt === "on") {
      const secret = deriveSecretKey(this.proxyKey.privateKey, serverPublicKey, salt);
      this.hostCodec.enableEncryption(secret);
      this.log(`[#${this.id}] host AES enabled`);
    } else {
      this.log(`[#${this.id}] host handshake received, host AES NOT enabled`);
    }
    this.#writeHost([{ id: PACKET.CLIENT_TO_SERVER_HANDSHAKE, payload: Buffer.alloc(0) }]);
    this.#offerPlayerHandshake();
  }

  #onHostNetworkSettings(packet) {
    const threshold = packet.payload.readUInt16LE(0);
    const algorithm = packet.payload.readUInt16LE(2);
    this.log(
      `[#${this.id}] host NetworkSettings: threshold=${threshold} algorithm=${algorithm} -> player (same values)`,
    );
    this.#writePlayerNow([packet]);
    this.hostCodec.enableCompression(threshold, algorithm);
    this.playerCodec.enableCompression(threshold, algorithm);
  }

  #fromHost(buf) {
    const packets = this.hostCodec.decode(buf, { withHeader: true });
    const out = [];
    for (const p of packets) {
      if (p.id === PACKET.NETWORK_SETTINGS) {
        this.#onHostNetworkSettings(p);
        continue;
      }
      if (p.id === PACKET.SERVER_TO_CLIENT_HANDSHAKE) {
        this.#onHostHandshake(p);
        continue;
      }
      this.#hooked("clientbound", p, out);
    }
    if (out.length) this.#writePlayer(out);
  }

  #openGate() {
    this.playerGate = true;
    const pending = this.outbox.splice(0);
    if (pending.length) this.#writePlayerNow(pending);
  }

  #decodeHandshakeReply(buf) {
    const modes =
      this.playerEncrypt === "on" ? ["on"] : this.playerEncrypt === "off" ? ["off"] : ["off", "on"];
    let lastErr;
    for (const mode of modes) {
      try {
        const codec = new BatchCodec({ header: this.playerCodec.header });
        codec.compression = this.playerCodec.compression;
        if (mode === "on") codec.enableEncryption(this.playerKey);
        const packets = codec.decode(buf, { withHeader: true });
        if (packets[0]?.id !== PACKET.CLIENT_TO_SERVER_HANDSHAKE)
          throw new Error("first packet after handshake is not ClientToServerHandshake");
        if (mode === "on") this.playerCodec.cipher = codec.cipher;
        this.log(
          `[#${this.id}] player handshake reply decoded (${mode === "on" ? "AES on" : "plain, no AES"})`,
        );
        this.awaitPlayerHandshake = false;
        return packets;
      } catch (e) {
        lastErr = e;
      }
    }
    throw new Error(`could not decode the player's handshake reply (${lastErr.message})`);
  }

  async #onPlayerLogin(packet) {
    const login = parsePlayerLogin(packet.payload, { wrapped: true });
    this.player = login;
    const name = login.identityData.DisplayName || login.clientData.ThirdPartyName || "?";
    this.log(
      `[#${this.id}] player Login: "${name}" identity=${login.identityData.Identity} protocol=${login.clientProtocol}`,
    );
    this.hooks.onLogin?.(login, this);
    this.emit("login", login);
    const nonce = await this.getHostNonce?.();
    const relayed = buildRelayedLogin({
      identityData: login.identityData,
      clientData: login.clientData,
      proxyPrivateKey: this.proxyKey.privateKey,
      hostNonce: nonce,
      legacy: this.legacyLogin,
      log: (m) => this.log(`[#${this.id}] ${m}`),
    });
    const protoBuf = Buffer.alloc(4);
    protoBuf.writeInt32BE(login.clientProtocol ?? this.clientProtocol ?? 0);
    this.#writeHost([
      {
        id: PACKET.LOGIN,
        payload: Buffer.concat([protoBuf, writeVaruint(relayed.length), relayed]),
      },
    ]);
    this.log(
      `[#${this.id}] relayed Login to host (re-signed, ${relayed.length} bytes, nonce ${nonce ?? "n/a"})`,
    );
    if (this.playerHandshake === "always") this.#offerPlayerHandshake();
  }

  async #fromPlayer(buf) {
    if (this.closed) return;
    const packets = this.awaitPlayerHandshake
      ? this.#decodeHandshakeReply(buf)
      : this.playerCodec.decode(buf, { withHeader: true });
    const out = [];
    for (const p of packets) {
      if (p.id === PACKET.REQUEST_NETWORK_SETTINGS) {
        this.clientProtocol = p.payload.readInt32BE(0);
        this.log(`[#${this.id}] player RequestNetworkSettings (protocol ${this.clientProtocol}) -> host`);
        this.#writeHost([p]);
        continue;
      }
      if (p.id === PACKET.LOGIN) {
        await this.#onPlayerLogin(p);
        continue;
      }
      if (p.id === PACKET.CLIENT_TO_SERVER_HANDSHAKE) {
        this.#openGate();
        continue;
      }
      this.#hooked("serverbound", p, out);
    }
    if (out.length) this.#writeHost(out);
  }
}

// ---- the NetherNet proxy -------------------------------------------------

export class NetherNetProxy {
  constructor(opts) {
    const lanListen = opts.lanListen ?? false;
    const httpListen = opts.httpListen ?? null;
    const upstream = opts.upstream;
    const identity = opts.identity ?? new ServerIdentity();
    const hooks = opts.hooks ?? {};
    const dump = opts.dump ?? false;
    const probe = opts.probe ?? false;
    const bindAddress = opts.bindAddress;
    const log = opts.log ?? console.log;
    const raw = opts.raw ?? false;
    const external = opts.external ?? false;
    const upstreamIdentity = opts.upstreamIdentity ?? "auto";
    const lanDialBind = opts.lanDialBind;
    const lanSignalBroadcast = opts.lanSignalBroadcast ?? true;
    const httpExtraPorts = opts.httpExtraPorts ?? [443, 80];
    const hostEncrypt = opts.hostEncrypt ?? "off";
    const playerEncrypt = opts.playerEncrypt ?? "auto";
    const frameHeader = opts.frameHeader ?? false;
    const loginLegacy = opts.loginLegacy ?? false;
    const lanBind = opts.lanBind;

    if (!upstream) throw new Error("upstream is required");
    if (!lanListen && !httpListen && !probe && !external)
      throw new Error("enable at least one of lanListen / httpListen (or probe, or external)");

    Object.assign(this, {
      external,
      lanListen,
      httpListen,
      upstream,
      upstreamIdentity,
      lanDialBind,
      lanSignalBroadcast,
      httpExtraPorts,
      identity,
      hooks,
      dump,
      bindAddress,
      log,
      raw,
      hostEncrypt,
      playerEncrypt,
      frameHeader,
      loginLegacy,
      lanBind,
    });

    this.proxyKey = generateKeyPair();
    this.info = { ...DEFAULT_INFO };
    this.lanAppData = null;
    this.lanServer = null;
    this.lanDialer = null;
    this.lanTarget = null;
    this.dialRoutes = new Map();
    this.lanSessions = new Map();
    this.sessions = new Set();
    this.seq = 0;
    this.httpServer = null;
    this.timers = [];
  }

  get sessionCount() {
    return this.sessions.size;
  }

  async start() {
    if (this.upstream.type === "lan") {
      this.lanDialer = new LanSignaling({
        networkId: randomId64(),
        port: 0,
        address: this.lanDialBind,
        signalBroadcast: this.lanSignalBroadcast,
        log: this.log,
      });
      await this.lanDialer.start();
      this.lanDialer.on("signal", (s) => this.#onSignal(s));
    }

    await this.#refreshUpstreamInfo();

    if (this.lanListen) {
      this.lanServer = new LanSignaling({
        networkId: randomId64(),
        port: 7551,
        address: this.lanBind,
        log: this.log,
      });
      if (this.lanDialer) {
        this.lanServer.aliases.add(this.lanDialer.networkId);
        this.lanServer.peers = this.lanDialer.peers;
        this.lanServer.responses = this.lanDialer.responses;
      }
      await this.lanServer.start();
      this.lanServer.on("signal", (s) => this.#onSignal(s));
      if (this.lanListen) this.lanServer.serverData = this.lanAppData;
    }

    if (this.lanListen) {
      this.log(
        `[lan] advertising on ${this.lanBind ?? "0.0.0.0"}:7551 as network ${this.lanServer.networkId}`,
      );
    }

    if (this.httpListen) {
      this.httpServer = await createHttpSignalingServer({
        ...this.httpListen,
        getInfo: () => this.info,
        onOffer: (networkId, offerSdp) => this.#onHttpOffer(networkId, offerSdp),
        log: this.log,
      });
      this.log(`[http] signaling on :${this.httpListen.port} (GET /v1/join, POST /v1/join/{id})`);
      this.extraHttpServers = [];
      if (this.httpListen.port === 19132) {
        for (const p of this.httpExtraPorts) {
          try {
            this.extraHttpServers.push(
              await createHttpSignalingServer({
                ...this.httpListen,
                port: p,
                getInfo: () => this.info,
                onOffer: (networkId, offerSdp) => this.#onHttpOffer(networkId, offerSdp),
                log: this.log,
              }),
            );
            this.log(`[http] also listening on :${p} (client probe port; allow it in the firewall)`);
          } catch (e) {
            this.log(
              `[http] extra port :${p} not available (${e.code ?? e.message}) - fine unless the phone stalls`,
            );
          }
        }
      }
    }

    if (this.upstream.type === "http") {
      this.timers.push(setInterval(() => this.#refreshUpstreamInfo().catch(() => {}), 15000));
    }

    if (this.identity) {
      this.log(`[identity] operator key fingerprint (sha256 of cpk JWK): ${this.identity.keyFingerprint}`);
    }
  }

  stop() {
    this.timers.forEach(clearInterval);
    this.httpServer?.close();
    for (const s of this.extraHttpServers ?? []) s.close();
    this.lanServer?.stop();
    this.lanDialer?.stop();
    for (const sess of Array.from(this.sessions)) {
      sess.client.close();
      sess.upstream.close();
    }
  }

  async probe(timeoutMs = 20000) {
    const started = Date.now();
    let upstream;
    try {
      try {
        upstream = await this.#connectUpstream("probe");
        this.log(`[probe] signaling done in ${Date.now() - started} ms; waiting for data channels...`);
        await new Promise((resolve, reject) => {
          const timer = setTimeout(
            () => reject(new Error(`data channels did not open within ${timeoutMs} ms`)),
            timeoutMs,
          );
          upstream.once("open", () => {
            clearTimeout(timer);
            resolve();
          });
          upstream.once("close", (e) => {
            clearTimeout(timer);
            reject(e ?? new Error("closed before open"));
          });
        });
        this.log(`[probe] OK: reliable + unreliable channels open after ${Date.now() - started} ms`);
        return true;
      } catch (e) {
        this.log(`[probe] FAILED: ${e.message}`);
        return false;
      }
    } finally {
      upstream?.close();
    }
  }

  async loginProbe(opts = {}) {
    const legacy = opts.legacy ?? false;
    const frame = opts.frame ?? "none";
    const encrypt = opts.encrypt ?? "auto";
    const timeoutMs = opts.timeoutMs ?? 20000;

    const headers = frame === "auto" ? [false, true] : [frame === "fe"];
    const encrypts = encrypt === "auto" ? [false, true] : [encrypt === "on"];
    const legacies = legacy ? [true] : [false, true];

    encryptLoop: for (const enc of encrypts) {
      for (const profile of ["go", "basic"]) {
        headerLoop: for (const hdr of headers) {
          let result;
          for (const leg of legacies) {
            this.log(
              `[login] ===== attempt: encrypt=${enc ? "on" : "off"}, ${hdr ? "WITH" : "WITHOUT"} 0xFE, ${leg ? "legacy" : "new"} login format, ClientData profile "${profile}" =====`,
            );
            result = await this.#loginAttempt({ legacy: leg, header: hdr, profile, encrypt: enc, timeoutMs });
            if (result.result === "no-reply") continue;
            if (result.result === "error") continue;
            break;
          }
          if (result.result === "ok") return true;
          if (result.result === "violation") continue headerLoop;
          continue encryptLoop;
        }
      }
    }
    return false;
  }

  async relayLoginProbe(opts = {}) {
    const timeoutMs = opts.timeoutMs ?? 20000;
    const kp = generateKeyPair();
    const identity = { displayName: "RelayTestPlayer", identity: crypto.randomUUID() };
    const clientData = goStyleClientData({
      displayName: identity.displayName,
      version: "1.26.52",
      serverAddress: "player-stale-address",
      nonce: "player-stale-nonce",
    });
    const loginRequest = buildLoginRequest({ privateKey: kp.privateKey, identity, clientData });
    this.log(`[relay] simulated player login built (${loginRequest.length} bytes, signed by a throwaway player key)`);
    const { identityData, clientData: parsedClient } = parsePlayerLogin(loginRequest, { wrapped: false });
    this.log(
      `[relay] parsed player login: displayName=${identityData.DisplayName} identity=${identityData.Identity} selfSignedId(player-declared)=${parsedClient.SelfSignedId}`,
    );

    let hostNonce;
    if (this.upstream.type === "lan") {
      this.lanDialer.responses.delete(this.lanTarget.networkId);
      this.lanTarget = await this.lanDialer.discover({
        address: this.upstream.address,
        filter: (t) => t.networkId !== this.lanServer?.networkId,
      });
      hostNonce = decodeServerData(this.lanTarget.applicationData).nonce;
    }

    const proxyKp = generateKeyPair();
    const relayed = buildRelayedLogin({
      identityData,
      clientData: parsedClient,
      proxyPrivateKey: proxyKp.privateKey,
      hostNonce,
      log: this.log,
    });
    this.log(`[relay] re-signed for host (${relayed.length} bytes, signed by the proxy's own key, not the player's)`);
    const r = await this.#loginAttempt({
      header: false,
      encrypt: false,
      timeoutMs,
      loginRequestOverride: relayed,
      privateKeyOverride: proxyKp.privateKey,
    });
    return r.result === "ok";
  }

  async attachPeer(client, opts = {}) {
    const { player, onReady } = opts;
    const id = ++this.seq;
    this.log(`[#${id}] attached external client${player?.name ? ` "${player.name}"` : ""}`);
    let upstream;
    try {
      upstream = await this.#connectUpstream(id, undefined, player);
      if (client.closed) throw new Error("client went away while the upstream was connecting");
      onReady?.();
      this.#bridge(id, client, upstream);
    } catch (e) {
      upstream?.close(e);
      throw e;
    }
    return id;
  }

  async refreshInfo() {
    await this.#refreshUpstreamInfo();
    return this.info;
  }

  #onSignal(sig) {
    this.#onLanSignal(sig);
    this.#onDialerSignal(sig);
  }

  async #onHttpOffer(networkId, offerSdp) {
    const { answer } = await this.#acceptClient({ offerSdp, networkId, trickle: false, via: "http" });
    return answer;
  }

  async #acceptClient({ offerSdp, networkId, trickle, via }) {
    const id = ++this.seq;
    const ident = inspectIdentity(offerSdp);
    this.log(
      `[#${id}] client via ${via}, network ${networkId}${ident?.claims ? `, identity claims: ${Object.keys(ident.claims).join(",")}` : ", no a=identity"}`,
    );
    const httpNetwork = via === "http" ? networkId : undefined;
    const player = { xuid: ident?.claims?.xid, name: ident?.claims?.xname };
    const upstream = await this.#connectUpstream(id, httpNetwork, player);
    const client = new NetherNetPeer({ name: `cl-${id}`, log: this.log, bindAddress: this.bindAddress });
    try {
      let answer = await client.acceptOffer(offerSdp, { trickle });
      if (this.identity) answer = this.identity.sign(answer);
      this.#bridge(id, client, upstream);
      return { answer, client };
    } catch (e) {
      client.close(e);
      upstream.close(e);
      throw e;
    }
  }

  #onLanSignal(sig) {
    const senderId = sig.senderId;
    const signal = sig.signal;
    const key = `${senderId}:${signal.connectionId}`;
    const reply = (payload) => {
      try {
        this.lanServer.signal(senderId, { connectionId: signal.connectionId, ...payload });
      } catch (e) {
        this.log(e.message);
      }
    };

    if (signal.type === SignalType.OFFER) {
      if (!this.lanListen || this.lanSessions.has(key)) return;
      const entry = { client: null, pending: [] };
      this.lanSessions.set(key, entry);
      this.#acceptClient({ offerSdp: signal.data, networkId: senderId.toString(), trickle: true, via: "lan" })
        .then(({ client, answer }) => {
          entry.client = client;
          client.once("close", () => this.lanSessions.delete(key));
          reply({ type: SignalType.ANSWER, data: answer });
          client.startCandidates((c) =>
            reply({ type: SignalType.CANDIDATE, data: formatLocalCandidate(c, client.ufrag) }),
          );
          entry.pending.splice(0).forEach((cand) => client.addRemoteCandidate(cand));
        })
        .catch((e) => {
          this.log(`[lan] client ${senderId} failed: ${e.message}`);
          this.lanSessions.delete(key);
          reply({ type: SignalType.ERROR, data: String(ErrorCode.GENERIC_FAILURE) });
        });
    } else if (signal.type === SignalType.CANDIDATE) {
      const entry = this.lanSessions.get(key);
      if (!entry) return;
      if (entry.client) entry.client.addRemoteCandidate(signal.data);
      else entry.pending.push(signal.data);
    } else if (signal.type === SignalType.ERROR) {
      const entry = this.lanSessions.get(key);
      if (entry?.client) entry.client.close(new Error(`client CONNECTERROR ${signal.data}`));
      this.lanSessions.delete(key);
    }
  }

  #onDialerSignal(sig) {
    const route = this.dialRoutes.get(sig.signal.connectionId);
    if (!route) return;
    if (sig.signal.type === SignalType.ANSWER) route.resolve(sig.signal.data);
    else if (sig.signal.type === SignalType.CANDIDATE) route.peer.addRemoteCandidate(sig.signal.data);
    else if (sig.signal.type === SignalType.ERROR)
      route.reject(new Error(`upstream CONNECTERROR ${sig.signal.data}`));
  }

  async #connectUpstream(id, networkId, player) {
    try {
      return await this.#connectUpstreamOnce(id, networkId, player);
    } catch (e) {
      if (!/without ICE transport/.test(e?.message ?? "")) throw e;
      this.log(
        `[#${id}] upstream: libdatachannel refused the answer (${e.message}); retrying once with a fresh connection`,
      );
      return this.#connectUpstreamOnce(id, networkId, player);
    }
  }

  async #connectUpstreamOnce(id, networkId, player) {
    const peer = new NetherNetPeer({ name: `up-${id}`, log: this.log, bindAddress: this.bindAddress });
    try {
      if (this.upstream.type === "http") {
        const offer = await peer.createOffer({ trickle: false });
        const signed = this.#signUpstreamOffer(offer, player);
        const nid = networkId ?? randomId64().toString();
        const answer = await httpJoin(this.upstream.url, nid, signed);
        this.log(`[#${id}] upstream http answer (${answer.length} chars): ${JSON.stringify(answer.slice(0, 500))}`);
        const ident = inspectIdentity(answer);
        if (ident?.claims?.cpk) {
          this.log(`[#${id}] upstream operator iss=${ident.claims.iss ?? "?"}`);
        }
        peer.setAnswer(answer);
      } else {
        const target = this.lanTarget;
        const connectionId = randomId64();
        const offer = await peer.createOffer({ trickle: true });
        const signed = this.#signUpstreamOffer(offer, player);
        const answerPromise = new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("LAN upstream: answer timeout")), 15000);
          this.dialRoutes.set(connectionId, {
            peer,
            resolve: (v) => {
              clearTimeout(timer);
              resolve(v);
            },
            reject: (e) => {
              clearTimeout(timer);
              reject(e);
            },
          });
        });
        this.lanDialer.signal(target.networkId, { type: SignalType.OFFER, connectionId, data: signed });
        peer.startCandidates((c) =>
          this.lanDialer.signal(target.networkId, {
            type: SignalType.CANDIDATE,
            connectionId,
            data: formatLocalCandidate(c, peer.ufrag),
          }),
        );
        peer.once("close", () => this.dialRoutes.delete(connectionId));
        const answer = await answerPromise;
        peer.setAnswer(answer);
      }
      return peer;
    } catch (e) {
      peer.close(e);
      throw e;
    }
  }

  #signUpstreamOffer(offer, player) {
    if (this.upstreamIdentity === "off") return offer;
    this.log("[upstream] offer carries a self-signed client a=identity (proxy key)");
    return signClientOffer(offer, this.proxyKey.privateKey, { xuid: player?.xuid, name: player?.name });
  }

  async #freshHostNonce() {
    if (this.upstream.type !== "lan") return undefined;
    const prevNetworkId = this.lanTarget.networkId;
    this.lanDialer.responses.delete(prevNetworkId);
    this.lanTarget = await this.lanDialer.discover({
      address: this.upstream.address,
      filter: (t) => t.networkId === prevNetworkId && t.networkId !== this.lanServer?.networkId,
    });
    return decodeServerData(this.lanTarget.applicationData).nonce;
  }

  async #refreshUpstreamInfo() {
    if (this.upstream.type === "http") {
      const info = await httpInfo(this.upstream.url);
      this.info = Object.assign({ ...DEFAULT_INFO }, info);
      const data = {
        serverName: this.info.name,
        protocol: this.info.protocol,
        version: this.info.version,
        levelName: this.info.level,
        gameType: this.info.gameType,
        playerCount: this.info.players,
        maxPlayerCount: this.info.maxPlayers,
        editorWorld: false,
        hardcore: false,
        acceptsOnlineAuth: false,
        acceptsSelfSignedAuth: true,
        nonce: crypto.randomBytes(8).toString("hex"),
        connectionType: 4,
      };
      this.lanAppData = encodeServerData(data);
    } else {
      this.lanTarget = await this.lanDialer.discover({
        address: this.upstream.address,
        filter: (t) => t.networkId !== this.lanServer?.networkId,
      });
      this.log(
        `[lan] found upstream ${this.lanTarget.address}:${this.lanTarget.port} (network ${this.lanTarget.networkId})`,
      );
      const onThisMachine = Object.values(os.networkInterfaces())
        .flat()
        .some((i) => i && i.address === this.lanTarget.address);
      if (onThisMachine && this.lanListen && (!this.lanBind || this.lanBind === this.lanTarget.address)) {
        throw new Error(
          `the upstream LAN world (${this.lanTarget.address}) is on THIS machine. The game and the proxy both use UDP 7551 for --listen-lan, so the proxy's signaling to the host loops back to itself. On the same PC use --listen-http <port> (players add this PC as a server by IP:port; RakNet no longer exists since 1.26.60), or --lan-bind <second local IP> (advanced), or run the proxy on another machine.`,
        );
      }
      this.lanAppData = this.lanTarget.applicationData;
      try {
        const data = decodeServerData(this.lanAppData);
        this.log("[lan] upstream ServerData", JSON.stringify(data));
        this.info = {
          ...DEFAULT_INFO,
          name: data.serverName,
          protocol: data.protocol,
          version: data.version,
          level: data.levelName,
          players: data.playerCount,
          maxPlayers: data.maxPlayerCount,
          gameType: data.gameType,
        };
        const advertised = { ...data, serverName: `${data.serverName} [proxy]` };
        this.lanAppData = encodeServerData(advertised);
      } catch (e) {
        this.log(`[lan] could not decode ServerData (${e.message}); advertising raw bytes`);
      }
    }
    if (this.lanServer && this.lanListen) this.lanServer.serverData = this.lanAppData;
  }

  #bridge(id, client, upstream) {
    const session = { id, client, upstream };
    this.sessions.add(session);
    this.hooks.onSession?.(session);

    const wire = (from, to, dirKey, label) => {
      from.on("packet", (kind, payload) => {
        let out = payload;
        if (this.hooks[dirKey]) {
          let r;
          try {
            r = this.hooks[dirKey](payload, { kind, session });
          } catch (e) {
            this.log(`[#${id}] hook ${dirKey} threw: ${e.message}`);
          }
          if (r == null) return;
          if (r) out = r;
        }
        if (this.dump) {
          this.log(
            `[#${id}] ${label} ${kind.padEnd(10)} ${String(out.length).padStart(6)}B ${out.subarray(0, 24).toString("hex")}`,
          );
        }
        to.send(kind, out);
      });
    };

    if (!this.raw) {
      const mitm = new MitmSession({
        id,
        client,
        upstream,
        proxyKey: this.proxyKey,
        hooks: this.hooks,
        dump: this.dump,
        log: this.log,
        getHostNonce: () => this.#freshHostNonce(),
        hostEncrypt: this.hostEncrypt,
        legacyLogin: this.loginLegacy,
        hostFrameHeader: this.frameHeader,
        playerFrameHeader: this.frameHeader,
        playerHandshake: "mirror",
        playerEncrypt: this.playerEncrypt,
      });
      Object.assign(session, { mitm });
      mitm.start();
    } else {
      wire(client, upstream, "serverbound", "C→S");
      wire(upstream, client, "clientbound", "S→C");
    }

    const done = (which) => (err) => {
      if (!this.sessions.delete(session)) return;
      this.log(`[#${id}] ${which} closed${err ? `: ${err.message ?? err}` : ""}`);
      client.close();
      upstream.close();
    };
    client.once("close", done("client"));
    upstream.once("close", done("upstream"));
    client.once("open", () => this.log(`[#${id}] client channels open`));
    upstream.once("open", () => this.log(`[#${id}] upstream channels open`));
  }

  async #loginAttempt(opts) {
    const { legacy, header, profile, encrypt, timeoutMs, loginRequestOverride, privateKeyOverride } = opts;
    let nonce;
    let version = this.info.version;
    let protocol = this.info.protocol;
    let serverAddress = "proxy";

    if (this.upstream.type === "lan") {
      this.lanDialer.responses.delete(this.lanTarget.networkId);
      this.lanTarget = await this.lanDialer.discover({
        address: this.upstream.address,
        filter: (t) => t.networkId !== this.lanServer?.networkId,
      });
      const sd = decodeServerData(this.lanTarget.applicationData);
      version = sd.version;
      protocol = sd.protocol;
      serverAddress = `${this.lanTarget.address}:${this.lanTarget.port}`;
      this.log(
        `[login] fresh host nonce ${sd.nonce} (protocol ${sd.protocol}, game ${sd.version}, selfSigned=${sd.acceptsSelfSignedAuth}, online=${sd.acceptsOnlineAuth})`,
      );
    }

    let upstream;
    try {
      upstream = await this.#connectUpstream("login");
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("data channels did not open")), 15000);
        upstream.once("open", () => {
          clearTimeout(timer);
          resolve();
        });
        upstream.once("close", (e) => {
          clearTimeout(timer);
          reject(e ?? new Error("closed before open"));
        });
      });
      this.log("[login] data channels open");

      let privateKey;
      let loginRequest;
      if (loginRequestOverride) {
        privateKey = privateKeyOverride;
        loginRequest = loginRequestOverride;
      } else {
        const kp = generateKeyPair();
        privateKey = kp.privateKey;
        const identity = { displayName: "MITMProbe", identity: crypto.randomUUID() };
        let clientData;
        if (profile === "go") {
          clientData = goStyleClientData({
            displayName: "MITMProbe",
            version,
            serverAddress: String(this.lanTarget?.networkId ?? serverAddress),
            nonce,
          });
        } else {
          clientData = defaultClientData({ displayName: "MITMProbe", version, serverAddress, nonce });
        }
        loginRequest = buildLoginRequest({ privateKey, legacy, identity, clientData });
      }
      this.log(`[login] login request ${loginRequest.length} bytes, protocol ${protocol}`);

      const client = new BedrockClient({
        protocol,
        loginRequest,
        privateKey,
        header,
        encrypt,
        log: this.log,
        send: (buf) => {
          this.log(`[login] -> reliable ${buf.length} bytes: ${buf.subarray(0, 16).toString("hex")}`);
          upstream.send("reliable", buf);
        },
      });

      let rawCount = 0;
      upstream.on("raw", (label, data) => {
        if (rawCount++ < 12)
          this.log(`[login] <- ${label} message ${data.length} bytes: ${data.subarray(0, 24).toString("hex")}`);
      });
      upstream.on("packet", (kind, data) => {
        if (kind === "reliable") client.receive(data);
      });

      const result = await new Promise((resolve) => {
        const hard = setTimeout(() => resolve({ result: "timeout" }), timeoutMs);
        const soft = setTimeout(() => resolve({ result: "no-reply" }), 6000);
        const done = (v) => {
          clearTimeout(hard);
          clearTimeout(soft);
          resolve(v);
        };
        upstream.once("raw", () => clearTimeout(soft));
        client.on("play_status", (s) => {
          this.log(`[login] PlayStatus = ${s}${s === 0 ? " (login success)" : ""}`);
          if (s === 0) setTimeout(() => done({ result: "ok" }), 1500);
          else done({ result: "play_status", status: s });
        });
        client.on("disconnect", (d) => {
          this.log(
            `[login] DISCONNECT reason=${d.reason} hidden=${d.hidden} message="${d.message}" raw=${d.hex}`,
          );
          done({ result: "disconnect", ...d });
        });
        client.on("violation", (v) => {
          this.log(
            `[login] PACKET VIOLATION type=${v.type} (0=malformed) severity=${v.severity} (2=terminating) packetId=${v.packetId} (1=Login)`,
          );
          this.log(`[login]   context: "${v.context}"`);
          this.log(`[login]   raw: ${v.hex}`);
          done({ result: "violation", ...v });
        });
        client.on("packet", (pid, payload) => {
          this.log(
            `[login] <- packet id ${pid}${pid === PACKET.RESOURCE_PACKS_INFO ? " (ResourcePacksInfo)" : ""} (${payload.length} bytes)`,
          );
        });
        client.on("error", (e) => {
          this.log(`[login] ERROR ${e.message}`);
          done({ result: "error", message: e.message });
        });
        upstream.once("close", (e) => done({ result: "closed", message: e?.message }));
        client.start();
      });
      this.log(`[login] result: ${JSON.stringify(result)} | traffic: ${JSON.stringify(upstream.stats)}`);
      return result;
    } catch (e) {
      this.log(`[login] FAILED: ${e.message}`);
      return { result: "failed", message: e.message };
    } finally {
      upstream?.close();
    }
  }
}

// ---- the host agent (relay registration + joiner acceptance) -------------

export class HostAgent extends EventEmitter {
  constructor(opts) {
    super();
    const id = normalizeId(opts.id);
    if (!ID_RE.test(id))
      throw new Error('id must be 3-32 characters: a-z, 0-9 and "-" (first character a letter or digit)');
    if (typeof opts.secret !== "string" || opts.secret.length < 8)
      throw new Error("secret must be at least 8 characters");

    this.urls = relayUrls(opts.relay);
    Object.assign(this, {
      id,
      secret: opts.secret,
      token: opts.token,
      maxSessions: opts.maxSessions ?? 8,
      proxy: opts.proxy,
      infoIntervalMs: opts.infoIntervalMs ?? 20000,
      log: opts.log ?? console.log,
    });
    this.joinKey = opts.password ? sha256hex(opts.password) : null;
    this.stopped = false;
    this.control = null;
    this.timer = null;
    this.online = false;
  }

  async start() {
    this.stopped = false;
    while (!this.stopped) {
      try {
        await this.proxy.start();
        break;
      } catch (e) {
        this.log(`[host] cannot reach the world yet: ${e.message} - retrying in 5 s`);
        await sleep(5000);
      }
    }
    this.#loop().catch((e) => this.log(`[host] stopped: ${e.message}`));
  }

  stop() {
    this.stopped = true;
    clearInterval(this.timer);
    try {
      this.control?.close();
    } catch {}
    this.proxy.stop?.();
  }

  async #incoming(msg) {
    const { sid, player, from } = msg;
    this.log(`[host] incoming joiner ${sid} from ${from}${player?.name ? ` ("${player.name}")` : ""}`);
    const ws = await connectWs(`${this.urls.ws}/accept`);
    try {
      sendJson(ws, { t: "accept", id: this.id, secret: this.secret, sid });
      const r = await firstJson(ws, 10000);
      if (r.t !== "ok") throw new Error(r.message ?? r.code ?? "relay did not accept the work connection");
    } catch (e) {
      try {
        ws.close();
      } catch {}
      throw e;
    }

    const tunnel = new TunnelPeer(ws, { name: `tun-${sid}`, log: this.log });
    if (this.proxy.sessionCount >= this.maxSessions) {
      sendJson(ws, { t: "fail", code: "host-full", message: "host is full" });
      tunnel.close(new Error("host full"));
      return;
    }
    try {
      await this.proxy.attachPeer(tunnel, { player, onReady: () => sendJson(ws, { t: "ready" }) });
    } catch (e) {
      sendJson(ws, {
        t: "fail",
        code: "host-unreachable",
        message: `the host could not reach the world: ${e.message}`.slice(0, 200),
      });
      tunnel.close(e);
    }
  }

  async #controlSession() {
    const ws = await connectWs(`${this.urls.ws}/host`);
    this.control = ws;
    let registered = false;
    try {
      sendJson(ws, {
        t: "register",
        id: this.id,
        secret: this.secret,
        token: this.token,
        joinKey: this.joinKey,
        maxSessions: this.maxSessions,
        info: this.proxy.info,
      });
      const r = await firstJson(ws, 10000);
      if (r.t !== "registered")
        throw new TunnelError(r.code ?? "relay-error", r.message ?? "registration refused");
      registered = true;
      this.online = true;
      this.log(`[host] online as "${this.id}" on ${this.urls.ws} - joiners connect with --id ${this.id}`);
      this.emit("online");

      ws.on("message", (data, isBinary) => {
        if (isBinary) return;
        let m;
        try {
          m = JSON.parse(data.toString());
        } catch {
          return;
        }
        if (m.t === "incoming") {
          this.#incoming(m).catch((e) => this.log(`[host] session ${m.sid} failed: ${e.message}`));
        }
      });

      this.timer = setInterval(async () => {
        try {
          const info = await this.proxy.refreshInfo();
          sendJson(ws, { t: "info", info });
        } catch (e) {
          this.log(`[host] info refresh failed: ${e.message}`);
        }
      }, this.infoIntervalMs);
      this.timer.unref?.();

      await new Promise((resolve) => ws.once("close", resolve));
    } finally {
      clearInterval(this.timer);
      this.online = false;
      try {
        ws.close();
      } catch {}
    }
    return registered;
  }

  async #loop() {
    let delay = 1000;
    while (!this.stopped) {
      try {
        const ok = await this.#controlSession();
        if (ok) delay = 1000;
      } catch (e) {
        if (e instanceof TunnelError && FATAL_CODES.has(e.code)) {
          this.log(`[host] relay refused this host: ${e.message}`);
          this.emit("fatal", e);
          this.stop();
          return;
        }
        this.log(`[host] relay connection failed: ${e.message}`);
      }
      if (this.stopped) return;
      this.log(`[host] reconnecting to the relay in ${Math.round(delay / 1000)} s`);
      await sleep(delay);
      delay = Math.min(delay * 2, 30000);
    }
  }
}

// ---- CLI -----------------------------------------------------------------

const HELP = `host-agent — publish your Minecraft LAN world (or BDS) through a relay. No port-forward needed.

  --relay <host[:port]>     relay address (ws://, wss:// also fine; default port 7000)
  --id <name>               the id joiners will type (3-32 chars: a-z 0-9 -)
  --secret <text>           proves the id is yours (default: generated once, kept in ./host-agent-state.json)
  --token <text>            the relay's host token, if it has one
  --password <text>         optional: joiners must give this password
  --max-players <n>         joiners at once (default 8)

World (pick one):
  --upstream-lan [ip|broadcast]   a LAN world on this network (default: broadcast discovery)
  --upstream-http <url>           BDS / any server with NetherNet HTTP signaling

Advanced (same meaning as in nethernet-mitm):
  --upstream-identity <auto|on|off>  --lan-dial-bind <ip>  --lan-signal-broadcast <on|off>  --bind <ip>
  --hooks <file.js>  --dump`;

const { values } = parseArgs({
  options: {
    relay: { type: "string" },
    id: { type: "string" },
    secret: { type: "string" },
    token: { type: "string" },
    password: { type: "string" },
    "max-players": { type: "string" },
    "upstream-lan": { type: "string" },
    "upstream-http": { type: "string" },
    "upstream-identity": { type: "string" },
    "lan-dial-bind": { type: "string" },
    "lan-signal-broadcast": { type: "string" },
    bind: { type: "string" },
    hooks: { type: "string" },
    dump: { type: "boolean" },
    "state-file": { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});

if (values.help || !values.relay || !values.id) {
  console.log(HELP);
  process.exit(values.help ? 0 : 1);
}

const stateFile = values["state-file"] ?? "./host-agent-state.json";
let secret = values.secret;
if (!secret) {
  let state = {};
  try {
    state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
  } catch {}
  const key = `${relayUrls(values.relay).ws}/${values.id.toLowerCase()}`;
  if (!state[key]) {
    state[key] = randomSecret();
    fs.mkdirSync(path.dirname(path.resolve(stateFile)), { recursive: true });
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2));
    console.log(
      `[host] created a secret for "${values.id}" and saved it in ${stateFile} - keep that file, it is what lets you reuse this id`,
    );
  }
  secret = state[key];
}

async function main() {
  let hooks = {};
  if (values.hooks) {
    hooks = await import(pathToFileURL(path.resolve(values.hooks)).href);
  }

  const upstream = values["upstream-http"]
    ? { type: "http", url: values["upstream-http"] }
    : {
        type: "lan",
        address:
          values["upstream-lan"] && values["upstream-lan"] !== "broadcast"
            ? values["upstream-lan"]
            : undefined,
      };

  const proxy = new NetherNetProxy({
    external: true,
    upstream,
    identity: null,
    hooks,
    dump: !!values.dump,
    bindAddress: values.bind,
    upstreamIdentity: values["upstream-identity"] ?? "auto",
    lanDialBind: values["lan-dial-bind"],
    lanSignalBroadcast: (values["lan-signal-broadcast"] ?? "on") !== "off",
  });

  const agent = new HostAgent({
    relay: values.relay,
    id: values.id,
    secret,
    token: values.token ?? process.env.RELAY_TOKEN,
    password: values.password,
    maxSessions: values["max-players"] ? Number(values["max-players"]) : 8,
    proxy,
  });
  agent.on("fatal", () => process.exit(1));
  await agent.start();
}

main().catch((e) => {
  console.error(e?.stack ?? e);
  process.exit(1);
});

process.on("SIGINT", () => {
  console.log("[exit] SIGINT");
  process.exit(130);
});
process.on("uncaughtException", (e) => {
  console.log("[exit] uncaught exception:", e?.stack ?? e);
  process.exit(1);
});
process.on("unhandledRejection", (e) => {
  console.log("[exit] unhandled rejection:", e?.stack ?? e);
});
