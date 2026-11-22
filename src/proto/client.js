// client.js — Bedrock client / login / batch-codec helpers (host side)
//
// Role: speaks the Bedrock batch framing (varint-length packets, flate
// compression, AES-256-CTR + sha256 checksum encryption), builds/parses the
// Login request and JWT chains, formats local ICE candidates and signs the
// NetherNet client offer identity. host.js require()s these helpers.
//
// CommonJS to match the proto/ folder (a CommonJS island). It uses node:crypto
// directly and does NOT require ../nethernet/identity.js (that module is ESM and
// cannot be required from CJS); the JWT / SDP-identity / ECDH helpers below
// duplicate identity.js logic — see the `// NOTE:` markers.

const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { EventEmitter } = require("node:events");
const protocol = require("./protocol.cjs");

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

const DEFAULT_VERSION = "1.26.60";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// ---- varint helpers --------------------------------------------------------

function readVaruint(buffer, offset) {
  let result = 0;
  for (let shift = 0; shift < 35; shift += 7) {
    if (offset >= buffer.length) throw new Error("varuint: unexpected end");
    const byte = buffer[offset++];
    result |= (byte & 0x7f) << shift;
    if (!(byte & 0x80)) return [result >>> 0, offset];
  }
  throw new Error("varuint: too long");
}

function writeVaruint(value) {
  const bytes = [];
  value = value >>> 0;
  while (value >= 0x80) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  bytes.push(value);
  return Buffer.from(bytes);
}

function zigzag(n) {
  return (n >>> 1) ^ -(n & 1);
}

// ---- base64url / JWT helpers (NOTE: duplicates identity.js) ----------------

function b64u(data) {
  return Buffer.from(data).toString("base64url");
}

function b64uJson(obj) {
  return b64u(JSON.stringify(obj));
}

function b64(data) {
  return Buffer.from(data).toString("base64");
}

function decodeJwt(jwt) {
  const [headerPart, claimsPart, signature] = jwt.split(".");
  return {
    header: JSON.parse(Buffer.from(headerPart, "base64url").toString()),
    claims: JSON.parse(Buffer.from(claimsPart, "base64url").toString()),
    signature,
    signingInput: `${headerPart}.${claimsPart}`,
  };
}

// NOTE: duplicates identity.js — ES384 JWT signing with raw (ieee-p1363) sig.
function signJwt(privateKey, header, payload) {
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const signature = crypto.sign("sha384", Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${b64u(signature)}`;
}

// NOTE: duplicates identity.js — raw ES384 signature over arbitrary bytes.
function es384(data, key) {
  return crypto.sign("sha384", Buffer.from(data), { key, dsaEncoding: "ieee-p1363" });
}

function publicKeyB64(privateKey) {
  const pub = crypto.createPublicKey(privateKey);
  return pub.export({ type: "spki", format: "der" }).toString("base64");
}

function generateKeyPair() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
}

// NOTE: duplicates identity.js — deterministic offline UUID from an XUID.
function xuidStorageUUID(xuid) {
  const digest = crypto.createHash("md5").update("pocket-auth-1-xuid:" + xuid).digest();
  digest[6] = (digest[6] & 15) | 48;
  digest[8] = (digest[8] & 63) | 128;
  const hex = digest.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isValidUUID(value) {
  return typeof value === "string" && UUID_RE.test(value);
}

// ---- SDP identity helpers (NOTE: duplicates identity.js) -------------------

function stripIdentity(sdp) {
  return sdp
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("a=identity:"))
    .join("\r\n");
}

function insertIdentity(sdp, identity) {
  const lines = stripIdentity(sdp).split(/\r?\n/);
  const mediaIndex = lines.findIndex((line) => line.startsWith("m="));
  const at = mediaIndex < 0 ? lines.length : mediaIndex;
  lines.splice(at, 0, `a=identity:${identity}`);
  return lines.join("\r\n");
}

function extractFingerprints(sdp) {
  const result = [];
  for (const line of sdp.split(/\r?\n/)) {
    const match = /^a=fingerprint:(\S+)\s+(\S+)/.exec(line);
    if (!match) continue;
    result.push({ algorithm: match[1], digest: match[2] });
  }
  return result;
}

function canonicalFingerprints(sdp) {
  const items = extractFingerprints(sdp).map(
    (fp) => `{"algorithm":${JSON.stringify(fp.algorithm)},"digest":${JSON.stringify(fp.digest)}}`,
  );
  return `{"fingerprint":[${items.join(",")}]}`;
}

// ---- server handshake (NOTE: duplicates identity.js server-handshake) ------

function parseServerHandshake(jwt) {
  const { header, claims } = decodeJwt(jwt);
  return {
    serverPublicKey: header.x5u,
    salt: Buffer.from(String(claims.salt).replace(/=+$/, ""), "base64"),
  };
}

// NOTE: duplicates identity.js — ECDH(secp384r1) then sha256(salt || shared).
function deriveSecretKey(privateKey, serverPublicKey, salt) {
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(serverPublicKey, "base64"),
    format: "der",
    type: "spki",
  });
  const shared = crypto.diffieHellman({ privateKey, publicKey });
  return crypto.createHash("sha256").update(salt).update(shared).digest();
}

// ---- server->client packet parsers -----------------------------------------

function parsePacketViolation(payload) {
  try {
    let offset = 0;
    let value;
    [value, offset] = readVaruint(payload, 0);
    const type = zigzag(value);
    [value, offset] = readVaruint(payload, offset);
    const severity = zigzag(value);
    [value, offset] = readVaruint(payload, offset);
    const packetId = zigzag(value);
    let length;
    [length, offset] = readVaruint(payload, offset);
    return {
      type,
      severity,
      packetId,
      context: payload.toString("utf8", offset, offset + length),
      hex: payload.toString("hex"),
    };
  } catch (err) {
    return {
      type: null,
      severity: null,
      packetId: null,
      context: `(unparsed: ${err.message})`,
      hex: payload.toString("hex"),
    };
  }
}

function parseDisconnect(payload) {
  try {
    let offset = 0;
    let value;
    [value, offset] = readVaruint(payload, 0);
    const reason = zigzag(value);
    const hidden = !(payload[offset++] === 0);
    let message = "";
    if (!hidden) {
      if (offset < payload.length) {
        let length;
        [length, offset] = readVaruint(payload, offset);
        message = payload.toString("utf8", offset, offset + length);
      }
    }
    return { reason, hidden, message, hex: payload.toString("hex") };
  } catch (err) {
    return {
      reason: null,
      hidden: false,
      message: `(unparsed: ${err.message})`,
      hex: payload.toString("hex"),
    };
  }
}

// ---- login request (build) -------------------------------------------------

function buildLoginRequest(opts) {
  const legacy = opts.legacy ?? false;
  const x5u = publicKeyB64(opts.privateKey);
  const header = { alg: "ES384", x5u };
  const now = Math.floor(Date.now() / 1000);
  const notBefore = now - 21600;
  const expires = now + 21600;
  const xuid = opts.identity.xuid ?? "";

  let chainJson;
  if (legacy) {
    const token = signJwt(opts.privateKey, header, {
      nbf: notBefore,
      exp: expires,
      extraData: {
        XUID: xuid,
        identity: opts.identity.identity,
        displayName: opts.identity.displayName,
      },
      identityPublicKey: x5u,
    });
    chainJson = JSON.stringify({ chain: [token] });
  } else {
    const token = signJwt(opts.privateKey, header, {
      aud: "api://auth-minecraft-services/multiplayer",
      nbf: notBefore,
      exp: expires,
      ipt: "",
      mid: "",
      tid: "",
      cpk: x5u,
      xid: xuid,
      xname: opts.identity.displayName,
      ...(opts.identity.identity ? { leguuid: opts.identity.identity } : {}),
    });
    chainJson = JSON.stringify({
      Certificate: JSON.stringify({ chain: [""] }),
      AuthenticationType: 2,
      Token: token,
    });
  }

  const clientToken = signJwt(opts.privateKey, header, opts.clientData);
  const chainBuf = Buffer.from(chainJson);
  const clientBuf = Buffer.from(clientToken);
  const chainLen = Buffer.alloc(4);
  const clientLen = Buffer.alloc(4);
  chainLen.writeInt32LE(chainBuf.length);
  clientLen.writeInt32LE(clientBuf.length);
  return Buffer.concat([chainLen, chainBuf, clientLen, clientBuf]);
}

// ---- login request (parse) -------------------------------------------------

function parseLoginRequestBytes(buffer) {
  const chainLength = buffer.readInt32LE(0);
  if (chainLength <= 0) throw new Error(`invalid chain length: ${chainLength}`);
  const chainJson = buffer.toString("utf8", 4, 4 + chainLength);
  const parsed = JSON.parse(chainJson);
  const tokenLength = buffer.readInt32LE(4 + chainLength);
  const tokenStart = 4 + chainLength + 4;
  const rawToken = buffer.toString("utf8", tokenStart, tokenStart + tokenLength);
  if (tokenStart + tokenLength !== buffer.length) {
    throw new Error(`${buffer.length - (tokenStart + tokenLength)} unread bytes after login request`);
  }

  let chain;
  if (typeof parsed.Certificate === "string") {
    const certificate = JSON.parse(parsed.Certificate);
    chain = certificate.chain ?? [];
  } else {
    chain = parsed.Certificate?.Chain ?? parsed.chain ?? [];
  }

  return {
    chain,
    authenticationType: parsed.AuthenticationType,
    token: parsed.Token,
    rawToken,
  };
}

function extractClientData(rawToken) {
  const { claims } = decodeJwt(rawToken);
  const data = { ...claims };
  delete data.nbf;
  delete data.exp;
  delete data.iat;
  delete data.aud;
  delete data.iss;
  return data;
}

function extractIdentityData(request) {
  if (request.token) {
    const { claims } = decodeJwt(request.token);
    let identity = claims.leguuid || "";
    if (!identity) {
      identity = claims.xid ? xuidStorageUUID(claims.xid) : crypto.randomUUID();
    }
    return {
      XUID: claims.xid ?? "",
      DisplayName: claims.xname ?? "",
      Identity: identity,
      PlayFabID: claims.mid ?? "",
      PlayFabTitleID: claims.tid ?? "",
      TitleID: "",
    };
  }

  if (request.chain?.length) {
    // Player identity comes from the last JWT in the chain.
    const extraData = decodeJwt(request.chain[request.chain.length - 1]).claims.extraData ?? {};
    return {
      XUID: extraData.XUID ?? "",
      DisplayName: extraData.displayName ?? extraData.DisplayName ?? "",
      Identity: extraData.identity ?? extraData.Identity ?? "",
      PlayFabID: "",
      PlayFabTitleID: "",
      TitleID: extraData.titleId ?? "",
    };
  }

  throw new Error("login request has neither Token nor a certificate chain");
}

function parsePlayerLogin(buffer, opts = {}) {
  const wrapped = opts.wrapped ?? true;
  let payload = buffer;
  let clientProtocol;
  if (wrapped) {
    clientProtocol = buffer.readInt32BE(0);
    const [length, offset] = readVaruint(buffer, 4);
    payload = buffer.subarray(offset, offset + length);
  }
  const request = parseLoginRequestBytes(payload);
  const identityData = extractIdentityData(request);
  const clientData = extractClientData(request.rawToken);
  const { header } = decodeJwt(request.rawToken);
  return {
    clientProtocol,
    identityData,
    clientData,
    publicKey: header.x5u,
    authenticationType: request.authenticationType,
  };
}

// ---- client data presets ---------------------------------------------------

function goStyleClientData(opts) {
  const skinResourcePatch = { geometry: { default: "geometry.humanoid.custom" } };
  const skinGeometry = {
    format_version: "1.12.0",
    "minecraft:geometry": [
      {
        description: {
          identifier: "geometry.humanoid.custom",
          texture_width: 64,
          texture_height: 32,
          visible_bounds_width: 2,
          visible_bounds_height: 3,
          visible_bounds_offset: [0, 1.5, 0],
        },
        bones: [
          { name: "root", pivot: [0, 0, 0] },
          {
            name: "body",
            parent: "root",
            pivot: [0, 24, 0],
            cubes: [{ origin: [-4, 12, -2], size: [8, 12, 4], uv: [16, 16] }],
          },
          {
            name: "head",
            parent: "body",
            pivot: [0, 24, 0],
            cubes: [{ origin: [-4, 24, -4], size: [8, 8, 8], uv: [0, 0] }],
          },
        ],
      },
    ],
  };

  const skinData = Buffer.alloc(8192);
  for (let i = 0; i < skinData.length; i += 4) {
    skinData[i + 3] = 255;
  }

  const data = {
    AnimatedImageData: [],
    CapeData: "",
    CapeId: "",
    CapeImageHeight: 0,
    CapeImageWidth: 0,
    CapeOnClassicSkin: false,
    ClientRandomId: null,
    CurrentInputMode: 2,
    DefaultInputMode: 2,
    DeviceModel: "",
    DeviceOS: 1,
    DeviceId: null,
    GameVersion: null,
    GuiScale: 0,
    FilterProfanity: false,
    ClientEditorConnectionIntent: 0,
    ClientIsEditorCapable: false,
    LanguageCode: "en_GB",
    PersonaSkin: false,
    PlatformOfflineId: "",
    PlatformOnlineId: "",
    PremiumSkin: false,
    SelfSignedId: null,
    ServerAddress: null,
    SkinAnimationData: "",
    SkinData: null,
    SkinGeometryData: null,
    SkinGeometryDataEngineVersion: null,
    SkinId: null,
    PlayFabId: null,
    SkinImageHeight: 32,
    SkinImageWidth: 64,
    SkinResourcePatch: null,
    SkinColor: "",
    ArmSize: "",
    PersonaPieces: [],
    PieceTintColors: [],
    ThirdPartyName: null,
    UIProfile: 0,
    TrustedSkin: false,
    OverrideSkin: false,
    CompatibleWithClientSideChunkGen: false,
    MaxViewDistance: 0,
    MemoryTier: 0,
    PlatformType: 0,
    GraphicsMode: 0,
    PartyId: "",
    IsPartyLeader: false,
    ProfileHash: "",
  };

  data.ClientRandomId = Number(crypto.randomBytes(6).readUIntBE(0, 6));
  data.DeviceId = crypto.randomBytes(16).toString("hex");
  data.GameVersion = opts.version;
  data.SelfSignedId = crypto.randomUUID();
  data.ServerAddress = opts.serverAddress;
  data.SkinData = skinData.toString("base64");
  data.SkinGeometryData = b64(JSON.stringify(skinGeometry));
  data.SkinGeometryDataEngineVersion = b64("0.0.0");
  data.SkinId = crypto.randomUUID();
  data.PlayFabId = crypto.randomBytes(8).toString("hex");
  data.SkinResourcePatch = b64(JSON.stringify(skinResourcePatch));
  data.ThirdPartyName = opts.displayName;
  if (opts.nonce !== undefined) {
    data.Nonce = opts.nonce;
  }
  return data;
}

function defaultClientData(opts) {
  const data = {
    AnimatedImageData: [],
    ArmSize: "wide",
    CapeData: "",
    CapeId: "",
    CapeImageHeight: 0,
    CapeImageWidth: 0,
    CapeOnClassicSkin: false,
    ClientRandomId: null,
    ClientEditorConnectionIntent: 0,
    ClientIsEditorCapable: false,
    CompatibleWithClientSideChunkGen: false,
    CurrentInputMode: 1,
    DefaultInputMode: 1,
    FilterProfanity: false,
    DeviceId: null,
    DeviceModel: "nethernet-mitm",
    DeviceOS: 7,
    GameVersion: null,
    GraphicsMode: 1,
    GuiScale: 0,
    IsPartyLeader: false,
    LanguageCode: "en_US",
    MaxViewDistance: 0,
    MemoryTier: 0,
    OverrideSkin: false,
    PartyId: "",
    PlatformType: 0,
    ProfileHash: "",
    PersonaPieces: [],
    PersonaSkin: false,
    PieceTintColors: [],
    PlatformOfflineId: "",
    PlatformOnlineId: "",
    PlayFabId: "",
    PremiumSkin: false,
    SelfSignedId: null,
    ServerAddress: null,
    SkinAnimationData: "",
    SkinColor: "#0",
    SkinData: null,
    SkinGeometryData: "",
    SkinGeometryDataEngineVersion: null,
    SkinId: null,
    SkinImageHeight: 64,
    SkinImageWidth: 64,
    SkinResourcePatch: null,
    ThirdPartyName: null,
    ThirdPartyNameOnly: false,
    TrustedSkin: true,
    UIProfile: 0,
  };

  data.ClientRandomId = Number(crypto.randomBytes(6).readUIntBE(0, 6));
  data.DeviceId = crypto.randomUUID();
  data.GameVersion = opts.version;
  data.SelfSignedId = opts.selfSignedId ?? crypto.randomUUID();
  data.ServerAddress = opts.serverAddress;
  data.SkinData = Buffer.alloc(16384, 255).toString("base64");
  data.SkinGeometryDataEngineVersion = Buffer.from("1.14.60").toString("base64");
  data.SkinId = `${crypto.randomUUID()}.Custom`;
  data.SkinResourcePatch = Buffer.from(
    JSON.stringify({ geometry: { default: "geometry.humanoid.custom" } }),
  ).toString("base64");
  data.ThirdPartyName = opts.displayName;
  if (opts.nonce !== undefined) {
    data.Nonce = opts.nonce;
  }
  return data;
}

// ---- relayed login ---------------------------------------------------------

function pickSelfSignedId(identityData, clientData, offline) {
  if (offline) {
    if (isValidUUID(clientData.SelfSignedId)) {
      return { id: clientData.SelfSignedId, source: "client(offline)" };
    }
    if (isValidUUID(identityData.Identity)) {
      return { id: identityData.Identity, source: "identity(offline)" };
    }
    return { id: "", source: "none" };
  }
  if (identityData.XUID) {
    return { id: xuidStorageUUID(identityData.XUID), source: "xuid" };
  }
  if (isValidUUID(identityData.Identity)) {
    return { id: identityData.Identity, source: "identity" };
  }
  if (isValidUUID(clientData.SelfSignedId)) {
    return { id: clientData.SelfSignedId, source: "client" };
  }
  return { id: "", source: "none" };
}

function buildRelayedLogin(opts) {
  const offline = opts.offline ?? true;
  const legacy = opts.legacy ?? false;
  const log = opts.log ?? (() => {});

  const identityData = offline
    ? { ...opts.identityData, XUID: "" }
    : opts.identityData;
  const clientData = { ...opts.clientData, Nonce: opts.hostNonce };

  const picked = pickSelfSignedId(identityData, clientData, offline);
  if (picked.id) {
    clientData.SelfSignedId = picked.id;
    log(`[relay] SelfSignedId pinned: ${picked.id} (source=${picked.source})`);
  } else {
    log("[relay] could not pin a SelfSignedId — this session will not persist inventory/position on the host");
  }

  return buildLoginRequest({
    privateKey: opts.proxyPrivateKey,
    legacy,
    identity: {
      displayName: identityData.DisplayName,
      identity: identityData.Identity,
      xuid: identityData.XUID,
    },
    clientData,
  });
}

// ---- NetherNet client offer identity (NOTE: duplicates identity.js) --------

function signClientOffer(offerSdp, privateKey, opts = {}) {
  const domain = opts.domain ?? "self";
  const ttlSec = opts.ttlSec ?? 3600;
  const xuid = opts.xuid;
  const name = opts.name;

  const publicKeyDerB64 = crypto
    .createPublicKey(privateKey)
    .export({ type: "spki", format: "der" })
    .toString("base64");
  const now = Math.floor(Date.now() / 1000);

  const tokenHeader = b64uJson({ alg: "ES384", x5u: publicKeyDerB64 });
  const tokenPayload = b64uJson({
    cpk: publicKeyDerB64,
    ...(xuid ? { xid: String(xuid), xname: name ?? "" } : {}),
    exp: now + ttlSec,
    iat: now,
  });
  const tokenSigningInput = `${tokenHeader}.${tokenPayload}`;
  const token = `${tokenHeader}.${tokenPayload}.${b64u(es384(tokenSigningInput, privateKey))}`;

  const fingerprintHeader = b64uJson({ alg: "ES384" });
  const fingerprintSigningInput = `${fingerprintHeader}.${b64u(canonicalFingerprints(offerSdp))}`;
  const fingerprints = `${fingerprintHeader}..${b64u(es384(fingerprintSigningInput, privateKey))}`;

  const assertion = JSON.stringify({ fingerprints, token });
  const identity = JSON.stringify({ assertion, idp: { domain, protocol: "default" } });
  return insertIdentity(offerSdp, Buffer.from(identity).toString("base64"));
}

// ---- protocol packet (de)serialization tools -------------------------------

function packetTools(version = DEFAULT_VERSION) {
  const cached = packetTools.cache.get(version);
  if (cached) return cached;

  const def = protocol.load(version);
  const tools = {
    version,
    name: (id) => def.names.get(id),
    id: (name) => def.ids.get(name),
    warmup: () => {
      protocol.compiled(def);
    },
    decode: (id, payload) => {
      const parser = protocol.compiled(def).parser;
      const buffer = Buffer.concat([writeVaruint(id), payload]);
      const parsed = parser.parsePacketBuffer(buffer);
      if (!parsed?.data) {
        throw new Error(`cannot decode ${def.names.get(id) ?? id}`);
      }
      return parsed.data.params;
    },
    encode: (name, params) => {
      if (def.ids.get(name) === undefined) {
        throw new Error(`unknown packet name "${name}"`);
      }
      const serializer = protocol.compiled(def).serializer;
      const buffer = serializer.createPacketBuffer({ name, params });
      const [id, size] = readVaruint(buffer, 0);
      return { id, payload: buffer.subarray(size) };
    },
  };
  packetTools.cache.set(version, tools);
  return tools;
}
packetTools.cache = new Map();

// ---- local ICE candidate formatting ----------------------------------------

function formatLocalCandidate(candidate, ufrag, networkId = 1) {
  let line = candidate.replace(/^a=/, "").trim();
  const parts = line.split(/\s+/);
  if (parts[2]) {
    parts[2] = parts[2].toLowerCase();
  }
  line = parts.join(" ");
  if (!/\sgeneration\s/.test(line)) {
    line = line + " generation 0";
  }
  if (!/\sufrag\s/.test(line)) {
    line = line + ` ufrag ${ufrag}`;
  }
  if (!/\snetwork-id\s/.test(line)) {
    line = line + ` network-id ${networkId}` + " network-cost 0";
  }
  return line;
}

// ---- AES-256-CTR packet cipher ---------------------------------------------

class PacketCipher {
  constructor(secretKey) {
    if (secretKey.length !== 32) {
      throw new Error("secret key must be 32 bytes");
    }
    this.key = secretKey;
    const iv = Buffer.concat([secretKey.subarray(0, 12), Buffer.from([0, 0, 0, 2])]);
    this.enc = crypto.createCipheriv("aes-256-ctr", secretKey, iv);
    this.dec = crypto.createDecipheriv("aes-256-ctr", secretKey, iv);
    this.sendCounter = 0n;
    this.recvCounter = 0n;
  }

  encrypt(data) {
    const checksum = this.#checksum(this.sendCounter, data);
    this.sendCounter = this.sendCounter + 1n;
    return this.enc.update(Buffer.concat([data, checksum]));
  }

  decrypt(data) {
    const out = this.dec.update(data);
    if (out.length < 8) {
      throw new Error("encrypted packet shorter than checksum");
    }
    const body = out.subarray(0, out.length - 8);
    const got = out.subarray(out.length - 8);
    const want = this.#checksum(this.recvCounter, body);
    this.recvCounter = this.recvCounter + 1n;
    if (!crypto.timingSafeEqual(got, want)) {
      throw new Error("packet checksum mismatch");
    }
    return body;
  }

  // Counters are BigInt: writeBigUInt64LE below strictly requires one.
  #checksum(counter, data) {
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64LE(counter);
    return crypto
      .createHash("sha256")
      .update(counterBuf)
      .update(data)
      .update(this.key)
      .digest()
      .subarray(0, 8);
  }
}

// ---- Bedrock batch codec ----------------------------------------------------

class BatchCodec {
  constructor(opts = {}) {
    this.header = opts.header ?? true;
    this.compression = null;
    this.cipher = null;
  }

  enableCompression(threshold, algorithm) {
    if (algorithm !== 0) {
      throw new Error(`compression algorithm ${algorithm} not supported (only 0 = flate)`);
    }
    this.compression = { threshold, algorithm };
  }

  enableEncryption(secretKey) {
    this.cipher = new PacketCipher(secretKey);
  }

  encode(packets) {
    let buffer = Buffer.concat(
      packets.map((packet) => {
        const id = packet.header ?? packet.id;
        const idBuf = writeVaruint(id);
        return Buffer.concat([
          writeVaruint(idBuf.length + packet.payload.length),
          idBuf,
          packet.payload,
        ]);
      }),
    );

    if (this.compression) {
      if (buffer.length >= this.compression.threshold) {
        buffer = Buffer.concat([Buffer.from([0]), zlib.deflateRawSync(buffer)]);
      } else {
        buffer = Buffer.concat([Buffer.from([255]), buffer]);
      }
    }

    if (this.cipher) {
      buffer = this.cipher.encrypt(buffer);
    }

    if (this.header) {
      return Buffer.concat([Buffer.from([254]), buffer]);
    }
    return buffer;
  }

  decode(data, opts = {}) {
    const withHeader = opts.withHeader ?? false;

    if (this.header) {
      if (data[0] !== 254) {
        throw new Error(`bad batch header 0x${data[0]?.toString(16)}`);
      }
    }

    let buffer = this.header ? data.subarray(1) : data;

    if (this.cipher) {
      buffer = this.cipher.decrypt(buffer);
    }

    if (this.compression) {
      const compressionId = buffer[0];
      if (compressionId === 0) {
        buffer = zlib.inflateRawSync(buffer.subarray(1));
      } else if (compressionId === 255) {
        buffer = buffer.subarray(1);
      } else {
        throw new Error(`unsupported compression id ${compressionId}`);
      }
    }

    const packets = [];
    let offset = 0;
    while (offset < buffer.length) {
      let length;
      [length, offset] = readVaruint(buffer, offset);
      if (offset + length > buffer.length) {
        throw new Error("packet length overflows batch");
      }
      const frame = buffer.subarray(offset, offset + length);
      offset += length;
      const [id, idSize] = readVaruint(frame, 0);
      if (withHeader) {
        packets.push({ id: id & 1023, header: id, payload: frame.subarray(idSize) });
      } else {
        packets.push({ id: id & 1023, payload: frame.subarray(idSize) });
      }
    }
    return packets;
  }
}

// ---- Bedrock client ---------------------------------------------------------

class BedrockClient extends EventEmitter {
  constructor(opts) {
    super();
    const header = opts.header ?? true;
    const encrypt = opts.encrypt ?? true;
    const log = opts.log ?? (() => {});
    Object.assign(this, {
      protocol: opts.protocol,
      loginRequest: opts.loginRequest,
      privateKey: opts.privateKey,
      rawSend: opts.send,
      encrypt,
      log,
    });
    this.codec = new BatchCodec({ header });
  }

  start() {
    const buffer = Buffer.alloc(4);
    buffer.writeInt32BE(this.protocol);
    this.#send(PACKET.REQUEST_NETWORK_SETTINGS, buffer);
  }

  receive(data) {
    let packets;
    try {
      packets = this.codec.decode(data);
    } catch (err) {
      this.emit("error", err);
      return;
    }
    for (const packet of packets) {
      try {
        this.#handle(packet);
      } catch (err) {
        this.emit("error", err);
      }
    }
  }

  #send(id, payload) {
    const encoded = this.codec.encode([{ id, payload }]);
    this.rawSend(encoded);
  }

  #handle(packet) {
    switch (packet.id) {
      case PACKET.NETWORK_SETTINGS: {
        const threshold = packet.payload.readUInt16LE(0);
        const algorithm = packet.payload.readUInt16LE(2);
        this.log(`[bedrock] NetworkSettings: threshold=${threshold} algorithm=${algorithm}`);
        this.codec.enableCompression(threshold, algorithm);
        const protocolBuf = Buffer.alloc(4);
        protocolBuf.writeInt32BE(this.protocol);
        const login = Buffer.concat([
          protocolBuf,
          writeVaruint(this.loginRequest.length),
          this.loginRequest,
        ]);
        this.#send(PACKET.LOGIN, login);
        break;
      }
      case PACKET.SERVER_TO_CLIENT_HANDSHAKE: {
        const [length, offset] = readVaruint(packet.payload, 0);
        const jwt = packet.payload.toString("utf8", offset, offset + length);
        const { serverPublicKey, salt } = parseServerHandshake(jwt);
        if (this.encrypt) {
          const key = deriveSecretKey(this.privateKey, serverPublicKey, salt);
          this.codec.enableEncryption(key);
          this.log("[bedrock] encryption enabled");
          this.emit("encrypted");
        } else {
          this.log("[bedrock] handshake received, AES NOT enabled (transport-level encryption assumed)");
        }
        this.#send(PACKET.CLIENT_TO_SERVER_HANDSHAKE, Buffer.alloc(0));
        break;
      }
      case PACKET.PLAY_STATUS: {
        this.emit("play_status", packet.payload.readInt32BE(0));
        break;
      }
      case PACKET.DISCONNECT: {
        this.emit("disconnect", parseDisconnect(packet.payload));
        break;
      }
      case PACKET.PACKET_VIOLATION_WARNING: {
        this.emit("violation", parsePacketViolation(packet.payload));
        break;
      }
      default:
        this.emit("packet", packet.id, packet.payload);
    }
  }
}

module.exports = { BedrockClient, BatchCodec, packetTools, formatLocalCandidate, buildRelayedLogin, parsePlayerLogin, goStyleClientData, defaultClientData, buildLoginRequest, generateKeyPair, readVaruint, writeVaruint, signClientOffer };
