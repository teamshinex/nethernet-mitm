// identity.js — NetherNet server identity + SDP identity/fingerprint helpers
//
// Role: the local NetherNet "server" presents an ECDSA P-384 (ES384)
// identity. An SDP answer carries an `a=identity:` attribute built from a
// detached JWS over the canonical fingerprint list plus a self-signed JWT.
// The host-side bedrock handshake helpers (JWT sign/verify, ECDH key
// derivation, login-identity extraction, and the LAN "ServerData" struct
// codec) live here too.

import crypto from "node:crypto";
import fs from "node:fs";

// ---- base64url helpers ----------------------------------------------------

export function b64u(data) {
  return Buffer.from(data).toString("base64url");
}

export function b64uJson(obj) {
  return b64u(JSON.stringify(obj));
}

// ---- ECDSA P-384 server identity ------------------------------------------

export class ServerIdentity {
  constructor(opts = {}) {
    const keyPath = opts.keyPath ?? "./identity-key.pem";
    const domain = opts.domain ?? "nethernet-mitm.local";
    const issuer = opts.issuer ?? "nethernet-mitm";
    this.domain = domain;
    this.issuer = issuer;

    if (keyPath && fs.existsSync(keyPath)) {
      this.privateKey = crypto.createPrivateKey(fs.readFileSync(keyPath));
    } else {
      const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
      this.privateKey = privateKey;
      if (keyPath) {
        fs.writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      }
    }

    this.publicJwk = crypto.createPublicKey(this.privateKey).export({ format: "jwk" });
  }

  get keyFingerprint() {
    return crypto.createHash("sha256").update(JSON.stringify(this.publicJwk)).digest("hex");
  }

  #sign(data) {
    return crypto.sign("sha384", Buffer.from(data), { key: this.privateKey, dsaEncoding: "ieee-p1363" });
  }

  #token() {
    const now = Math.floor(Date.now() / 1000);
    const header = b64uJson({ alg: "ES384", typ: "JWT" });
    const payload = b64uJson({ iss: this.issuer, iat: now, exp: now + 604800, cpk: this.publicJwk });
    const signature = b64u(this.#sign(`${header}.${payload}`));
    return `${header}.${payload}.${signature}`;
  }

  assertionFor(sdp) {
    const header = b64uJson({ alg: "ES384" });
    const payload = b64u(canonicalFingerprints(sdp));
    // Detached JWS: the payload segment is signed but left empty in the token.
    const signature = b64u(this.#sign(`${header}.${payload}`));
    const fingerprints = `${header}..${signature}`;
    const assertion = JSON.stringify({ token: this.#token(), fingerprints });
    const envelope = { idp: { domain: this.domain, protocol: "default" }, assertion };
    return Buffer.from(JSON.stringify(envelope)).toString("base64");
  }

  sign(sdp) {
    return insertIdentity(sdp, this.assertionFor(sdp));
  }
}

// ---- SDP identity / fingerprint helpers -----------------------------------

export function inspectIdentity(sdp) {
  const attr = getIdentityAttr(sdp);
  if (!attr) return null;
  try {
    const envelope = JSON.parse(Buffer.from(attr, "base64").toString("utf8"));
    const assertion = typeof envelope.assertion === "string" ? JSON.parse(envelope.assertion) : envelope.assertion;
    const payload = assertion.token.split(".")[1];
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return { idp: envelope.idp, claims };
  } catch (err) {
    return { error: err.message };
  }
}

export function insertIdentity(sdp, identity) {
  const lines = stripIdentity(sdp).split(/\r?\n/);
  const mIndex = lines.findIndex((line) => line.startsWith("m="));
  const at = mIndex < 0 ? lines.length : mIndex;
  lines.splice(at, 0, `a=identity:${identity}`);
  return lines.join("\r\n");
}

export function stripIdentity(sdp) {
  return sdp
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("a=identity:"))
    .join("\r\n");
}

export function getIdentityAttr(sdp) {
  const m = /^a=identity:(\S+)/.exec(sdp);
  return m ? m[1] : null;
}

export function canonicalFingerprints(sdp) {
  const items = extractFingerprints(sdp).map(
    (fp) => `{"algorithm":${JSON.stringify(fp.algorithm)},"digest":${JSON.stringify(fp.digest)}}`,
  );
  return `{"fingerprint":[${items.join(",")}]}`;
}

export function extractFingerprints(sdp) {
  const out = [];
  for (const line of sdp.split(/\r?\n/)) {
    const m = /^a=fingerprint:(\S+)\s+(\S+)/.exec(line);
    if (!m) continue;
    out.push({ algorithm: m[1], digest: m[2] });
  }
  return out;
}

// ---- host-side bedrock handshake (JWT / ECDH) -----------------------------

export function decodeJwt(jwt) {
  const [header, claims, signature] = jwt.split(".");
  return {
    header: JSON.parse(Buffer.from(header, "base64url").toString()),
    claims: JSON.parse(Buffer.from(claims, "base64url").toString()),
    signature,
    signingInput: `${header}.${claims}`,
  };
}

export function signJwt(privateKey, header, claims) {
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
  const signature = crypto.sign("sha384", Buffer.from(signingInput), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${signingInput}.${b64u(signature)}`;
}

export function publicKeyB64(key) {
  return crypto.createPublicKey(key).export({ type: "spki", format: "der" }).toString("base64");
}

export function deriveSecretKey(privateKey, peerPublicKey, salt) {
  const publicKey = crypto.createPublicKey({ key: Buffer.from(peerPublicKey, "base64"), format: "der", type: "spki" });
  const shared = crypto.diffieHellman({ privateKey, publicKey });
  return crypto.createHash("sha256").update(salt).update(shared).digest();
}

export function xuidStorageUUID(xuid) {
  const hash = crypto.createHash("md5").update(`pocket-auth-1-xuid:${xuid}`).digest();
  hash[6] = (hash[6] & 15) | 48;
  hash[8] = (hash[8] & 63) | 128;
  const hex = hash.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function extractIdentityData(login) {
  if (login.token) {
    const { claims } = decodeJwt(login.token);
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
  if (login.chain?.length) {
    const { claims } = decodeJwt(login.chain[login.chain.length - 1]);
    const extra = claims.extraData ?? {};
    return {
      XUID: extra.XUID ?? "",
      DisplayName: extra.displayName ?? extra.DisplayName ?? "",
      Identity: extra.identity ?? extra.Identity ?? "",
      PlayFabID: "",
      PlayFabTitleID: "",
      TitleID: extra.titleId ?? "",
    };
  }
  throw new Error("login request has neither Token nor a certificate chain");
}

export function createServerHandshake(privateKey, clientPublicKey) {
  const salt = crypto.randomBytes(16);
  const header = { alg: "ES384", x5u: publicKeyB64(privateKey) };
  const payload = { salt: salt.toString("base64").replace(/=+$/, "") };
  const jwt = signJwt(privateKey, header, payload);
  return { jwt, key: deriveSecretKey(privateKey, clientPublicKey, salt) };
}

export function parseServerHandshake(jwt) {
  const { header, claims } = decodeJwt(jwt);
  return {
    serverPublicKey: header.x5u,
    salt: Buffer.from(String(claims.salt).replace(/=+$/, ""), "base64"),
  };
}

// ---- NetherNet LAN "ServerData" struct codec ------------------------------

export function decodeServerData(buf) {
  let pos = 0;
  const byte = () => {
    if (pos >= buf.length) throw new Error("serverdata: eof");
    return buf[pos++];
  };
  const varu = () => {
    let value = 0;
    for (let shift = 0; shift < 35; shift += 7) {
      const b = byte();
      value |= (b & 127) << shift;
      if (!(b & 128)) return value >>> 0;
    }
    throw new Error("serverdata: varuint too long");
  };
  const vari = () => {
    const n = varu();
    return (n >>> 1) ^ -(n & 1);
  };
  const str = () => {
    const len = varu();
    if (pos + len > buf.length) throw new Error("serverdata: string overflow");
    const s = buf.toString("utf8", pos, pos + len);
    pos += len;
    return s;
  };

  const version = byte();
  if (version !== 7) throw new Error(`serverdata: unsupported version ${version}`);
  return {
    serverName: str(),
    protocol: vari(),
    version: str(),
    levelName: str(),
    playerCount: vari(),
    maxPlayerCount: vari(),
    gameType: vari(),
    editorWorld: !!byte(),
    hardcore: !!byte(),
    acceptsOnlineAuth: !!byte(),
    acceptsSelfSignedAuth: !!byte(),
    nonce: str(),
    connectionType: vari(),
  };
}

export function encodeServerData(data) {
  const wVaru = (n) => {
    const out = [];
    n >>>= 0;
    while (n >= 128) {
      out.push((n & 127) | 128);
      n >>>= 7;
    }
    out.push(n);
    return Buffer.from(out);
  };
  const wVari = (n) => wVaru(((n << 1) ^ (n >> 31)) >>> 0);
  const wStr = (s) => {
    const b = Buffer.from(s, "utf8");
    return Buffer.concat([wVaru(b.length), b]);
  };
  const wBool = (b) => Buffer.from([b ? 1 : 0]);

  return Buffer.concat([
    Buffer.from([7]),
    wStr(data.serverName),
    wVari(data.protocol),
    wStr(data.version),
    wStr(data.levelName),
    wVari(data.playerCount),
    wVari(data.maxPlayerCount),
    wVari(data.gameType),
    wBool(data.editorWorld),
    wBool(data.hardcore),
    wBool(data.acceptsOnlineAuth),
    wBool(data.acceptsSelfSignedAuth),
    wStr(data.nonce),
    wVari(data.connectionType),
  ]);
}
