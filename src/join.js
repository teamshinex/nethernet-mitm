// join.js — nethernet-mitm join agent (runs on the joiner's PC)
//
// Role: presents a local NetherNet "server" that the user adds in Minecraft as
// "<this PC's IP>:<port>". It polls the relay's /api/hosts/:id to learn whether
// the host is online, and for every local client connection it opens a relay
// tunnel (openJoin) and pipes NetherNet packets both ways.

import "./cli/_native-shim.cjs"; // NOTE: loaded for its side effect (resolves the node-datachannel native addon) before peer.js pulls in node-datachannel.

import { parseArgs } from "node:util";
import path from "node:path";

import { NetherNetPeer } from "./nethernet/peer.js";
import { ServerIdentity, inspectIdentity } from "./nethernet/identity.js";
import { createHttpSignalingServer } from "./nethernet/signaling.js";
import { openJoin, relayUrls } from "./nethernet/tunnel.js";
import { normalizeId } from "./nethernet/util.js";

// Server info advertised to the local game until the relay tells us otherwise.
const DEFAULT_INFO = {
  name: "Relay world",
  protocol: 2225,
  version: "1.26.60",
  level: "Relay",
  players: 0,
  maxPlayers: 8,
  gameType: 0,
};

export class JoinAgent {
  constructor(opts) {
    this.relay = opts.relay;
    this.id = normalizeId(opts.id);
    this.password = opts.password;
    this.httpPort = opts.httpPort ?? 19132;
    this.httpExtraPorts = opts.httpExtraPorts ?? [443, 80];
    this.httpHost = opts.httpHost ?? "0.0.0.0";
    this.identity = opts.identity ?? null;
    this.bindAddress = opts.bindAddress;
    this.log = opts.log ?? console.log;

    this.urls = relayUrls(opts.relay);
    this.info = { ...DEFAULT_INFO, name: `${this.id} (relay)`, level: this.id };
    this.hostOnline = null;
    this.servers = [];
    this.timer = null;
    this.seq = 0;
    // Live peer objects (added in #pipe, closed in stop).
    this.active = new Set();
  }

  async start() {
    const mk = (port) =>
      createHttpSignalingServer({
        port,
        host: this.httpHost,
        getInfo: () => this.info,
        onOffer: (id, offer) => this.#onOffer(id, offer),
        log: this.log,
      });

    await this.#pollInfo();
    this.timer = setInterval(() => this.#pollInfo(), 10000);
    this.timer.unref?.();

    this.servers.push(await mk(this.httpPort));
    this.log(
      `[join] add this PC as a server in Minecraft: <this PC's IP>:${this.httpPort}   (joins host "${this.id}" via ${this.urls.ws})`,
    );

    if (this.httpPort === 19132) {
      for (const port of this.httpExtraPorts) {
        try {
          this.servers.push(await mk(port));
          this.log(`[join] also listening on :${port} (client probe port)`);
        } catch (e) {
          this.log(`[join] extra port :${port} not available (${e.code ?? e.message})`);
        }
      }
    }
  }

  stop() {
    clearInterval(this.timer);
    for (const server of this.servers) server.close();
    for (const peer of Array.from(this.active)) peer.close();
  }

  async #onOffer(id, offer) {
    const n = ++this.seq;
    const claims = inspectIdentity(offer)?.claims;
    const player = { xuid: claims?.xid, name: claims?.xname };
    this.log(
      `[join #${n}] player connecting${player.name ? ` ("${player.name}")` : ""}; asking the relay for "${this.id}"`,
    );

    const tunnel = await openJoin({
      relay: this.relay,
      id: this.id,
      password: this.password,
      player,
      log: this.log,
    });

    const peer = new NetherNetPeer({
      name: `join-${n}`,
      log: this.log,
      bindAddress: this.bindAddress,
    });
    try {
      let answer = await peer.acceptOffer(offer, { trickle: false });
      if (this.identity) answer = this.identity.sign(answer);
      this.#pipe(n, peer, tunnel);
      return answer;
    } catch (e) {
      peer.close(e);
      tunnel.close(e);
      throw e;
    }
  }

  #pipe(n, peer, tunnel) {
    this.active.add(peer);
    peer.on("packet", (kind, payload) => tunnel.send(kind, payload));
    tunnel.on("packet", (kind, payload) => peer.send(kind, payload));

    const done = (label) => (err) => {
      if (!this.active.delete(peer)) return;
      this.log(`[join #${n}] ${label} closed${err ? `: ${err.message ?? err}` : ""}`);
      peer.close();
      tunnel.close();
    };
    peer.once("close", done("player"));
    tunnel.once("close", done("relay"));
    peer.once("open", () => this.log(`[join #${n}] player channels open`));
  }

  #setOnline(online, reason) {
    if (online === this.hostOnline) return;
    this.hostOnline = online;
    const status =
      online ? "online" : online === false ? `offline (${reason})` : `unknown (${reason})`;
    this.log(`[join] host "${this.id}": ${status}`);
  }

  async #pollInfo() {
    try {
      const res = await fetch(`${this.urls.http}/api/hosts/${encodeURIComponent(this.id)}`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.status === 404) {
        this.#setOnline(false, "the relay does not know this id");
        return;
      }
      const data = await res.json();
      if (data.info) {
        this.info = { ...DEFAULT_INFO, ...data.info };
      }
      this.#setOnline(!!data.online, data.online ? undefined : "host is offline");
    } catch (e) {
      this.#setOnline(null, `relay not reachable (${e.message})`);
    }
  }
}

// ---- CLI -----------------------------------------------------------------

const { values } = parseArgs({
  options: {
    relay: { type: "string" },
    id: { type: "string" },
    password: { type: "string" },
    port: { type: "string" },
    "http-extra-ports": { type: "string" },
    "http-host": { type: "string" },
    bind: { type: "string" },
    "identity-key": { type: "string" },
    "no-identity": { type: "boolean" },
    help: { type: "boolean", short: "h" },
  },
});

if (values.help || !values.relay || !values.id) {
  console.log(
`join-agent — join a friend's world through a relay. No port-forward needed.

  --relay <host[:port]>     relay address (default port 7000)
  --id <name>               the host's id (ask the host)
  --password <text>         if the host set one
  --port <n>                port Minecraft connects to (default 19132)
  --http-extra-ports <443,80|none>   with port 19132 the game also probes these (default 443,80)
  --http-host <ip>          bind address (default 0.0.0.0, so phones/consoles on your LAN can use this PC)
  --bind <ip>               local IP for WebRTC (advanced)

Then in Minecraft: Servers -> Add server -> this PC's IP, port 19132.`);
  process.exit(values.help ? 0 : 1);
}

async function main() {
  const opts = {
    relay: values.relay,
    id: values.id,
    password: values.password,
    httpPort: values.port ? Number(values.port) : 19132,
    httpExtraPorts:
      values["http-extra-ports"] === "none"
        ? []
        : (values["http-extra-ports"] ?? "443,80").split(",").map(Number).filter(Boolean),
    httpHost: values["http-host"] ?? "0.0.0.0",
    bindAddress: values.bind,
    identity: values["no-identity"]
      ? null
      : new ServerIdentity({ keyPath: values["identity-key"] ?? path.resolve("./identity-key.pem") }),
  };

  const agent = new JoinAgent(opts);
  await agent.start();
}

main().catch((e) => { console.error(e?.stack ?? e); process.exit(1); });

process.on("SIGINT", () => { console.log("[exit] SIGINT"); process.exit(130); });
process.on("uncaughtException", (e) => { console.log("[exit] uncaught exception:", e?.stack ?? e); process.exit(1); });
process.on("unhandledRejection", (e) => { console.log("[exit] unhandled rejection:", e?.stack ?? e); });
