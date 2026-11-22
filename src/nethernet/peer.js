// peer.js — nethernet-mitm NetherNet peer (WebRTC wrapper over node-datachannel)
//
// Role: wraps a node-datachannel `PeerConnection` with the NetherNet data-channel
// convention — a "ReliableDataChannel" (fragmented/reassembled) and an
// "UnreliableDataChannel" (single-frame, best-effort). Emits "raw"/"packet"
// bytes, drives offer/answer + ICE candidate exchange.

import { EventEmitter } from "node:events";
import NodeDataChannel from "node-datachannel";
import { Reassembler, fragment, frameSingle } from "./frame.js";
import { stripIdentity } from "./identity.js";

const { PeerConnection } = NodeDataChannel;

export const MAX_MESSAGE_SIZE = 262144;
export const LABELS = { ReliableDataChannel: "reliable", UnreliableDataChannel: "unreliable" };

function defaultLog() {}

export class NetherNetPeer extends EventEmitter {
  constructor(options) {
    super();
    const opts = options ?? {};
    const name = opts.name ?? "peer";
    const log = opts.log ?? defaultLog;
    const bindAddress = opts.bindAddress;

    this.name = name;
    this.log = log;

    const config = {
      iceServers: [],
      maxMessageSize: MAX_MESSAGE_SIZE,
      ...(bindAddress ? { bindAddress } : {}),
    };
    this.pc = new PeerConnection(name, config);

    this.channels = { reliable: null, unreliable: null };
    this.queues = { reliable: [], unreliable: [] };
    this.reassemblers = {
      reliable: new Reassembler({ allowFragments: true }),
      unreliable: new Reassembler({ allowFragments: false }),
    };
    this.remoteSet = false;
    this.remoteMid = "0";
    this.pendingRemoteCandidates = [];
    this.localCandidateBuf = [];
    this.candidateSink = null;
    this.stats = { sentMsgs: 0, sentBytes: 0, recvMsgs: 0, recvBytes: 0 };
    this.closed = false;
    this.opened = false;
    this.localDesc = null;
    this._descWaiters = [];
    this._gatherWaiters = [];
    this.gatheringDone = false;

    this.pc.onLocalDescription((sdp, type) => {
      this.localDesc = { sdp, type };
      for (const w of this._descWaiters.splice(0)) w.resolve(this.localDesc);
    });
    this.pc.onLocalCandidate((candidate) => {
      if (this.candidateSink) this.candidateSink(candidate);
      else this.localCandidateBuf.push(candidate);
    });
    this.pc.onGatheringStateChange((state) => {
      if (state === "complete") {
        this.gatheringDone = true;
        for (const w of this._gatherWaiters.splice(0)) w.resolve();
      }
    });
    this.pc.onStateChange((state) => {
      this.log(`[${this.name}] pc state: ${state}`);
      this.emit("state", state);
      if (state === "failed" || state === "closed" || state === "disconnected") {
        this.close(new Error(`pc ${state}`));
      }
    });
    this.pc.onDataChannel((channel) => this.#attach(channel));
  }

  async createOffer(opts) {
    const { trickle } = opts;
    const descP = this.#waitLocalDescription();
    this.#attach(this.pc.createDataChannel("ReliableDataChannel", {}));
    this.#attach(this.pc.createDataChannel("UnreliableDataChannel", { unordered: true, maxRetransmits: 0 }));
    await descP;
    if (!trickle) {
      await this.#waitGathering();
      return this.pc.localDescription().sdp;
    }
    return this.localDesc.sdp;
  }

  async acceptOffer(offer, opts) {
    const { trickle } = opts;
    const descP = this.#waitLocalDescription();
    this.#setRemote(stripIdentity(offer), "offer");
    await descP;
    if (!trickle) {
      await this.#waitGathering();
      return this.pc.localDescription().sdp;
    }
    return this.localDesc.sdp;
  }

  setAnswer(answer) {
    this.#setRemote(stripIdentity(answer), "answer");
  }

  addRemoteCandidate(candidate) {
    if (!this.remoteSet) {
      this.pendingRemoteCandidates.push(candidate);
      return;
    }
    try {
      this.pc.addRemoteCandidate(candidate.replace(/^a=/, ""), this.remoteMid);
    } catch (e) {
      this.log(`[${this.name}] bad remote candidate: ${e.message}`);
    }
  }

  startCandidates(sink) {
    this.candidateSink = sink;
    for (const candidate of this.localCandidateBuf.splice(0)) sink(candidate);
  }

  get ufrag() {
    // NOTE: no `m` flag; `^` matches only the start of the whole SDP string.
    const m = /^a=ice-ufrag:(\S+)/.exec(this.localDesc?.sdp ?? "");
    return m?.[1] ?? "";
  }

  send(kind, data) {
    if (this.closed || data.length === 0) return;
    this.queues[kind].push(data);
    if (this.channels[kind]?.isOpen()) this.#flush(kind);
  }

  close(reason) {
    if (this.closed) return;
    this.closed = true;
    try { this.channels.reliable?.close(); } catch {}
    try { this.channels.unreliable?.close(); } catch {}
    try { this.pc.close(); } catch {}
    this.emit("close", reason);
  }

  #waitLocalDescription(timeoutMs = 10000) {
    if (this.localDesc) return Promise.resolve(this.localDesc);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out waiting for local description")), timeoutMs);
      this._descWaiters.push({
        resolve: (desc) => { clearTimeout(timer); resolve(desc); },
      });
    });
  }

  #waitGathering(timeoutMs = 15000) {
    if (this.gatheringDone) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out waiting for ICE gathering")), timeoutMs);
      this._gatherWaiters.push({
        resolve: () => { clearTimeout(timer); resolve(); },
      });
    });
  }

  #setRemote(sdp, type) {
    const m = /^a=mid:(\S+)/.exec(sdp);
    if (m) this.remoteMid = m[1];
    this.pc.setRemoteDescription(sdp, type);
    this.remoteSet = true;
    for (const candidate of this.pendingRemoteCandidates.splice(0)) {
      this.addRemoteCandidate(candidate);
    }
  }

  #attach(channel) {
    const kind = LABELS[channel.getLabel()];
    if (!kind) {
      this.log(`[${this.name}] ignoring unexpected data channel "${channel.getLabel()}"`);
      return;
    }
    this.channels[kind] = channel;
    channel.onMessage((msg) => {
      try {
        let buf;
        if (typeof msg === "string") {
          buf = Buffer.from(msg);
        } else {
          buf = Buffer.from(msg.buffer ? new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength) : msg);
        }
        this.stats.recvMsgs += 1;
        this.stats.recvBytes += buf.length;
        this.emit("raw", kind, buf);
        const packet = this.reassemblers[kind].push(buf);
        if (packet) this.emit("packet", kind, packet);
      } catch (e) {
        this.close(e);
      }
    });
    channel.onClosed(() => this.close(new Error(`${kind} data channel closed`)));
    channel.onOpen(() => this.#onChannelOpen(kind));
    if (channel.isOpen()) this.#onChannelOpen(kind);
  }

  #onChannelOpen(kind) {
    this.#flush(kind);
    if (!this.opened && this.channels.reliable?.isOpen() && this.channels.unreliable?.isOpen()) {
      this.opened = true;
      this.emit("open");
    }
  }

  #flush(kind) {
    const channel = this.channels[kind];
    if (!channel || !channel.isOpen()) return;
    for (const message of this.queues[kind].splice(0)) {
      try {
        if (kind === "reliable") {
          for (const segment of fragment(message)) {
            channel.sendMessageBinary(segment);
            this.stats.sentMsgs += 1;
            this.stats.sentBytes += segment.length;
          }
        } else if (message.length + 1 <= MAX_MESSAGE_SIZE) {
          const framed = frameSingle(message);
          channel.sendMessageBinary(framed);
          this.stats.sentMsgs += 1;
          this.stats.sentBytes += framed.length;
        } else {
          this.log(`[${this.name}] dropping oversize unreliable message (${message.length} bytes)`);
        }
      } catch (e) {
        this.log(`[${this.name}] send failed on ${kind}: ${e.message}`);
      }
    }
  }
}
