// nethernet/frame.js — NetherNet message fragmentation / reassembly
//
// A NetherNet data-channel message is prefixed with one header byte: the number
// of further segments that still follow (0 = last/only segment). encodeFrame /
// decodeFrame wrap a tunnel payload with a one-byte channel-kind tag instead.

// Channel kinds, indexed by the tag byte used on the wire (0 = reliable).
export const KINDS = ["reliable", "unreliable"];

// Largest payload carried in a single NetherNet segment before fragmenting.
export const MAX_SEGMENT = 10000;

export class Reassembler {
  constructor(opts = {}) {
    this.allowFragments = opts.allowFragments ?? true;
    this.remaining = 0;
    this.parts = [];
  }

  push(data) {
    if (data.length < 2) {
      throw new Error("nethernet: message shorter than 2 bytes");
    }
    const header = data[0];
    if (!this.allowFragments) {
      if (header > 0) {
        throw new Error(`nethernet: unexpected fragment header ${header} on unreliable channel`);
      }
    }
    if (this.remaining > 0) {
      if (this.remaining - 1 !== header) {
        throw new Error(`nethernet: invalid promised segments: expected ${this.remaining - 1}, got ${header}`);
      }
    }
    this.remaining = header;
    this.parts.push(data.subarray(1));
    if (header > 0) {
      return null;
    }
    const message = this.parts.length === 1 ? this.parts[0] : Buffer.concat(this.parts);
    this.parts = [];
    return message;
  }
}

export function decodeFrame(buf) {
  if (!KINDS[buf[0]] || buf.length < 2) {
    return null;
  }
  return { kind: KINDS[buf[0]], payload: buf.subarray(1) };
}

export function encodeFrame(kind, payload) {
  const buf = Buffer.allocUnsafe(payload.length + 1);
  buf[0] = kind === "unreliable" ? 1 : 0;
  payload.copy(buf, 1);
  return buf;
}

export function frameSingle(payload) {
  return Buffer.concat([Buffer.from([0]), payload]);
}

export function fragment(data, maxSegment = MAX_SEGMENT) {
  const count = Math.max(1, Math.ceil(data.length / maxSegment));
  if (count > 256) {
    throw new RangeError(`payload too large to fragment (${data.length} bytes)`);
  }
  const parts = [];
  for (let i = 0; i < count; i++) {
    const chunk = data.subarray(i * maxSegment, (i + 1) * maxSegment);
    const header = Buffer.from([count - 1 - i]);
    parts.push(Buffer.concat([header, chunk]));
  }
  return parts;
}
