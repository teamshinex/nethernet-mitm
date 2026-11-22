// nethernet/util.js — small shared helpers

import { WebSocket } from "ws";
// NOTE: circular import with ./tunnel.js (tunnel.js imports the helpers below).
// firstJson only references TunnelError inside runtime callbacks, so the ESM
// live binding is resolved by the time it is used.
import { TunnelError } from "./tunnel.js";

export function normalizeId(id) {
  return String(id ?? "").trim().toLowerCase();
}

export function sendJson(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

export function firstJson(ws, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      ws.off("message", onMsg);
      ws.off("close", onClose);
      ws.off("error", onErr);
    };
    const onMsg = (data, isBinary) => {
      cleanup();
      if (isBinary) {
        reject(new TunnelError("protocol", "unexpected binary frame"));
        return;
      }
      try {
        resolve(JSON.parse(data.toString()));
      } catch {
        reject(new TunnelError("protocol", "bad JSON from relay"));
      }
    };
    const onClose = (code) => {
      cleanup();
      reject(new TunnelError("closed", `connection closed (${code})`));
    };
    const onErr = (err) => {
      cleanup();
      reject(new TunnelError("connect", err.message));
    };
    timer = setTimeout(() => {
      cleanup();
      reject(new TunnelError("timeout", "timed out waiting for the relay"));
    }, timeoutMs);
    ws.on("message", onMsg);
    ws.once("close", onClose);
    ws.once("error", onErr);
  });
}
