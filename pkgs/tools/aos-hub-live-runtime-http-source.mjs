// Controlled HTTPS source for the closed live corpus. Source bytes count only
// bytes accepted by ServerResponse.write, independently of Worker/client reads.
// Cancellation requires the exact incomplete response and its TLS socket close;
// completed responses, producer failures and fixture teardown cannot qualify it.

import { createServer } from "node:https";

const CHUNK_BYTES = 64 * 1024;
const PACK_BYTES = 16 * 1024 * 1024;
const HOST = "upstream.example.invalid";
const PATHS = new Set([
  "HEAD", "info/refs", "channels/hold", "channels/missing", "channels/redirect",
  "channels/encoding", "channels/truncated", "channels/oversize",
  "objects/pack/full.pack", "objects/pack/hold.pack",
]);
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]);

function refreshCancellation(entry) {
  entry.cancelled = entry.socketClosed && entry.responseClosedBeforeFinish
    && !entry.responseFinished && !entry.ended && !entry.fixtureTeardown
    && !entry.sourceFailure && entry.sourceBytes > 0
    && entry.sourceBytes < entry.producerExpectedBytes;
}

function waitForResponse(response, event, milliseconds) {
  if (response.destroyed) return Promise.resolve(false);
  return new Promise(resolve => {
    let timer;
    const finish = ready => {
      clearTimeout(timer);
      response.removeListener("close", closed);
      if (event) response.removeListener(event, readyEvent);
      resolve(ready && !response.destroyed);
    };
    const closed = () => finish(false);
    const readyEvent = () => finish(true);
    response.once("close", closed);
    if (event) response.once(event, readyEvent);
    if (milliseconds !== undefined) timer = setTimeout(readyEvent, milliseconds);
  });
}

/** Creates a controlled TLS source without selecting its listening address. */
export function createLiveSocketSource({ runId, cert, key }) {
  if (!/^[a-f0-9]{32}$/.test(runId ?? "")) throw new Error("A closed fixture run identifier is required");
  const prefix = `/.aos-mirror-qualification/${runId}/`;
  const entries = [];
  const sockets = new Set();
  const transportSockets = new Set();
  const socketEntries = new WeakMap();
  const socketIds = new WeakMap();
  let sequence = 0;
  let socketSequence = 0;
  let pointerRevision = 0;
  let closing = false;
  let closePromise;
  const observations = () => entries.map(entry => ({ ...entry }));

  function trackSocket(socket) {
    if (socketIds.has(socket)) return;
    sockets.add(socket);
    socketIds.set(socket, ++socketSequence);
    socketEntries.set(socket, new Set());
    socket.once("close", () => {
      for (const entry of socketEntries.get(socket)) {
        entry.socketClosed = true;
        refreshCancellation(entry);
      }
      sockets.delete(socket);
    });
  }

  const server = createServer({ cert, key }, (request, response) => {
    trackSocket(request.socket);
    const validHost = request.headers.host === HOST;
    if (validHost && request.method === "GET" && request.url === "/__fixture/live-observations") {
      const bytes = Buffer.from(JSON.stringify(observations()));
      response.writeHead(200, { "content-type": "application/json", "content-length": bytes.length });
      response.end(bytes);
      return;
    }

    const suffix = request.url?.startsWith(prefix) ? request.url.slice(prefix.length) : null;
    const validPath = validHost && PATHS.has(suffix);
    const entry = {
      sequence: ++sequence, socketId: socketIds.get(request.socket),
      path: validPath ? suffix : "outside_fixture",
      method: METHODS.has(request.method) ? request.method : "OTHER",
      status: null, declaredBytes: null, contentEncoding: null,
      pulls: 0, sourceBytes: 0, sourceBytesKind: "producer_write_accepted",
      producerExpectedBytes: 0,
      ended: false, cancelled: false, responseFinished: false,
      responseClosedBeforeFinish: false, socketClosed: false,
      fixtureTeardown: closing, sourceFailure: false,
    };
    entries.push(entry);
    socketEntries.get(request.socket).add(entry);
    response.once("finish", () => {
      entry.responseFinished = true;
      refreshCancellation(entry);
    });
    response.once("close", () => {
      entry.responseClosedBeforeFinish = !response.writableFinished;
      refreshCancellation(entry);
    });
    response.on("error", () => {
      entry.sourceFailure = true;
      refreshCancellation(entry);
    });

    const reply = (status, size, headers = {}) => {
      entry.status = status;
      entry.declaredBytes = size;
      entry.contentEncoding = headers["content-encoding"] ?? null;
      response.writeHead(status, { "content-type": "application/octet-stream", "content-length": size, ...headers });
    };
    if (!validPath || !["GET", "HEAD"].includes(request.method) || closing) {
      reply(403, 0);
      entry.ended = true;
      response.end();
      return;
    }
    if (suffix === "channels/missing" || suffix === "channels/redirect") {
      reply(suffix === "channels/missing" ? 404 : 307, 0,
        suffix === "channels/redirect" ? { location: "https://foreign.example.invalid/HEAD" } : {});
      entry.ended = true;
      response.end();
      return;
    }

    const pack = suffix.startsWith("objects/pack/");
    const size = pack ? PACK_BYTES : suffix === "channels/oversize" ? 128 * 1024 + 1 : 64;
    entry.producerExpectedBytes = request.method === "HEAD" ? 0 : size;
    const pointer = Buffer.from(`ref: refs/heads/revision-${++pointerRevision}\n`);
    const headers = {};
    if (suffix === "channels/encoding") headers["content-encoding"] = "gzip";
    // The intended short EOF must be observable immediately, rather than
    // waiting for a keepalive timeout on a response with one missing byte.
    if (suffix === "channels/truncated") headers.connection = "close";
    reply(200, suffix === "channels/truncated" ? size + 1 : size, headers);
    if (request.method === "HEAD") {
      entry.ended = true;
      response.end();
      return;
    }
    response.flushHeaders();

    void (async () => {
      let offset = 0;
      while (offset < size && !response.destroyed && !closing) {
        if (suffix.endsWith("hold.pack") || suffix === "channels/hold") {
          if (!await waitForResponse(response, null, 3000)) return;
        }
        if (response.destroyed || closing) return;
        const count = Math.min(CHUNK_BYTES, size - offset);
        const chunk = Buffer.alloc(count, pack ? 71 : 32);
        if (!pack && offset < pointer.length) pointer.copy(chunk, 0, offset, Math.min(pointer.length, offset + count));
        const ready = response.write(chunk);
        entry.pulls += 1;
        entry.sourceBytes += count;
        offset += count;
        if (!ready && !await waitForResponse(response, "drain")) return;
      }
      if (offset === size && !response.destroyed && !closing) {
        entry.ended = true;
        response.end();
      }
    })().catch(() => {
      entry.sourceFailure = true;
      refreshCancellation(entry);
      response.destroy();
    });
  });

  server.on("secureConnection", trackSocket);
  server.on("connection", socket => {
    transportSockets.add(socket);
    socket.once("close", () => transportSockets.delete(socket));
  });

  async function close() {
    if (closePromise) return closePromise;
    closing = true;
    for (const entry of entries) if (!entry.socketClosed) entry.fixtureTeardown = true;
    closePromise = new Promise((resolve, reject) => {
      if (!server.listening) resolve();
      else server.close(error => error ? reject(error) : resolve());
      // Mark teardown before destroying any active source socket. These
      // closures cannot become evidence of client cancellation.
      for (const socket of sockets) socket.destroy();
      for (const socket of transportSockets) socket.destroy();
      server.closeAllConnections();
    });
    await closePromise;
  }

  return { server, observations, close };
}
