// Controlled upstream consumed by actual workerd Fetch/BYOB readers.
// Counters record source pulls/cancellation, not inferred client settlement.

const observations = [];
let pointerRevision = 0;
let requestSequence = 0;

export function resetLiveSourceObservations() {
  observations.length = 0;
  pointerRevision = 0;
  requestSequence = 0;
}

export function liveSourceObservations() {
  return observations.map(item => ({ ...item }));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const run = env.LIVE_RUN_ID;
    const validRun = /^[a-f0-9]{32}$/.test(run ?? "");
    const validOrigin = url.origin === "https://upstream.example.invalid";
    if (validRun && validOrigin && url.pathname === "/__fixture/live-observations") {
      return Response.json(liveSourceObservations());
    }
    const prefix = `/.aos-mirror-qualification/${run}/`;
    // A refused foreign dispatch is still a dispatch. Do not hide it from
    // zero-dispatch cases, and never retain its raw URL or headers.
    const validPath = validRun && validOrigin && url.pathname.startsWith(prefix);
    const path = validPath ? url.pathname.slice(prefix.length) : "outside_fixture";
    const entry = {
      sequence: ++requestSequence, path, method: request.method, status: null,
      declaredBytes: null, contentEncoding: null,
      pulls: 0, sourceBytes: 0, cancelled: false, ended: false,
    };
    observations.push(entry);
    const reply = (body, init) => {
      const response = new Response(body, init);
      entry.status = response.status;
      const declared = response.headers.get("content-length");
      entry.declaredBytes = declared === null ? null : Number(declared);
      entry.contentEncoding = response.headers.get("content-encoding");
      return response;
    };
    if (!validPath || !["GET", "HEAD"].includes(request.method)) {
      return reply(null, { status: 403 });
    }
    if (path === "channels/missing") {
      return reply(null, { status: 404 });
    }
    if (path === "channels/redirect") {
      return reply(null, { status: 307, headers: { location: "https://foreign.example.invalid/HEAD" } });
    }

    const isPack = path.startsWith("objects/pack/");
    const size = isPack ? 16 * 1024 * 1024 : path === "channels/oversize" ? 128 * 1024 + 1 : 64;
    const pointer = new TextEncoder().encode(`ref: refs/heads/revision-${++pointerRevision}\n`);
    const bytes = new Uint8Array(size <= 128 * 1024 ? size : 0).fill(32);
    if (bytes.length) bytes.set(pointer.subarray(0, bytes.length));
    const headers = new Headers({ "content-type": "application/octet-stream", "content-length": String(size) });
    if (path === "channels/encoding") headers.set("content-encoding", "gzip");
    if (path === "channels/truncated") headers.set("content-length", String(size + 1));
    if (request.method === "HEAD") {
      entry.ended = true;
      return reply(null, { headers });
    }

    let offset = 0;
    const body = new ReadableStream({
      type: "bytes",
      async pull(controller) {
        if (path.endsWith("hold.pack") || path === "channels/hold") {
          await new Promise(resolve => setTimeout(resolve, 3000));
          if (entry.cancelled) return;
        }
        if (offset === size) {
          entry.ended = true;
          const pending = controller.byobRequest;
          controller.close();
          pending?.respond(0);
          return;
        }
        const count = Math.min(65536, size - offset);
        const chunk = isPack ? new Uint8Array(count).fill(71) : bytes.slice(offset, offset + count);
        offset += count;
        entry.pulls += 1;
        entry.sourceBytes += chunk.length;
        controller.enqueue(chunk);
      },
      cancel() {
        entry.cancelled = true;
      },
    });
    return reply(body, { headers });
  },
};
