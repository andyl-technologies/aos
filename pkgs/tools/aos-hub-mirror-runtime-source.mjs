// Approved controlled upstream for the real Fetch/range/ETag producer path.
// Large sources are generated in <=64KiB chunks; no whole NAR is retained here.

function decode(encoded = "") {
  return Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
}

const observations = new Map();

export default {
  fetch(request, env) {
    const url = new URL(request.url);
    if (url.origin !== "https://upstream.example.invalid") {
      return new Response(null, { status: 403 });
    }
    if (url.pathname === "/__fixture/observations") {
      return Response.json(Array.from(observations, ([path, requests]) => ({ path, requests })));
    }
    const source = JSON.parse(env.UPSTREAM_SOURCES)[url.pathname];
    if (!source) return new Response(null, { status: 404 });

    observations.set(url.pathname, (observations.get(url.pathname) ?? 0) + 1);

    const etag = `"controlled-${source.sha256}"`;
    const condition = request.headers.get("if-match");
    if (condition && condition !== etag) return new Response(null, { status: 412 });
    let start = 0;
    let end = source.size;
    const range = request.headers.get("range");
    if (range) {
      const matched = /^bytes=(\d+)-(\d+)$/.exec(range);
      if (!matched) return new Response(null, { status: 416 });
      start = Number(matched[1]);
      end = Number(matched[2]) + 1;
      if (start >= end || end > source.size) return new Response(null, { status: 416 });
    }

    const fixed = source.base64 ? decode(source.base64) : null;
    const prefix = decode(source.prefix);
    const suffix = decode(source.suffix);
    let offset = start;
    const body = new ReadableStream({
      type: "bytes",
      pull(controller) {
        if (offset === end) {
          const pending = controller.byobRequest;
          controller.close();
          pending?.respond(0);
          return;
        }
        const count = Math.min(65536, end - offset);
        const bytes = fixed ? fixed.slice(offset, offset + count) : new Uint8Array(count).fill(source.fill);
        if (!fixed) {
          for (let index = 0; index < count; index++) {
            const position = offset + index;
            if (position < prefix.length) bytes[index] = prefix[position];
            else if (position >= source.size - suffix.length) {
              bytes[index] = suffix[position - (source.size - suffix.length)];
            }
          }
        }
        offset += count;
        controller.enqueue(bytes);
      },
    });
    const headers = { "content-length": String(end - start), etag, "accept-ranges": "bytes" };
    if (range) headers["content-range"] = `bytes ${start}-${end - 1}/${source.size}`;
    return new Response(body, { status: range ? 206 : 200, headers });
  },
};
