// Minimal state services for the open-source workerd qualification harness.
//
// workerd models Workers KV and the Cache API as HTTP service bindings. The
// production Worker needs KV for sessions and invokes the ephemeral edge cache
// for anonymous browse requests. This fixture implements those HTTP contracts
// without pretending to qualify Cloudflare infrastructure itself.

const kv = new Map();

function kvKey(request) {
  return decodeURIComponent(new URL(request.url).pathname.slice(1));
}

function liveValue(key) {
  const value = kv.get(key);
  if (value?.expiresAt !== undefined && value.expiresAt <= Date.now()) {
    kv.delete(key);
    return undefined;
  }
  return value;
}

async function handleKv(request) {
  const url = new URL(request.url);
  const key = kvKey(request);
  if (request.method === "GET" && key === "") {
    const prefix = url.searchParams.get("prefix") ?? "";
    const keys = [...kv.keys()]
      .filter((candidate) => liveValue(candidate) !== undefined && candidate.startsWith(prefix))
      .map((name) => ({ name }));
    return Response.json({ keys, list_complete: true, cursor: "" });
  }
  if (request.method === "GET") {
    const value = liveValue(key);
    return value === undefined
      ? new Response(null, { status: 404 })
      : new Response(value.bytes.slice(0));
  }
  if (request.method === "PUT") {
    const expiration = url.searchParams.get("expiration");
    const expirationTtl = url.searchParams.get("expiration_ttl");
    const expiresAt = expiration !== null
      ? Number(expiration) * 1000
      : expirationTtl !== null
        ? Date.now() + Number(expirationTtl) * 1000
        : undefined;
    kv.set(key, { bytes: await request.arrayBuffer(), expiresAt });
    return new Response(null, { status: 204 });
  }
  if (request.method === "DELETE") {
    kv.delete(key);
    return new Response(null, { status: 204 });
  }
  return new Response("unsupported KV fixture operation", { status: 405 });
}

function handleCache(request) {
  if (request.method === "GET") {
    return new Response(null, {
      status: 504,
      headers: { "cf-cache-status": "MISS" },
    });
  }
  if (request.method === "PUT") {
    return new Response(null, { status: 204 });
  }
  if (request.method === "PURGE") {
    return new Response(null, { status: 404 });
  }
  return new Response("unsupported cache fixture operation", { status: 405 });
}

export default {
  async fetch(request) {
    return request.headers.has("cf-kv-flprod-405")
      ? handleKv(request)
      : handleCache(request);
  },
};
