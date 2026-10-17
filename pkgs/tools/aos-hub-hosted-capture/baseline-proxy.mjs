// Fixed qualification transport. Native retains its original ingress verifier.
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const bodyLimit = 8 * 1024 * 1024;
const requiredFields = [
  "version", "deployment_id", "issued_at", "expires_at", "request_id",
  "scheme", "authority", "method", "path_and_query", "body_sha256", "client_ip",
];

function refuse(status = 401) {
  return new Response("qualification origin refused", {
    status,
    headers: { "cache-control": "private, no-store" },
  });
}

function bytesFromBase64url(text, maximum) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text) || text.length > maximum) {
    throw new Error("noncanonical frame");
  }
  const decoded = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  const canonical = btoa(decoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (canonical !== text) throw new Error("noncanonical frame");
  return bytes;
}

function parseObject(bytes) {
  const value = JSON.parse(decoder.decode(bytes));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("object required");
  return value;
}

function validIP(text) {
  if (typeof text !== "string" || text.length > 45) return false;
  if (/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(text)) {
    return text.split(".").every((part) => Number(part) <= 255);
  }
  if (!/^[0-9a-fA-F:.]+$/.test(text) || !text.includes(":")) return false;
  try {
    return new URL(`http://[${text}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}

function selectedOrigin(value, providerTarget = false) {
  if (typeof value !== "string" || value.length > 2048) {
    throw new Error("selected origin required");
  }
  const url = new URL(value);
  if (url.origin !== value || url.protocol !== "https:" || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash || url.port ||
      (providerTarget && !url.hostname.endsWith(".run.app"))) {
    throw new Error("selected origin refused");
  }
}

function checkedPolicy(policy) {
  const fields = ["version", "project", "service", "serviceUID", "target", "proxyOrigin",
    "publicOrigin", "deploymentID", "invokerEmail", "invokerUID", "startsAt", "expiresAt"];
  if (!policy || Array.isArray(policy) || Object.keys(policy).length !== fields.length ||
      fields.some(field => !Object.hasOwn(policy, field))) {
    throw new Error("closed selected policy required");
  }
  if (policy.version !== 1 || typeof policy.project !== "string" ||
      !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(policy.project) ||
      typeof policy.service !== "string" || !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(policy.service) ||
      typeof policy.serviceUID !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(policy.serviceUID) ||
      typeof policy.invokerUID !== "string" || !/^[0-9]{1,32}$/.test(policy.invokerUID) ||
      typeof policy.invokerEmail !== "string" || policy.invokerEmail.length > 254 ||
      !policy.invokerEmail.endsWith("@" + policy.project + ".iam.gserviceaccount.com") ||
      !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(policy.invokerEmail.split("@")[0]) ||
      typeof policy.deploymentID !== "string" || !/^[a-z0-9-]{1,128}$/.test(policy.deploymentID) ||
      !Number.isSafeInteger(policy.startsAt) || !Number.isSafeInteger(policy.expiresAt) ||
      policy.expiresAt <= policy.startsAt || policy.expiresAt - policy.startsAt !== 3600) {
    throw new Error("selected qualification policy refused");
  }

  // Operator-selected coordinates are configuration, not provider identity or
  // IAM proof. Exact audience, subject and request checks remain downstream.
  selectedOrigin(policy.target, true);
  selectedOrigin(policy.proxyOrigin);
  selectedOrigin(policy.publicOrigin);
  return Object.freeze({ ...policy });
}

function validateAssertion(value, text, request, url, policy, now) {
  const fields = [...requiredFields];
  if ("upload_phase" in value) fields.push("upload_phase");
  if (Object.keys(value).length !== fields.length || fields.some((field) => !(field in value))) {
    throw new Error("closed ingress assertion required");
  }
  const phase = value.upload_phase;
  if (value.version !== 1 || value.deployment_id !== policy.deploymentID ||
      value.scheme !== "https" || value.authority !== new URL(policy.publicOrigin).host ||
      value.method !== request.method || !/^[A-Z]{1,16}$/.test(value.method) ||
      value.path_and_query !== url.pathname + url.search || encoder.encode(value.path_and_query).length > 8192 ||
      typeof value.request_id !== "string" || !value.request_id || encoder.encode(value.request_id).length > 128 ||
      !/^[0-9a-f]{64}$/.test(value.body_sha256) || !validIP(value.client_ip) ||
      !Number.isSafeInteger(value.issued_at) || !Number.isSafeInteger(value.expires_at) ||
      value.issued_at > now + 5 || value.expires_at < now ||
      value.expires_at < value.issued_at || value.expires_at - value.issued_at > 30 ||
      (phase !== undefined && (typeof phase !== "string" || !/^[a-z-]{1,32}$/.test(phase))) ||
      request.headers.get("x-aos-hybrid-upload-phase") !== (phase ?? null)) {
    throw new Error("request or clock mismatch");
  }
  // Reject duplicate fields and serialization variants. This is the actual
  // paired Rust sender's struct order, including its omitted optional field.
  const canonical = {};
  for (const field of requiredFields.slice(0, -1)) canonical[field] = value[field];
  if (phase !== undefined) canonical.upload_phase = phase;
  canonical.client_ip = value.client_ip;
  if (JSON.stringify(canonical) !== text) throw new Error("noncanonical sender JSON");
}

async function authenticatedAssertion(request, url, policy, keyText, now) {
  if (typeof keyText !== "string" || !/^[0-9a-f]{64}$/.test(keyText)) throw new Error("existing key format refused");
  const frame = request.headers.get("x-aos-hybrid-ingress");
  if (!frame || frame.length > 16 * 1024 || frame.split(".").length !== 2) throw new Error("bounded frame required");
  const [payload, signatureText] = frame.split(".");
  const bytes = bytesFromBase64url(payload, 16 * 1024);
  const signature = bytesFromBase64url(signatureText, 64);
  if (signature.length !== 32) throw new Error("MAC size refused");
  // The stored 64 ASCII bytes are used unchanged, never hex-decoded.
  const key = await crypto.subtle.importKey("raw", encoder.encode(keyText),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify("HMAC", key, signature, encoder.encode(payload))) {
    throw new Error("MAC refused");
  }
  const text = decoder.decode(bytes);
  const value = parseObject(bytes);
  validateAssertion(value, text, request, url, policy, now);
  return value;
}

function checkedToken(token, policy, now) {
  if (typeof token !== "string" || token.length > 8192 || token.split(".").length !== 3) {
    throw new Error("bounded private ID token required");
  }
  const [headerText, payloadText, signatureText] = token.split(".");
  const header = parseObject(bytesFromBase64url(headerText, 4096));
  const payload = parseObject(bytesFromBase64url(payloadText, 8192));
  if (bytesFromBase64url(signatureText, 2048).length < 128 || header.alg !== "RS256" ||
      !["accounts.google.com", "https://accounts.google.com"].includes(payload.iss) ||
      payload.aud !== policy.target || payload.sub !== policy.invokerUID ||
      payload.email !== policy.invokerEmail || payload.email_verified !== true ||
      !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) ||
      payload.iat > now + 5 || payload.exp < now + 30 || payload.exp <= payload.iat ||
      payload.exp - payload.iat > 3600 || payload.exp > now + 3605) {
    throw new Error("ID token scope or TTL refused");
  }
  // This projects only an operator-installed secret. Google verifies the
  // token's RSA signature and invocation authorization at the fixed target.
  return token;
}

async function boundedBody(request) {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^(0|[1-9][0-9]*)$/.test(declared) || Number(declared) > bodyLimit)) {
    throw new Error("body ceiling refused");
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > bodyLimit) throw new Error("body ceiling refused");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  if (declared !== null && Number(declared) !== length) throw new Error("body length mismatch");
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return body;
}

/** Builds a closed target handler; its only mutable input is the private token. */
export function createProxy(configuration, transport = fetch, clock = () => Math.floor(Date.now() / 1000)) {
  const policy = checkedPolicy(configuration);
  return async function handle(request, secrets) {
    try {
      if (request.signal.aborted) return refuse();
      const now = clock();
      const url = new URL(request.url);
      if (!Number.isSafeInteger(now) || now < policy.startsAt || now >= policy.expiresAt ||
          url.origin !== policy.proxyOrigin || url.username || url.password || url.hash ||
          url.pathname.startsWith("/_internal/storage/")) return refuse();
      const assertion = await authenticatedAssertion(request, url, policy, secrets.HUB_HYBRID_INGRESS_KEY, now);
      const token = checkedToken(secrets.GOOGLE_INVOKER_ID_TOKEN, policy, now);
      const body = await boundedBody(request);
      if (body.length && ["GET", "HEAD", "DELETE"].includes(request.method)) return refuse();
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", body)),
        (byte) => byte.toString(16).padStart(2, "0")).join("");
      if (hash !== assertion.body_sha256) return refuse();
      // Do not dispatch an assertion that expired while its body was read.
      const dispatchTime = clock();
      if (dispatchTime >= policy.expiresAt || dispatchTime > assertion.expires_at) return refuse();
      checkedToken(token, policy, dispatchTime);
      const headers = new Headers(request.headers);
      for (const name of ["host", "connection", "transfer-encoding", "content-length",
        "expect", "keep-alive", "proxy-connection", "te", "trailer", "upgrade"]) headers.delete(name);
      headers.set("x-serverless-authorization", `Bearer ${token}`);
      const init = { method: request.method, headers, redirect: "manual", signal: request.signal };
      if (body.length) init.body = body;
      // No awaited validation may leave a cancelled caller eligible to dispatch.
      if (request.signal.aborted) return refuse();
      const response = await transport(new Request(policy.target + url.pathname + url.search, init));
      const output = new Headers(response.headers);
      output.delete("x-serverless-authorization");
      // Manual transport never follows Location. App redirects, cookies and
      // cache policy remain Native's response; the provider token stays local.
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers: output });
    } catch {
      return refuse();
    }
  };
}
