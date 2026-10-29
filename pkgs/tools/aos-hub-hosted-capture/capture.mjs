// Private diagnostic transport observations. These records never grant authority.
export const BODY_LIMIT = 8 * 1024 * 1024;
export const CORPUS_LIMIT = 512 * 1024 * 1024;
// This isolate-local memory ceiling is separate from the shared durable corpus
// budget. Under pressure only the diagnostic image becomes incomplete.
const MEMORY_LIMIT = 16 * 1024 * 1024;
let retainedMemory = 0;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const digestPattern = /^[0-9a-f]{64}$/;
const idPattern = /^[0-9a-f]{32}$/;
const originMetadataPaths = new Set([
  ...["BeginRegistryPublicationManifest", "AppendRegistryPublicationManifest", "SealRegistryPublicationManifest",
    "CommitRegistryPublication", "ListRegistryPublications", "GetRegistryPublication"]
    .map(method => `/aos.hub.v1.PublishService/${method}`),
  "/aos.hub.v1.RegistryService/GetRegistry",
  "/aos.hub.v1.IdentityService/WhoAmI",
  "/aos.hub.v1.DirectUploadService/GrantPartsBatch",
  ...["GetCapabilities", "BeginBatch", "StatusBatch", "ReportPartsBatch", "CompleteBatch", "Abort"]
    .map(method => `/aos.hub.v1.DirectUploadService/${method}`),
]);

const storageFrames = new Map([
  ["/_internal/storage/v1/execute", "x-aos-storage-work-signature"],
  ["/_internal/storage/v1/capabilities", "x-aos-storage-work-signature"],
  ["/_internal/storage/direct-upload-authority", "x-aos-direct-authority-signature"],
  ["/_internal/storage/direct-upload-final-guard", "x-aos-direct-final-guard-signature"],
  ["/_internal/storage/direct-upload-deployment", "x-aos-direct-deployment-signature"],
]);

export async function sha256(bytes) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    byte => byte.toString(16).padStart(2, "0")).join("");
}

export function checkedCapturePolicy(value) {
  const fields = ["version", "corpusId", "windowId", "sourceCommit", "sourceTree",
    "runtimeSourceDigest", "nativeExecutableSha256", "workerSourceDigest",
    "captureImplementationSha256", "startsAt", "expiresAt", "capturePrefix",
    "storageOrigin", "originProxyOrigin", "originRoutes", "maximumBodyBytes", "maximumCorpusBytes"];
  if (!value || Object.keys(value).length !== fields.length || fields.some(field => !(field in value))
      || value.version !== 1 || !idPattern.test(value.corpusId) || !idPattern.test(value.windowId)
      || !/^[0-9a-f]{40}$/.test(value.sourceCommit) || !/^[0-9a-f]{40}$/.test(value.sourceTree)
      || !["runtimeSourceDigest", "nativeExecutableSha256", "workerSourceDigest",
        "captureImplementationSha256"].every(field => digestPattern.test(value[field]))
      || !Number.isSafeInteger(value.startsAt) || !Number.isSafeInteger(value.expiresAt)
      || value.expiresAt <= value.startsAt || value.expiresAt - value.startsAt > 3600
      || value.maximumBodyBytes !== BODY_LIMIT || value.maximumCorpusBytes !== CORPUS_LIMIT
      || value.capturePrefix !== `private-capture/${value.corpusId}/`
      || !Array.isArray(value.originRoutes) || value.originRoutes.length > 64) {
    throw new Error("closed capture policy refused");
  }
  for (const field of ["storageOrigin", "originProxyOrigin"]) {
    const url = new URL(value[field]);
    if (url.origin !== value[field] || url.protocol !== "https:" || url.username || url.password) {
      throw new Error("capture origin refused");
    }
  }
  const routes = new Set();
  for (const route of value.originRoutes) {
    if (!route || Object.keys(route).sort().join(",") !== "method,path,purpose"
        || !(route.method === "POST" && originMetadataPaths.has(route.path)
          || route.method === "GET" && route.path === "/-/instance")
        || !/^[a-z][a-z0-9-]{0,47}$/.test(route.purpose)
        || routes.has(`${route.method} ${route.path}`)) throw new Error("capture metadata route refused");
    routes.add(`${route.method} ${route.path}`);
  }
  return Object.freeze({ ...value, originRoutes: value.originRoutes.map(route => Object.freeze({ ...route })) });
}

function selection(request, role, policy) {
  const url = new URL(request.url);
  if (url.origin !== (role === "origin_proxy" ? policy.originProxyOrigin : policy.storageOrigin)) return null;
  if (role === "origin_proxy") {
    // This same endpoint also returns delegated provider grants to clients.
    // Select only the compact Native authorization hop, never the public grant.
    if (url.pathname === "/aos.hub.v1.DirectUploadService/GrantPartsBatch"
        && (request.headers.get("x-aos-hybrid-upload-phase") !== "authorize"
          || !digestPattern.test(request.headers.get("x-aos-direct-upload-logical-signature") ?? ""))) return null;
    return policy.originRoutes.find(route => route.method === request.method && route.path === url.pathname) ?? null;
  }
  if (request.method === "POST" && storageFrames.has(url.pathname)) {
    return { purpose: url.pathname === "/_internal/storage/v1/execute" ? "storage-work"
      : url.pathname === "/_internal/storage/v1/capabilities" ? "storage-capabilities"
        : url.pathname.slice("/_internal/storage/".length), method: "POST", path: url.pathname };
  }
  return null;
}

function privateFrames(headers, direction, role, path) {
  const names = role === "origin_proxy"
    ? [...(direction === "received_request" ? ["x-aos-hybrid-ingress"] : []),
      "x-aos-direct-upload-logical-signature", "x-aos-hybrid-upload-phase"]
    : [storageFrames.get(path)];
  const result = [];
  for (const name of names) {
    const value = headers.get(name);
    if (value === null) continue;
    const bytes = encoder.encode(value);
    if (bytes.length > (name === "x-aos-hybrid-ingress" ? 16384 : 128)) {
      return { state: "overflow", values: [] };
    }
    if ((name === "x-aos-hybrid-ingress" && !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(value))
        || (name.endsWith("signature") && !digestPattern.test(value))
        || (name === "x-aos-hybrid-upload-phase"
          && !["admission", "authorize", "commit", "abort-report"].includes(value))) {
      return { state: "unknown", values: [] };
    }
    result.push({ name, bytes });
  }
  return { state: "bounded", values: result };
}

function safeImage(bytes) {
  // Credential routes are never selected. Reject a body containing a URL query
  // rather than exporting a possible delegated provider URL or redacting bytes.
  try {
    const text = decoder.decode(bytes);
    return !/https?:\/\/[^\s"'<>]*\?[^\s"'<>]*/i.test(text)
      && !/"(?:authorization|cookie|password|secret[_-]?key|secret[_-]?access[_-]?key|private[_-]?key|access[_-]?key[_-]?(?:id|secret)|googleInvokerIdToken)"\s*:/i.test(text);
  }
  catch { return false; }
}

function join(chunks, length) {
  const result = new Uint8Array(length);
  let position = 0;
  for (const chunk of chunks) { result.set(chunk, position); position += chunk.byteLength; }
  return result;
}

function background(context, work) {
  // No observation failure replaces the application or transport's result.
  const safe = work.catch(() => {});
  try { context.waitUntil(safe); } catch { /* persistence remains unknown */ }
}

function tap(body, headers, signal, direction, base, policy, sink, context, beginning) {
  const frames = privateFrames(headers, direction, base.role, base.selectedPath);
  const chunks = [];
  let retained = 0, observed = 0, overflow = false, finished = false;
  const started = Date.now();
  const reader = body?.getReader();

  function finish(state, eof) {
    if (finished) return;
    finished = true;
    signal?.removeEventListener("abort", aborted);
    let bytes = new Uint8Array(), imageAllowed = false;
    try { bytes = join(chunks, retained); imageAllowed = safeImage(bytes); }
    catch { state = "unknown"; }
    chunks.length = 0;
    const { selectedPath, ...publicBase } = base;
    const observation = { ...publicBase, direction,
      provenance: direction === "received_request" ? "independent_wrapper_received_bytes" : "wrapper_exposed_reply_bytes",
      state: overflow ? "overflow" : state,
      observedBytes: String(observed), retainedBytes: String(imageAllowed ? retained : 0), eof,
      imageKind: eof && !overflow && imageAllowed
        ? direction === "received_request" ? "complete_received_image" : "complete_wrapper_reply_image"
        : "bounded_prefix_or_missing",
      frameState: frames.state, startedAtMillis: String(started), finishedAtMillis: String(Date.now()),
      responseConsumptionClaim: false };
    if (!imageAllowed) observation.state = "unknown";
    background(context, beginning.then(() => sink.finish(observation,
      imageAllowed ? bytes : new Uint8Array(), frames.values)).finally(() => {
        retainedMemory -= retained;
      }));
  }

  function aborted() { finish("cancelled", false); }
  if (signal?.aborted) aborted();
  else signal?.addEventListener("abort", aborted, { once: true });
  if (!reader) { finish("eof", true); return { body: null, abandon: () => {} }; }

  const stream = new ReadableStream({
    async pull(controller) {
      try {
        const value = await reader.read();
        if (value.done) {
          controller.close(); finish("eof", true); reader.releaseLock(); return;
        }
        try {
          if (!finished) {
            observed += value.value.byteLength;
            const available = Math.min(BODY_LIMIT - retained, MEMORY_LIMIT - retainedMemory);
            if (available > 0) {
              const prefix = value.value.slice(0, available);
              chunks.push(prefix); retained += prefix.byteLength; retainedMemory += prefix.byteLength;
            }
            if (observed > BODY_LIMIT || observed > retained) overflow = true;
          }
        } catch { finish("unknown", false); }
        // The actual chunk is forwarded untouched, including after overflow.
        controller.enqueue(value.value);
      } catch (error) { finish("unknown", false); controller.error(error); }
    },
    async cancel(reason) {
      finish("cancelled", false);
      try { await reader.cancel(reason); } finally { reader.releaseLock(); }
    },
  }, { highWaterMark: 0 });
  return { body: stream, abandon: () => finish("unknown", false) };
}

export function createObservedHandler(delegate, role, configuration, sink, clock = () => Math.floor(Date.now() / 1000)) {
  const policy = checkedCapturePolicy(configuration);
  if (!["origin_proxy", "storage_wrapper"].includes(role)) throw new Error("capture role refused");
  return async function handle(request, env, context) {
    const route = selection(request, role, policy), now = clock();
    if (!route || now < policy.startsAt || now >= policy.expiresAt) return delegate(request, env, context);
    let base, input, beginning;
    try {
      const url = new URL(request.url);
      const transport = request.headers.get("x-aos-storage-call-id");
      const ingress = request.headers.get("x-aos-fleet-request-id");
      base = { version: 1, captureId: crypto.randomUUID().replaceAll("-", ""),
        corpusId: policy.corpusId, windowId: policy.windowId, role, purpose: route.purpose,
        sourceCommit: policy.sourceCommit, sourceTree: policy.sourceTree,
        runtimeSourceDigest: policy.runtimeSourceDigest, nativeExecutableSha256: policy.nativeExecutableSha256,
        workerSourceDigest: policy.workerSourceDigest, captureImplementationSha256: policy.captureImplementationSha256,
        transportCallId: idPattern.test(transport ?? "") ? transport : null,
        requestId: idPattern.test(ingress ?? "") ? ingress : null,
        method: request.method, pathSha256: await sha256(encoder.encode(url.pathname)),
        queryClass: url.search ? "unsupported" : "absent", status: null,
        provenance: "independent_wrapper_received_bytes", instrumentationTraffic: true };
      beginning = Promise.resolve().then(() => sink.begin(base));
      background(context, beginning);
      if (url.search) {
        // Do not inspect a query-bearing body or protocol frame. The pending
        // call remains explicit and its request observation is incomplete.
        background(context, beginning.then(() => sink.finish({ ...base,
          direction: "received_request", state: "unknown", observedBytes: "0", retainedBytes: "0",
          eof: false, imageKind: "bounded_prefix_or_missing", frameState: "unknown",
          startedAtMillis: String(Date.now()), finishedAtMillis: String(Date.now()),
          responseConsumptionClaim: false }, new Uint8Array(), [])));
        return delegate(request, env, context);
      }
      input = tap(request.body, request.headers, request.signal, "received_request",
        { ...base, selectedPath: route.path }, policy, sink, context, beginning);
    } catch { return delegate(request, env, context); }

    const selected = new Request(request, { body: input.body, signal: request.signal,
      ...(input.body ? { duplex: "half" } : {}) });
    let response;
    try { response = await delegate(selected, env, context); }
    catch (error) { input.abandon(); throw error; }
    input.abandon();
    const output = tap(response.body, response.headers, request.signal, "exposed_response",
      { ...base, selectedPath: route.path, status: response.status }, policy, sink, context, beginning);
    return new Response(output.body, { status: response.status, statusText: response.statusText,
      headers: response.headers });
  };
}
