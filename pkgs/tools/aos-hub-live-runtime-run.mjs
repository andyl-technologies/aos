// Executes actual controlled Rust stream/query routes and retains exact controls.
// Native authorization and hosted acceptance remain UNKNOWN in this experiment.

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import diagnostics from "node:diagnostics_channel";
import { readFile, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  liveCorpusCases, sourceSequenceWatermark, selectLiveSourceRequest,
  liveMetadataOverlap, validateLiveSourceAttempt, validateLiveRefusal, validateLiveStatusRefusal,
  liveHeldAdmissionExpired,
} from "./aos-hub-live-runtime-corpus.mjs";

if (!process.execPath.startsWith("/nix/store/") || !process.argv[2]) throw new Error("Explicit source-built runner and fixture root required");
const root = resolve(process.argv[2]);
const runtime = JSON.parse(await readFile(join(root, "live-runtime.json")));
const plan = JSON.parse(await readFile(join(root, "live-plan.json")));
const { origin, pid, startTicks } = JSON.parse(await readFile(join(root, "live-ready.json")));
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(origin)) throw new Error("Only the closed loopback runtime is permitted");
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
async function privateKey(path) {
  const info = await stat(path);
  if (!info.isFile() || (info.mode & 0o077) || info.size < 32 || info.size > 4096) throw new Error("Private fixture key custody required");
  return readFile(path);
}
const streamKey = await privateKey(plan.streamKeyFile);
const queryKey = await privateKey(plan.queryKeyFile);
if (streamKey.equals(queryKey)) throw new Error("Controlled query and stream key roles must differ");
const sign = (key, domain, bytes) => createHmac("sha256", key)
  .update("aos-storage-work-v1\0").update(domain).update(bytes).digest("hex");

// Only the sequential cancellation control owns a socket association. Metadata
// concurrency and every other request keep their existing transport behavior.
let pendingCancellation = null;
diagnostics.channel("undici:client:sendHeaders").subscribe(({ socket, request }) => {
  if (!pendingCancellation || request.path !== "/__hub/mirror-live-candidate") return;
  pendingCancellation.assignments += 1;
  pendingCancellation.socket = socket;
});

function resetCancellation(opened, clientBytes) {
  const association = opened.cancellation;
  const socket = association?.socket;
  if (!association || association.controlId !== opened.id || association.assignments !== 1
      || !socket || socket.remoteAddress !== "127.0.0.1" || socket.remotePort !== Number(new URL(origin).port)
      || !Number.isInteger(socket.localPort) || socket.destroyed || socket.connecting
      || typeof socket.resetAndDestroy !== "function") {
    throw new Error("The exact cancellation request socket is unavailable");
  }

  // Closing an HTTP read-half can leave the server's write-half valid. This
  // controlled case deliberately tears down the connection before reader.cancel.
  const facts = {
    transport: "explicit_tcp_reset", controlId: opened.id, clientBytes,
    localPort: socket.localPort, remotePort: socket.remotePort,
    resetStartedUtcMilliseconds: Date.now(), resetRequestedUtcMilliseconds: null,
    socketClosedUtcMilliseconds: null, socketClosedHadError: null,
  };
  opened.cancellationFacts = facts;
  socket.once("close", hadError => {
    facts.socketClosedUtcMilliseconds = Date.now();
    facts.socketClosedHadError = hadError;
  });
  socket.resetAndDestroy();
  facts.resetRequestedUtcMilliseconds = Date.now();
}

const records = [];
const results = [];
let sequence = 0;

async function memorySample() {
  try {
    if (!Number.isSafeInteger(pid) || pid <= 0) return null;
    const processStat = await readFile(`/proc/${pid}/stat`, "utf8");
    if (processStat.slice(processStat.lastIndexOf(")") + 2).split(" ")[19] !== startTicks) return null;
    const status = await readFile(`/proc/${pid}/status`, "utf8");
    const rss = /^VmRSS:\s+(\d+) kB$/m.exec(status);
    const peak = /^VmHWM:\s+(\d+) kB$/m.exec(status);
    const response = await fetch(origin + "/__fixture/live-memory");
    const wasm = response.ok ? await response.json() : null;
    return {
      processResidentBytes: rss ? Number(rss[1]) * 1024 : null,
      processPeakResidentBytes: peak ? Number(peak[1]) * 1024 : null,
      wasmBytes: wasm?.wasmBytes ?? null,
      scope: "Actual controlled multi-service process and Wasm observations; not hosted per-worker memory qualification",
    };
  } catch {
    return null;
  }
}

function original(path, method, ttl = 30) {
  const issued = Math.floor(Date.now() / 1000);
  const target = plan.target;
  const candidate = {
    version: 1, run_id: runtime.runId, compiled_source_sha256: runtime.sourceDigest, script_version: runtime.scriptVersion,
    request: {
      version: 1, deployment_id: runtime.vars.HUB_DEPLOYMENT_ID, issued_at: issued, expires_at: issued + ttl,
      request_id: randomBytes(16).toString("hex"), scheme: "https", authority: "hub.example.invalid", method,
      path_and_query: `/.aos-mirror-qualification/${runtime.runId}/${path}`, body_sha256: sha(Buffer.alloc(0)),
      client_ip: "192.0.2.1",
    },
    target: {
      registry_id: target.registry_id, registry_resource_version: target.registry_resource_version,
      mirror_resource_version: target.mirror_resource_version, placement_id: target.placement_id,
      placement_resource_version: target.placement_resource_version, write_spec_version: target.write_spec_version,
      placement_prefix: `.aos-mirror-qualification/${runtime.runId}/final`, binding_id: target.binding_id,
      binding_resource_version: target.binding_resource_version, protected_profile_digest: target.protected_profile_digest,
      upstream_base: `https://upstream.example.invalid/.aos-mirror-qualification/${runtime.runId}`, path,
      class: path.startsWith("objects/pack/") ? "pack" : "metadata",
      maximum_bytes: path.startsWith("objects/pack/") ? 16 * 1024 * 1024 : 128 * 1024,
    },
  };
  return candidate;
}

async function openControl(spec) {
  const candidate = original(spec.path, spec.method ?? "GET", spec.ttlSeconds);
  if (spec.substitution === "unsafe_source") candidate.target.upstream_base = "https://127.0.0.1/";
  const query = spec.route === "query";
  const control = query ? { version: 1, nonce: randomBytes(16).toString("hex"), candidate } : candidate;
  let bytes = Buffer.from(JSON.stringify(control));
  const domain = query ? "aos.hub.mirror-live-query-controlled-candidate.v1\0" : "aos.hub.mirror-live-controlled-candidate.v1\0";
  const signature = sign(query ? queryKey : streamKey, domain, bytes);
  if (spec.substitutionAfterSigning) {
    candidate.request.request_id += "x";
    bytes = Buffer.from(JSON.stringify(control));
  }
  const id = ++sequence;
  await writeFile(join(root, `live-control-${id}.json`), bytes, { flag: "wx", mode: 0o600 });
  const admissionSources = await sourceObservations();
  const sourceWatermark = sourceSequenceWatermark(admissionSources);
  const started = performance.now();
  const dispatchStartedUtcMilliseconds = Date.now();
  const cancellation = spec.cancelAfterBytes ? { controlId: id, assignments: 0, socket: null } : null;
  if (cancellation && pendingCancellation) throw new Error("Cancellation controls must be sequential");
  let response;
  if (cancellation) pendingCancellation = cancellation;
  try {
    response = await fetch(origin + (query ? "/__hub/mirror-live-query-candidate" : "/__hub/mirror-live-candidate"), {
      method: "POST", headers: { "x-aos-storage-work-signature": signature, "content-type": "application/json" }, body: bytes,
      signal: AbortSignal.timeout(610000),
    });
  } finally {
    if (cancellation) pendingCancellation = null;
  }
  const responseReceivedUtcMilliseconds = Date.now();
  const opened = { id, control, requestBytes: bytes, response, started, query, spec, sourceWatermark,
    admissionSources, dispatchStartedUtcMilliseconds, responseReceivedUtcMilliseconds, cancellation };
  opened.initialSourceIdentity = await captureSourceIdentity(opened);
  return opened;
}

async function captureSourceIdentity(opened) {
  if (opened.spec.sourceStatus === undefined) return null;
  const observations = await sourceObservations();
  try {
    return selectLiveSourceRequest(observations, opened.sourceWatermark, opened.spec.path, opened.spec.method ?? "GET");
  } catch {
    // Missing/ambiguous dispatch cannot become successful negative coverage.
    return null;
  }
}

async function bodyRecord(opened, responseSha256, clientBytes, streamErrored, cancelled) {
  return {
    id: opened.id, route: opened.query ? "query" : "stream", path: opened.spec.path, status: opened.response.status,
    requestSha256: sha(opened.requestBytes), requestBytes: opened.requestBytes.length,
    responseSha256, clientBytes, streamErrored, cancelled,
    clientCancellation: opened.cancellationFacts ?? null,
    wallMilliseconds: performance.now() - opened.started,
    sourceWatermark: opened.sourceWatermark,
    sourceIdentity: opened.initialSourceIdentity ?? await captureSourceIdentity(opened),
    admissionSources: opened.admissionSources,
    dispatchStartedUtcMilliseconds: opened.dispatchStartedUtcMilliseconds,
    responseReceivedUtcMilliseconds: opened.responseReceivedUtcMilliseconds,
    requestIssuedAt: (opened.query ? opened.control.candidate : opened.control).request.issued_at,
    requestExpiresAt: (opened.query ? opened.control.candidate : opened.control).request.expires_at,
    memory: await memorySample(),
    nativeAuthorizationHeaderBytes: null, nativeBulkBytes: null,
    scope: "Controlled candidate; Native authorization and production acceptance UNKNOWN",
  };
}

async function consume(opened) {
  const { response, query, spec } = opened;
  const hash = createHash("sha256");
  const queryChunks = [];
  let clientBytes = 0;
  let streamErrored = false;
  let cancelled = false;
  const reader = response.body?.getReader();
  try {
    if (reader) while (true) {
      const { value, done } = await reader.read();
      if (value?.length) {
        clientBytes += value.length;
        if (clientBytes > (query ? 256 * 1024 : 16 * 1024 * 1024 + 4096)) throw new Error("Actual response exceeded corpus bound");
        hash.update(value);
        if (query) queryChunks.push(Buffer.from(value));
        if (spec.cancelAfterBytes && clientBytes >= spec.cancelAfterBytes) {
          resetCancellation(opened, clientBytes);
          await reader.cancel();
          cancelled = true;
          break;
        }
      }
      if (done) break;
    }
  } catch {
    streamErrored = true;
    await reader?.cancel().catch(() => {});
  } finally {
    reader?.releaseLock();
  }
  const record = await bodyRecord(opened, hash.digest("hex"), clientBytes, streamErrored, cancelled);
  if (query && response.ok) {
    const body = Buffer.concat(queryChunks);
    await writeFile(join(root, `live-query-reply-${opened.id}.json`), body, { flag: "wx", mode: 0o600 });
    const actualSignature = response.headers.get("x-aos-storage-work-signature");
    const expected = sign(queryKey, "aos.hub.mirror-live-query-controlled-candidate.reply.v1\0", body);
    if (!/^[a-f0-9]{64}$/.test(actualSignature ?? "") || !timingSafeEqual(Buffer.from(actualSignature, "hex"), Buffer.from(expected, "hex"))) {
      throw new Error("Actual query reply authentication refused");
    }
    const reply = JSON.parse(body);
    const content = Buffer.from(reply.outcome.content_base64 ?? "", "base64");
    const latest = Math.floor(Date.now() / 1000) + Number(runtime.vars.HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS);
    if (reply.version !== 1 || reply.request_sha256 !== sha(opened.requestBytes) || reply.nonce !== opened.control.nonce
        || reply.observed_at < opened.control.candidate.request.issued_at
        || !Number.isSafeInteger(latest) || reply.observed_at > latest || latest >= opened.control.candidate.request.expires_at
        || reply.observed_at >= opened.control.candidate.request.expires_at
        || reply.outcome.kind !== "mirror_live_metadata" || !content.length || content.length > 128 * 1024
        || reply.outcome.size !== content.length || reply.source_bytes !== content.length || reply.outcome.sha256 !== sha(content)) {
      throw new Error("Actual query original or bounded bytes differ");
    }
    record.querySourceBytes = reply.source_bytes;
    record.queryReplyBytes = body.length;
    record.queryOutputSha256 = reply.outcome.sha256;
  }
  records.push(record);
  return record;
}

async function sourceObservations() {
  const response = await fetch(origin + "/__fixture/live-observations");
  if (!response.ok) throw new Error("Actual source observations unavailable");
  return response.json();
}

try {
  for (const spec of liveCorpusCases) {
    const before = await sourceObservations();
    const beforeSequence = sourceSequenceWatermark(before);
    const actual = [];
    const attempts = [];
    let auxiliary = [];
    let metadataBeforeBulkEOF = null;
    let concurrentMemory = null;
    if (spec.queuedBehind) {
      // Sequential header admission gives each held source a unique original
      // watermark before the next identical fixture path can be dispatched.
      for (const path of spec.queuedBehind) {
        auxiliary.push(await openControl({ route: "stream", path, method: "GET", sourceStatus: 200 }));
      }
    }
    const opened = await openControl(spec);
    if (spec.concurrentMetadata) {
      const reader = opened.response.body?.getReader();
      let prefix = new Uint8Array(0);
      let streamErrored = false;
      let cancelled = false;
      const metadata = [];
      let bulkIdentity = null;
      try {
        if (reader) {
          const first = await reader.read();
          prefix = first.value ?? prefix;
        }
        bulkIdentity = await captureSourceIdentity(opened);
        const pairs = await Promise.all(spec.concurrentMetadata.map(async path => {
          const metadataSpec = { route: "stream", path, method: "GET", sourceStatus: 200 };
          return { spec: metadataSpec, record: await consume(await openControl(metadataSpec)) };
        }));
        metadata.push(...pairs.map(item => item.record));
        attempts.push(...pairs);
        const middle = await sourceObservations();
        metadataBeforeBulkEOF = bulkIdentity !== null && liveMetadataOverlap(bulkIdentity, middle, metadata);
        concurrentMemory = await memorySample();
      } catch {
        streamErrored = true;
      } finally {
        if (reader) {
          await reader.cancel();
          cancelled = true;
          reader.releaseLock();
        }
      }
      const bulk = await bodyRecord(opened, sha(prefix), prefix.length, streamErrored, cancelled);
      if (bulk.sourceIdentity?.sequence !== bulkIdentity?.sequence) bulk.sourceIdentity = null;
      records.push(bulk);
      actual.push(bulk, ...metadata);
      attempts.push({ spec, record: bulk });
    } else {
      const record = await consume(opened);
      actual.push(record);
      attempts.push({ spec, record });
    }
    for (let index = 1; index < (spec.repeat ?? 1); index++) {
      const record = await consume(await openControl(spec));
      actual.push(record);
      attempts.push({ spec, record });
    }
    if (spec.additionalAttempt) {
      const record = await consume(await openControl(spec.additionalAttempt));
      actual.push(record);
      attempts.push({ spec: spec.additionalAttempt, record });
    }
    const heldRecords = await Promise.all(auxiliary.map(consume));
    await new Promise(resolve => setTimeout(resolve, 100));
    const after = await sourceObservations();
    sourceSequenceWatermark(after);
    const fresh = after.filter(item => item.sequence > beforeSequence);
    const originalDispatches = after.filter(item => item.sequence > opened.sourceWatermark).length;
    const violations = validateLiveRefusal(spec, actual[0], originalDispatches);
    for (const attempt of attempts) {
      if (attempt.spec.sourceStatus === undefined) continue;
      const identity = attempt.record.sourceIdentity;
      const source = identity && after.find(entry => entry.sequence === identity.sequence && entry.path === identity.path && entry.method === identity.method);
      violations.push(...validateLiveSourceAttempt(attempt.spec, source).map(code => `${attempt.record.id}:${code}`));
      violations.push(...validateLiveStatusRefusal(attempt.spec, attempt.record).map(code => `${attempt.record.id}:${code}`));
      if (attempt.spec.expectStreamError && !(attempt.record.streamErrored || attempt.record.status >= 400)) violations.push(`${attempt.record.id}:length_refusal`);
    }
    if (spec.queuedBehind && !liveHeldAdmissionExpired(actual[0], heldRecords,
      Number(runtime.vars.HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS), originalDispatches)) {
      violations.push("expired_admission_wait_not_observed");
    }
    if (spec.expectedClientBytes !== undefined && actual[0].clientBytes !== spec.expectedClientBytes) violations.push("client_bytes");
    if (spec.expectedStatus !== undefined && actual[0].status !== spec.expectedStatus) violations.push("status");
    if (spec.requireChangedBody && actual[0].responseSha256 === actual[1].responseSha256) violations.push("fresh_pointer");
    if (spec.expectStreamError && !(actual[0].streamErrored || actual[0].status >= 400)) violations.push("length_refusal");
    const originalSource = actual[0].sourceIdentity && after.find(item => item.sequence === actual[0].sourceIdentity.sequence);
    if (spec.requireSourceCancellation && originalSource?.cancelled !== true) violations.push("source_cancel");
    if (spec.cancelAfterBytes && (actual[0].clientCancellation?.transport !== "explicit_tcp_reset"
        || !Number.isSafeInteger(actual[0].clientCancellation?.resetRequestedUtcMilliseconds))) violations.push("client_reset");
    if (spec.requireMetadataBeforeBulkEOF && !metadataBeforeBulkEOF) violations.push("metadata_capacity");
    if (spec.requirePositiveQueryReply && !(actual[0].querySourceBytes > 0 && actual[0].queryReplyBytes <= 256 * 1024)) violations.push("actual_query");
    results.push({ case: spec.name, controlledState: violations.length ? "FAIL" : "PASS", productionState: "UNKNOWN", violations, controls: actual.map(item => item.id), source: fresh, concurrentMemory });
    await writeFile(join(root, "live-corpus-progress.json"), JSON.stringify({ records, results }, null, 2), { mode: 0o600 });
  }
} finally {
  await writeFile(join(root, "live-corpus-final.json"), JSON.stringify({
    compiledSourceSha256: runtime.sourceDigest, records, results,
    scope: "Actual controlled candidate transport only; no Hosted acceptance, whole-worker budget or Native authorization claim",
  }, null, 2), { flag: "wx", mode: 0o600 });
}
if (results.length !== 13 || results.some(item => item.controlledState !== "PASS")) process.exitCode = 1;
