// Protected private-stage/queue qualification using actual provider uploads.
// Requires source-built Node on Linux (/proc/self/fd held-directory writes).
// Output is observation evidence only. No reviewer key or acceptance is minted.

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Readable } from "node:stream";

const options = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index], value = process.argv[index + 1];
  if (!name?.startsWith("--") || value === undefined || options.has(name)) {
    throw new Error("Expected unique --name value arguments.");
  }
  options.set(name, value);
}
const required = name => {
  const value = options.get(name);
  if (!value) throw new Error(`Required argument ${name} is missing.`);
  return value;
};
const endpoint = new URL(required("--origin"));
if (endpoint.protocol !== "https:" || endpoint.origin !== required("--origin")) {
  throw new Error("Use an exact HTTPS origin.");
}
const phase = options.get("--phase") ?? "run";
if (!["run", "status", "requeue", "clock"].includes(phase)) throw new Error("Unknown phase.");
const wait = Number(options.get("--wait-seconds") ?? "600");
if (!Number.isInteger(wait) || wait < 0 || wait > 3600) throw new Error("Bounded wait must be 0..3600 seconds.");
const runId = options.get("--run-id") ?? randomBytes(32).toString("hex");
if (!/^[a-f0-9]{64}$/.test(runId) || (phase !== "run" && !options.has("--run-id"))) {
  throw new Error("Recovery requires the exact original 64-hex run ID.");
}
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const sorted = value => Array.isArray(value) ? value.map(sorted)
  : value !== null && typeof value === "object"
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
const canonicalHash = value => hash(Buffer.from(JSON.stringify(sorted(value))));

async function privateFile(path, maximum = 262144) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const stat = await handle.stat();
  if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0 || stat.size > maximum || stat.nlink !== 1) {
    await handle.close();
    throw new Error("Private inputs must be owner-only regular files within bounds.");
  }
  try { return await handle.readFile(); } finally { await handle.close(); }
}
const key = (await privateFile(required("--control-key-file"), 4096)).toString("utf8").trim();
if (key.length < 32) throw new Error("Malformed control key.");
const identityDocument = JSON.parse(await privateFile(required("--identity-file")));
const identity = identityDocument.identity ?? identityDocument;
if (!/^[a-f0-9]{64}$/.test(identity.sourceDigest) || typeof identity.scriptVersion !== "string"
    || identity.publicOrigin !== endpoint.origin) throw new Error("Actual inspected identity does not match origin.");
const output = resolve(required("--output-dir"));
await mkdir(output, { recursive: true, mode: 0o700 });
const outputHandle = await open(output, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
const outputStat = await outputHandle.stat();
if (outputStat.uid !== process.getuid() || (outputStat.mode & 0o077) !== 0) {
  throw new Error("Evidence directory must be owner-only.");
}
const heldOutput = `/proc/self/fd/${outputHandle.fd}`;
if ((await readdir(heldOutput)).length) throw new Error("Use an empty evidence directory.");
const files = [];
async function save(name, value, raw = false) {
  const bytes = raw ? value : Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  const handle = await open(join(heldOutput, name), constants.O_WRONLY | constants.O_CREAT
    | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
  files.push({ name, sha256: hash(bytes) });
}
let sequence = 0, cancelled = false;
const active = new Set();
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => { cancelled = true; for (const controller of active) controller.abort(); });
}
async function observe(kind, intent, dispatch, timeout = 30000) {
  // Wire action names stay unchanged; retained filenames use the collector's
  // closed lower-kebab spelling. The unique sequence and create-only save keep
  // two dispatches from overwriting one another after normalization.
  const filenameKind = kind.replaceAll("_", "-");
  if (!/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(filenameKind) || filenameKind.length > 64) {
    throw new Error("Observation kind cannot form a bounded evidence filename.");
  }
  const name = `${String(++sequence).padStart(5, "0")}-${filenameKind}`;
  if (cancelled) { await save(`${name}-cancelled.json`, { ...intent, state: "cancelled_before_dispatch" });
    throw new Error("Cancellation prevents further effects."); }
  await save(`${name}-pending.json`, { ...intent, state: "pending" });
  const controller = new AbortController(); active.add(controller);
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    if (cancelled) controller.abort();
    if (controller.signal.aborted) throw new Error("Cancelled before dispatch.");
    return await dispatch(controller.signal, name);
  } catch {
    await save(`${name}-unknown.json`, { ...intent, state: "unknown", cause: controller.signal.aborted
      ? "deadline_or_cancellation" : "dispatch_or_reply_unknown" });
    throw new Error("Operation lacks an exact acknowledgement; evidence retained without replay.");
  } finally { clearTimeout(timer); active.delete(controller); }
}
async function bounded(response, maximum) {
  const chunks = []; let size = 0;
  for await (const chunk of response.body ?? []) {
    size += chunk.byteLength;
    if (size > maximum) throw new Error("Reply exceeds the bounded control contract.");
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
const mac = (domain, body) => createHmac("sha256", key).update("aos-storage-work-v1\0")
  .update(domain).update(body).digest("hex");
async function control(action) {
  const request = { version: 1, runId, nonce: randomBytes(32).toString("hex"),
    sourceDigest: identity.sourceDigest, scriptVersion: identity.scriptVersion,
    expiresAt: String(Math.floor(Date.now() / 1000) + 30), action };
  const body = Buffer.from(JSON.stringify(request));
  if (body.length > 262144) throw new Error("Control exceeds protocol byte limit.");
  return observe(action.kind, { runId, requestSha256: hash(body) }, async (signal, name) => {
    if (phase === "clock") await save(`${name}-request.json`, body, true);
    const sent = Date.now();
    const response = await fetch(new URL("/_internal/storage/direct-upload-qualification", endpoint), {
      method: "POST", body, headers: { "content-type": "application/json",
        "x-aos-direct-qualification-signature": mac("aos.direct-upload.qualification-request.v1\0", body) },
      redirect: "manual", signal,
    });
    const bytes = await bounded(response, 262144), received = Date.now();
    const signature = response.headers.get("x-aos-direct-qualification-signature") ?? "";
    const expected = mac("aos.direct-upload.qualification-reply.v1\0", bytes);
    if (!/^[a-f0-9]{64}$/.test(signature) || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
      throw new Error("Reply authentication failed.");
    }
    const reply = JSON.parse(bytes);
    if (reply.nonce !== request.nonce || reply.requestSha256 !== hash(body)) throw new Error("Reply correlation failed.");
    const inspection = action.kind === "status" || action.kind === "inspect";
    if (!inspection && (reply.sourceDigest !== identity.sourceDigest || reply.scriptVersion !== identity.scriptVersion)) {
      throw new Error("Reply runtime identity differs from the protected deployment inspection.");
    }
    if (phase === "clock") {
      const expected = required("--clock-uncertainty-seconds");
      const keys = Object.keys(reply).sort().join(",");
      const result = reply.result;
      if (keys !== "nonce,observedAtMillis,requestSha256,result,scriptVersion,sourceDigest,version"
          || reply.version !== 1 || !result || Object.keys(result).sort().join(",")
            !== "kind,nonce,observedAtMillis,uncertaintySeconds"
          || result.kind !== "clock" || result.nonce !== request.nonce
          || !/^(?:[1-9]|1[0-9]|2[0-9])$/.test(expected)
          || result.uncertaintySeconds !== expected
          || typeof result.observedAtMillis !== "string"
          || !/^[1-9][0-9]{0,19}$/.test(result.observedAtMillis)
          || typeof reply.observedAtMillis !== "string"
          || !/^[1-9][0-9]{0,19}$/.test(reply.observedAtMillis)
          || Number(result.observedAtMillis) < sent - Number(expected) * 1000
          || Number(result.observedAtMillis) > received + Number(expected) * 1000) {
        throw new Error("Source-only Clock reply schema or observation differs.");
      }
    }
    const capture = { status: response.status, requestSha256: hash(body), responseSha256: hash(bytes),
      sentAtMillis: String(sent), receivedAtMillis: String(received), replySignature: signature };
    // Direct grants contain bearer URLs and are never written to evidence.
    if (action.kind !== "grant") {
      await save(`${name}-capture.json`, bytes, true);
      await save(`${name}-authentication.json`, capture);
    } else { await save(`${name}-acknowledgement.json`, { ...capture, replySignature: undefined }); }
    if (!response.ok) throw new Error("Protected control refused or remains unknown.");
    return { result: reply.result, responseSha256: hash(bytes), sent, received,
      observedAtMillis: reply.observedAtMillis, captureFile: action.kind === "grant" ? null : `${name}-capture.json` };
  });
}

async function describe(file, metadata) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    return await inspectSource(handle, metadata);
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function inspectSource(handle, metadata) {
  const before = await handle.stat();
  if (!before.isFile() || before.uid !== process.getuid() || before.size <= 0 || !Number.isSafeInteger(before.size)) {
    throw new Error("Payload must be an owned nonempty regular file.");
  }
  const size = before.size, partSize = 8 * 1024 * 1024, parts = [];
  if (metadata && size > 256 * 1024) throw new Error("Narinfo fixture exceeds the production semantic parser limit.");
  const whole = createHash("sha256"), scratch = Buffer.alloc(65536);
  for (let offset = 0, number = 1; offset < size; offset += partSize, number += 1) {
    const bytes = Math.min(partSize, size - offset), sha = createHash("sha256"), md5 = createHash("md5");
    let read = 0;
    while (read < bytes) {
      if (cancelled) throw new Error("Cancelled during immutable source inspection.");
      const result = await handle.read(scratch, 0, Math.min(scratch.length, bytes - read), offset + read);
      if (!result.bytesRead) throw new Error("Payload changed during hashing.");
      const chunk = scratch.subarray(0, result.bytesRead); whole.update(chunk); sha.update(chunk); md5.update(chunk);
      read += result.bytesRead;
    }
    parts.push({ partNumber: number, offset: String(offset), byteSize: String(bytes), sha256: sha.digest("hex"),
      checksum: { algorithm: "md5", value: md5.digest("base64") } });
  }
  const after = await handle.stat();
  if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
    throw new Error("Payload changed during source inspection.");
  }
  return { handle, before, parts, plan: { objectId: randomBytes(32).toString("hex"), byteSize: String(size),
    expectedSha256: whole.digest("hex"), partSize: String(partSize), metadata } };
}

// Replies carry sorted JSON maps, but the authenticated Report must reproduce
// the declared Core DTO field order exactly. Reject extra/missing fields rather
// than silently eliding a changed grant schema while reconstructing that order.
function reportRecord(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).length !== fields.length
      || fields.some(field => !Object.hasOwn(value, field) || value[field] === undefined)) {
    throw new Error("Report source differs from the closed grant schema.");
  }
  return Object.fromEntries(fields.map(field => [field, value[field]]));
}

function reportPart(part) {
  const result = reportRecord(part, ["partNumber", "offset", "byteSize", "sha256", "checksum"]);
  result.checksum = reportRecord(part.checksum, ["algorithm", "value"]);
  return result;
}

function reportPlacement(placement) {
  return reportRecord(placement, ["placementId", "placementFingerprint", "placementResourceVersion",
    "writeSpecVersion", "bindingId", "bindingResourceVersion", "bindingWriteRevision",
    "profileFingerprint", "privatePolicyDigest", "checksumAlgorithm"]);
}

function reportObservation(objectId, grant, etag) {
  return { session: { sessionId: grant.sessionId, logicalFingerprint: grant.logicalFingerprint },
    placement: reportPlacement(grant.placement), operationId: canonicalHash([objectId, "report", grant.part.partNumber]),
    grantId: grant.grantId, grantRevision: grant.grantRevision,
    observed: { part: reportPart(grant.part), etag } };
}

async function upload(source, grant) {
  const part = grant.part, offset = Number(part.offset), size = Number(part.byteSize);
  return observe("upload-part", { runId, objectId: source.plan.objectId, partNumber: part.partNumber,
    byteSize: part.byteSize, sha256: part.sha256 }, async (signal, name) => {
    const stat = await source.handle.stat();
    if (stat.size !== source.before.size || stat.mtimeMs !== source.before.mtimeMs || stat.ctimeMs !== source.before.ctimeMs) {
      throw new Error("Original payload changed before direct upload.");
    }
    const stream = Readable.from((async function* () {
      let position = 0;
      while (position < size) {
        if (signal.aborted || cancelled) throw new Error("Direct stream cancelled.");
        const buffer = Buffer.alloc(Math.min(65536, size - position));
        const { bytesRead } = await source.handle.read(buffer, 0, buffer.length, offset + position);
        if (!bytesRead) throw new Error("Original payload truncated.");
        position += bytesRead; yield buffer.subarray(0, bytesRead);
      }
    })());
    const started = Date.now();
    const headers = Object.fromEntries(grant.requiredHeaders.map(header => [header.name, header.value]));
    headers["content-length"] = part.byteSize;
    const response = await fetch(grant.url, { method: "PUT", headers, body: stream,
      duplex: "half", redirect: "manual", signal });
    const responseBytes = await bounded(response, 8192), etag = response.headers.get("etag");
    if (!response.ok || !etag || !/^"[^"\\\x00-\x1f\x7f]+"$/.test(etag)) throw new Error("Part lacks positive strong ETag.");
    await save(`${name}-positive.json`, { objectId: source.plan.objectId, partNumber: part.partNumber,
      startedAtMillis: String(started), finishedAtMillis: String(Date.now()), status: response.status,
      responseSha256: hash(responseBytes), etag });
    return reportObservation(source.plan.objectId, grant, etag);
  });
}
async function concurrent(items, maximum, dispatch) {
  let cursor = 0, failure;
  const results = new Array(items.length);
  await Promise.all(Array.from({ length: Math.min(maximum, items.length) }, async () => {
    while (!failure && cursor < items.length) {
      const index = cursor++;
      try { results[index] = await dispatch(items[index]); } catch (error) { failure = error; }
    }
  }));
  if (failure) throw failure;
  return results;
}

async function inspectOriginalObjects(objectIds, { deadline = Infinity, maximumPages = Infinity } = {}) {
  const selected = new Set(objectIds);
  if (!selected.size || selected.size > 32 || selected.size !== objectIds.length
      || objectIds.some(id => !original.objects.some(object => object.objectId === id))) {
    throw new Error("Inspection must select bounded exact original objects.");
  }
  const originalHash = canonicalHash(original), receipts = [];
  let pages = 0;
  for (const object of original.objects.filter(object => selected.has(object.objectId))) {
    let after = 0;
    do {
      if (Date.now() >= deadline || pages >= maximumPages) {
        throw new Error("Diagnostic inspection bound elapsed; remaining attempts are unknown.");
      }
      pages += 1;
      const capture = await control({ kind: "inspect", objectId: object.objectId, afterAttempt: after });
      const page = capture.result;
      if (page.objectId !== object.objectId || canonicalHash(page.original) !== originalHash
          || !Array.isArray(page.attempts) || page.attempts.length > 1
          || (page.nextAttempt !== null && (page.nextAttempt !== after + 1 || page.nextAttempt > 128))) {
        throw new Error("Inspection page differs from the original or bounded cursor.");
      }
      for (const attempt of page.attempts) {
        if (attempt.receipt) receipts.push({ object, receipt: attempt.receipt, closed: page.closed,
          replySha256: capture.responseSha256 });
      }
      after = page.nextAttempt;
    } while (after !== null);
  }
  return receipts;
}

async function waitForMixedRelease(ready, stage = "admission") {
  const selectedFile = resolve(required("--mixed-admission-file"));
  const file = stage === "arm" ? resolve(output, "..", "mixed-arm-release.json") : selectedFile;
  if (selectedFile !== resolve(output, "..", "mixed-admission-release.json")) {
    throw new Error("Mixed release must use the exact owned invocation path.");
  }
  const deadline = Date.now() + 35000;
  await save(stage === "arm" ? "mixed-arm-ready.json" : "mixed-admission-ready.json", ready);
  while (Date.now() < deadline) {
    if (cancelled) throw new Error("Cancelled before mixed metadata admission.");
    let bytes;
    try { bytes = await privateFile(file, 16384); } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await new Promise(done => setTimeout(done, 25));
      continue;
    }
    const release = JSON.parse(bytes);
    if (bytes.toString("utf8") !== JSON.stringify(sorted(release))) {
      throw new Error("Mixed release must have the exact compact canonical source encoding.");
    }
    if (Object.keys(release).sort().join(",") !== "heldReceiptSha256,readySha256,runId,version"
        || release.version !== 1 || release.runId !== runId
        || release.readySha256 !== canonicalHash(ready)
        || !/^[a-f0-9]{64}$/.test(release.heldReceiptSha256)) {
      throw new Error("Mixed owner release differs from this exact original Begin.");
    }
    await save(stage === "arm" ? "mixed-arm-release-observed.json" : "mixed-admission-release-observed.json", release);
    return;
  }
  throw new Error("Mixed admission owner deadline elapsed; effects remain unknown.");
}

async function enqueueMixedWithAdmission(bulkObjects, metadataObjects) {
  if (!bulkObjects.length || !metadataObjects.length) throw new Error("Mixed admission requires both classes.");
  const first = bulkObjects[0];
  const closedCapture = await control({ kind: "inspect", objectId: first.objectId, afterAttempt: 0 });
  const closedPage = closedCapture.result;
  if (closedPage.objectId !== first.objectId || canonicalHash(closedPage.original) !== canonicalHash(original)
      || !closedPage.closed?.job || closedPage.attempts.length !== 0 || closedPage.nextAttempt !== null) {
    throw new Error("Mixed source requires a fresh closed job before any verification Enqueue.");
  }
  const cohort = { version: 1, cohortNonce: randomBytes(32).toString("hex"), runId,
    sourceDigest: identity.sourceDigest, scriptVersion: identity.scriptVersion,
    originalSha256: canonicalHash(original), objectId: first.objectId,
    expectedSourceSha256: first.expectedSha256, expectedSourceBytes: first.byteSize,
    closedSha256: canonicalHash(closedPage.closed), jobProjectionSha256: canonicalHash(closedPage.closed.job),
    inspectionSha256: closedCapture.responseSha256, inspectionFile: closedCapture.captureFile };
  await waitForMixedRelease(cohort, "arm");
  await control({ kind: "enqueue", objectIds: [first.objectId] });
  const deadline = Date.now() + 35000;
  let pending;
  while (Date.now() < deadline) {
    if (cancelled) throw new Error("Cancelled before observed bulk Begin.");
    const capture = await control({ kind: "inspect", objectId: first.objectId, afterAttempt: 0 });
    const page = capture.result;
    if (page.objectId !== first.objectId || canonicalHash(page.original) !== canonicalHash(original)
        || page.closed === null || !Array.isArray(page.attempts) || page.attempts.length > 1
        || page.nextAttempt !== null && page.nextAttempt !== 1) {
      throw new Error("Mixed bulk inspection differs from its original.");
    }
    const record = page.attempts[0];
    if (record?.receipt) throw new Error("Bulk finished before mixed admission rendezvous.");
    if (record) {
      if (!/^[a-f0-9]{64}$/.test(record.attempt.nonce)) {
        throw new Error("Mixed bulk Begin identity differs.");
      }
      // Begin precedes Capacity::acquire. The owner must separately join the
      // exact held provider GET, which the actual integrity path reaches only
      // after bulk capacity admission; Begin alone grants no release.
      pending = { version: 1, cohortNonce: cohort.cohortNonce, runId, sourceDigest: identity.sourceDigest,
        scriptVersion: identity.scriptVersion, originalSha256: canonicalHash(original),
        objectId: first.objectId, expectedSourceSha256: first.expectedSha256,
        expectedSourceBytes: first.byteSize, closedSha256: canonicalHash(page.closed),
        jobProjectionSha256: canonicalHash(page.closed.job),
        attemptNonce: record.attempt.nonce, attemptSha256: canonicalHash(record.attempt),
        inspectionSha256: capture.responseSha256, inspectionFile: capture.captureFile };
      break;
    }
    await new Promise(done => setTimeout(done, 25));
  }
  if (!pending) throw new Error("No unfinished bulk Begin before mixed cutoff.");
  if (pending.closedSha256 !== cohort.closedSha256 || pending.jobProjectionSha256 !== cohort.jobProjectionSha256) {
    throw new Error("Mixed Begin closed job changed after arming.");
  }
  await waitForMixedRelease(pending);
  const concurrentBulk = bulkObjects[1];
  if (concurrentBulk) {
    // Fill the second bulk slot before measuring the reserved metadata slot.
    // The metadata completion receipt must independently confirm both are active.
    await control({ kind: "enqueue", objectIds: [concurrentBulk.objectId] });
    let started = false;
    while (Date.now() < deadline) {
      if (cancelled) throw new Error("Cancelled before concurrent bulk Begin.");
      const capture = await control({ kind: "inspect", objectId: concurrentBulk.objectId, afterAttempt: 0 });
      const page = capture.result;
      if (page.objectId !== concurrentBulk.objectId || canonicalHash(page.original) !== canonicalHash(original)
          || !page.closed?.job || page.attempts.length > 1 || page.nextAttempt !== null) {
        throw new Error("Concurrent bulk inspection differs from its original.");
      }
      const record = page.attempts[0];
      if (record?.receipt) throw new Error("Concurrent bulk finished before metadata admission.");
      if (record) {
        started = true;
        break;
      }
      await new Promise(done => setTimeout(done, 25));
    }
    if (!started) throw new Error("Concurrent bulk Begin was not observed before the mixed cutoff.");
  }
  const metadata = metadataObjects[0];
  // Remaining originals still run once after the real metadata proof.
  await control({ kind: "enqueue", objectIds: [metadata.objectId] });
  await waitForObjects([metadata.objectId]);
  const verified = await inspectOriginalObjects([metadata.objectId], { deadline: Date.now() + 30000, maximumPages: 128 });
  const positive = verified.filter(item => item.receipt.verificationReplayed === false
    && Number(item.receipt.objects.bulkActive) === (concurrentBulk ? 2 : 1)
    && item.receipt.providerAfter.metadataAdmissionsDuringBulk > item.receipt.attempt.providerBefore.metadataAdmissionsDuringBulk);
  if (positive.length !== 1) throw new Error("Metadata lacks actual fresh admission under bulk.");
  if (bulkObjects.length > 2) {
    await control({ kind: "enqueue", objectIds: bulkObjects.slice(2).map(item => item.objectId) });
  }
  await save("mixed-admission-metadata-finish.json", { version: 1, runId,
    readySha256: canonicalHash(pending), record: positive[0] });
  await waitForObjects(bulkObjects.map(item => item.objectId));
}

async function waitForObjects(objectIds) {
  const selected = new Set(objectIds), deadline = Date.now() + wait * 1000;
  if (!selected.size || selected.size !== objectIds.length) {
    throw new Error("Queue waiting requires unique selected original objects.");
  }
  do {
    const status = await control({ kind: "status" });
    const objects = status.result.objects.filter(object => selected.has(object.objectId));
    if (objects.length !== selected.size || new Set(objects.map(object => object.objectId)).size !== selected.size) {
      throw new Error("Queue status differs from selected original object coverage.");
    }
    if (objects.every(object => object.verified)) return;
    if (Date.now() >= deadline) {
      // Inspect is observation only. It cannot extend queue waiting or replay a
      // mutation, and diagnostic failure must not replace the deadline error.
      try {
        let inspection = "complete";
        try {
          // No new dispatch after 30 seconds or 32 pages; the final in-flight
          // request still uses the existing 30-second control timeout.
          await inspectOriginalObjects(objectIds, { deadline: Date.now() + 30000, maximumPages: 32 });
        } catch { inspection = "unknown"; }
        await save("queue-deadline-inspection.json", { version: 1, runId, objectIds,
          state: "incomplete", inspection, unknownEffects: "retained_without_replay" });
      } finally {
        throw new Error("Queue observation deadline elapsed; closed originals remain recoverable.");
      }
    }
    if (cancelled) throw new Error("Cancelled before another queue observation.");
    await new Promise(done => setTimeout(done, 1000));
  } while (true);
}

let original, sources = [], completed = [], clockSamples = [], expiry = [];
try {
  if (phase === "clock") {
    const sample = await control({ kind: "clock" });
    await save("source-identity.json", { sourceDigest: identity.sourceDigest, scriptVersion: identity.scriptVersion });
    await save("source-clock-observation.json", { version: 1, scope: "authenticated_source_clock_only",
      runId, publicOrigin: endpoint.origin, sourceDigest: identity.sourceDigest,
      scriptVersion: identity.scriptVersion, sentAtMillis: String(sample.sent),
      receivedAtMillis: String(sample.received), observedAtMillis: sample.result.observedAtMillis,
      uncertaintySeconds: sample.result.uncertaintySeconds, replySha256: sample.responseSha256,
      captureFile: sample.captureFile });
  } else if (phase === "run") {
    const manifest = JSON.parse(await privateFile(required("--manifest-file")));
    if (!Array.isArray(manifest.objects) || !manifest.objects.length || manifest.objects.length > 32) {
      throw new Error("Manifest requires 1..32 actual payload files.");
    }
    for (const item of manifest.objects) sources.push(await describe(item.file, item.metadata === true));
    const start = await control({ kind: "start", provider: manifest.provider, objects: sources.map(source => source.plan) });
    original = start.result.original; await save("original.json", original);
    const checksum = original.material.profile.checksumAlgorithm;
    if (!["md5","sha256"].includes(checksum)) throw new Error("Actual checksum algorithm is unsupported.");
    if (checksum === "sha256") {
      for (const source of sources) {
        for (const part of source.parts) part.checksum = {algorithm:"sha256",value:Buffer.from(part.sha256,"hex").toString("base64")};
      }
    }
    for (let index = 0; index < 8; index += 1) {
      const sample = await control({ kind: "clock" });
      clockSamples.push({ sentAtMillis: String(sample.sent), receivedAtMillis: String(sample.received),
        observedAtMillis: sample.result.observedAtMillis, replySha256: sample.responseSha256 });
    }
    const cutoff = String(Math.floor(Date.now() / 1000) - 1);
    const expired = await control({ kind: "expired_mutation", cutoff });
    expiry.push({ cutoff, observedAtMillis: expired.observedAtMillis,
      isolateId: expired.result.providerBefore.isolateId,
      providerDispatchesBefore: String(expired.result.providerBefore.dispatches),
      providerDispatchesAfter: String(expired.result.providerAfter.dispatches), replySha256: expired.responseSha256 });
    for (const source of sources) {
      await control({ kind: "begin", objectId: source.plan.objectId });
      for (let offset = 0; offset < source.parts.length; offset += 32) {
        const grants = await control({ kind: "grant", objectId: source.plan.objectId, parts: source.parts.slice(offset, offset + 32) });
        const reports = await concurrent(grants.result.grants, 4, grant => upload(source, grant));
        await control({ kind: "report", objectId: source.plan.objectId, reports });
      }
      await control({ kind: "close", objectId: source.plan.objectId, deferEnqueue: true });
    }
    const bulkObjects = original.objects.filter(object => !object.metadata);
    const metadataObjects = original.objects.filter(object => object.metadata);
    // Distinct fresh sources measure metadata progress under bulk and elastic
    // metadata concurrency after bulk settles. Replayed proofs are excluded.
    const mixedObjects = bulkObjects.length ? [...bulkObjects, ...metadataObjects.slice(0, 1)] : [];
    if (mixedObjects.length) {
      const ids = mixedObjects.map(object => object.objectId);
      if (options.has("--mixed-admission-file")) {
        await enqueueMixedWithAdmission(bulkObjects, metadataObjects);
      } else if (metadataObjects.length) {
        throw new Error("Mixed qualification requires the explicitly wired source-owned admission barrier.");
      } else {
        await control({ kind: "enqueue", objectIds: ids });
        await waitForObjects(ids);
      }
    }
    const pureMetadata = bulkObjects.length ? metadataObjects.slice(1) : metadataObjects;
    if (pureMetadata.length) {
      const ids = pureMetadata.map(object => object.objectId);
      await control({ kind: "enqueue", objectIds: ids });
      await waitForObjects(ids);
    }
  } else {
    const status = await control({ kind: "status" }); original = status.result.original;
    await save("original.json", original);
    if (phase === "requeue") {
      const ids = status.result.objects.filter(object => object.closed && !object.verified).map(object => object.objectId);
      if (ids.length) await control({ kind: "enqueue", objectIds: ids });
    }
  }
  if (phase !== "clock") {
    const deadline = Date.now() + wait * 1000;
    let status;
    do {
      status = await control({ kind: "status" });
      if (status.result.objects.every(object => object.verified) || Date.now() >= deadline || phase === "status") break;
      if (cancelled) throw new Error("Cancelled before another status dispatch.");
      await new Promise(done => setTimeout(done, 1000));
    } while (true);
    completed = await inspectOriginalObjects(original.objects.map(object => object.objectId));
    const audience = { version: 1, executionKind: original.executionKind, deploymentId: original.deploymentId,
      publicOrigin: original.publicOrigin, sourceDigest: original.sourceDigest, scriptVersion: original.scriptVersion };
    const runtime = [], bulk = [], metadata = [], mixed = [];
    for (const item of completed) {
      const receipt = item.receipt, before = receipt.attempt.providerBefore, after = receipt.providerAfter;
      const fresh = after.dispatches - before.dispatches;
      if (receipt.verificationReplayed !== false || before.isolateId !== after.isolateId || fresh <= 0) continue;
      const proof = receipt.proof;
      const row = { objectId: item.object.objectId, isolateId: before.isolateId, messageId: receipt.messageId,
        startedAtMillis: receipt.attempt.startedAtMillis, finishedAtMillis: receipt.finishedAtMillis,
        byteSize: proof.byte_size, sha256: proof.sha256, proofSha256: canonicalHash(proof),
        aggregateActive: String(receipt.objects.aggregateActive), bulkActive: String(receipt.objects.bulkActive),
        metadataActive: String(receipt.objects.metadataActive), freshProviderDispatches: String(fresh), replySha256: item.replySha256 };
      (item.object.metadata ? metadata : bulk).push(row);
      runtime.push({ objectId: row.objectId, isolateId: row.isolateId, byteSize: row.byteSize, sha256: row.sha256,
        proofSha256: row.proofSha256, verificationMillis: String(Number(row.finishedAtMillis) - Number(row.startedAtMillis)),
        settlementMillis: item.closed.settlementMillis, peakParallelObjects: row.aggregateActive,
        peakParallelProviderRequests: String(after.peakActive), freshProviderDispatches: row.freshProviderDispatches,
        replySha256: row.replySha256 });
    }
    for (const meta of metadata) {
      const item = completed.find(item => item.receipt.messageId === meta.messageId);
      const before = item.receipt.attempt.providerBefore, after = item.receipt.providerAfter;
      for (const content of bulk) {
        if (content.isolateId === meta.isolateId && Number(meta.startedAtMillis) >= Number(content.startedAtMillis)
            && Number(meta.finishedAtMillis) <= Number(content.finishedAtMillis) && Number(meta.bulkActive) > 0
            && after.metadataAdmissionsDuringBulk > before.metadataAdmissionsDuringBulk) {
          mixed.push({ isolateId: meta.isolateId, bulkStartedAtMillis: content.startedAtMillis,
            bulkFinishedAtMillis: content.finishedAtMillis, metadataStartedAtMillis: meta.startedAtMillis,
            metadataFinishedAtMillis: meta.finishedAtMillis, bulkActive: meta.bulkActive,
            metadataAdmissionsBefore: String(before.metadataAdmissionsDuringBulk),
            metadataAdmissionsAfter: String(after.metadataAdmissionsDuringBulk), metadataReplySha256: meta.replySha256 });
          break;
        }
      }
    }
    await save("clock-raw.json", { ...audience, observations: { samples: clockSamples, expiredMutations: expiry } });
    await save("runtime-raw.json", { ...audience, observations: { samples: runtime } });
    await save("bulk-queue-raw.json", { ...audience, observations: { queueName: original.bulkQueueName, dependencyPhase: "content", samples: bulk } });
    await save("metadata-queue-raw.json", { ...audience, observations: { queueName: original.metadataQueueName, dependencyPhase: "metadata", samples: metadata } });
    await save("mixed-load-raw.json", { ...audience, observations: { samples: mixed } });
    await save("run-outcome.json", { ...audience, runId, observedPositiveObjects: status.result.objects.filter(object => object.verified).length,
      plannedObjects: original.objects.length, retainedPrivateStages: original.objects.length,
      plannedPrivateStageBytes: original.objects.reduce((sum, object) => sum + BigInt(object.byteSize), 0n).toString(),
      cleanup: "pending_explicit_reviewed_gc", scope: "participating_isolates_and_actual_queue_deliveries" });
  }
  await save("file-manifest.json", { version: 1, runId, files: [...files] });
  process.stdout.write(phase === "clock"
    ? `Retained authenticated source/clock observation for ${runId}; no provider qualification.\n`
    : `Retained qualification observations for ${runId}; independent review and private-stage cleanup remain required.\n`);
} catch (error) {
  await save("incomplete-run-outcome.json", { version: 1, runId, state: cancelled ? "cancelled" : "incomplete",
    sourceDigest: identity.sourceDigest, scriptVersion: identity.scriptVersion,
    cleanup: "pending_explicit_reviewed_gc", unknownEffects: "retained_without_replay" });
  await save("file-manifest.json", { version: 1, runId, files: [...files] });
  throw error;
} finally {
  for (const source of sources) await source.handle.close();
  await outputHandle.close();
}
