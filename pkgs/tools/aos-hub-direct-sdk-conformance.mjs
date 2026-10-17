// Hosted ordinary R2 SDK and direct S3 interoperability qualification driver.
// Run with source-built Node. Credentials stay in private input files/Worker
// secrets; output contains no bearer URL, MAC, key material or provider body.
// Requires a Linux qualification host with /proc/self/fd for held-directory writes.

import { createHash, createHmac, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, readdir } from "node:fs/promises";
import { resolve, join } from "node:path";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index];
  const value = process.argv[index + 1];
  if (!name?.startsWith("--") || !value || args.has(name)) {
    throw new Error("Expected unique --name value arguments.");
  }
  args.set(name, value);
}

const required = (name) => {
  const value = args.get(name);
  if (!value) throw new Error(`Required argument ${name} is missing.`);
  return value;
};

const endpoint = new URL(required("--endpoint"));
if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password
    || endpoint.pathname !== "/" || endpoint.search || endpoint.hash) {
  throw new Error("The endpoint must be an HTTPS origin.");
}

const accountId = required("--account-id");
const bucketName = required("--bucket");
if (!/^[a-f0-9]{32}$/.test(accountId) || !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucketName)) {
  throw new Error("Provider coordinates are malformed.");
}

async function privateHandle(path, directory = false) {
  const flags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
    | (directory ? constants.O_DIRECTORY : 0);
  const handle = await open(path, flags);
  const stat = await handle.stat();
  if (stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0
      || (directory ? !stat.isDirectory() : !stat.isFile())
      || (!directory && stat.size > 4096)) {
    await handle.close();
    throw new Error("Private input/evidence must be owner-only regular files or directories.");
  }
  return handle;
}

const keyHandle = await privateHandle(required("--control-key-file"));
const key = (await keyHandle.readFile("utf8")).trim();
await keyHandle.close();
if (key.length < 32) throw new Error("The private control key is malformed.");
const runId = args.get("--run-id") ?? randomBytes(32).toString("hex");
const phase = args.get("--phase") ?? "run";
if (!["run", "cleanup", "status"].includes(phase) || (phase !== "run" && !args.has("--run-id"))) {
  throw new Error("Use --phase run, cleanup or status; recovery requires the original --run-id.");
}
if (!/^[a-f0-9]{64}$/.test(runId)) throw new Error("The run ID is malformed.");
const outputDir = resolve(required("--output-dir"));
await mkdir(outputDir, { recursive: true, mode: 0o700 });
const outputHandle = await privateHandle(outputDir, true);
// Address the held directory inode, so a path replacement cannot redirect writes.
const heldOutput = `/proc/self/fd/${outputHandle.fd}`;
if ((await readdir(heldOutput)).length !== 0) {
  throw new Error("Use a fresh empty evidence directory for each invocation.");
}
const browserOrigin = args.get("--browser-origin");
if (browserOrigin) {
  const origin = new URL(browserOrigin);
  if (origin.protocol !== "https:" || origin.origin !== browserOrigin) {
    throw new Error("The browser origin must be an exact HTTPS origin.");
  }
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const save = async (name, value) => {
  const handle = await open(join(heldOutput, name), constants.O_WRONLY | constants.O_CREAT
    | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
};

const activeControllers = new Set();
let cancellationRequested = false;
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    cancellationRequested = true;
    for (const controller of activeControllers) controller.abort();
  });
}

// A local cancellation is an unknown observation, never provider settlement.
async function observe(name, intent, dispatch) {
  if (cancellationRequested) {
    await save(`${name}-cancelled.json`, { ...intent, state: "cancelled_before_dispatch" });
    throw new Error("Operator cancellation prevents further dispatch.");
  }
  await save(`${name}-pending.json`, { ...intent, state: "pending" });
  const controller = new AbortController();
  activeControllers.add(controller);
  const timer = setTimeout(() => controller.abort(), 30_000);
  try {
    if (cancellationRequested) controller.abort();
    if (controller.signal.aborted) throw new Error("Cancelled before dispatch.");
    return await dispatch(controller.signal);
  } catch {
    await save(`${name}-unknown.json`, { ...intent, state: "unknown", reason: controller.signal.aborted
      ? "local_deadline_or_cancellation" : "transport_or_bounded_reply_failure" });
    throw new Error("The operation has no retained positive acknowledgement; inspect retained effects before recovery.");
  } finally {
    clearTimeout(timer);
    activeControllers.delete(controller);
  }
}

async function bounded(response, maximum) {
  let size = 0;
  const chunks = [];
  for await (const chunk of response.body ?? []) {
    size += chunk.byteLength;
    if (size > maximum) throw new Error("The bounded probe reply exceeded its limit.");
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function control(phase, extra = {}) {
  const request = {
    version: 1,
    runId,
    phase,
    accountId,
    bucketName,
    expiresAt: String(Math.floor(Date.now() / 1000) + 30),
    partEtag: null,
    checksumRejectionSha256: null,
    ...extra,
  };
  const body = Buffer.from(JSON.stringify(request));
  const signature = createHmac("sha256", key)
    .update(Buffer.from("aos-storage-work-v1\0"))
    .update(Buffer.from("aos.direct-upload.hosted-sdk-probe.v1\0"))
    .update(body).digest("hex");
  const intent = {
    version: 1,
    runId,
    phase,
    requestSha256: sha256(body),
    endpointOrigin: endpoint.origin,
  };
  return observe(phase, intent, async (signal) => {
  const response = await fetch(new URL("/_internal/storage/direct-upload-sdk-conformance", endpoint), {
    method: "POST",
    headers: { "content-type": "application/json", "x-aos-direct-sdk-probe-signature": signature },
    body,
    redirect: "manual",
    signal,
  });
  const bytes = await bounded(response, 64 * 1024);
  let failure = null;
  try {
    const reported = JSON.parse(bytes.toString("utf8")).failure;
    if (reported && typeof reported.step === "string" && typeof reported.cause === "string"
      && /^[a-z_-]{1,64}$/.test(reported.step) && /^[a-z_]{1,64}$/.test(reported.cause)) {
      failure = { step: reported.step, cause: reported.cause };
    }
  } catch { /* Non-JSON replies remain classified by status and digest. */ }
  await save(`${phase}-reply.json`, {
    version: 1,
    runId,
    phase,
    requestSha256: sha256(body),
    status: response.status,
    responseSha256: sha256(bytes),
    state: response.ok ? "positive" : "refused_or_unknown",
    failure,
    endpointOrigin: endpoint.origin,
  });
  if (!response.ok) throw new Error(`The durable SDK probe returned ${response.status}; retained unknown effects must be inspected.`);
  return JSON.parse(bytes.toString("utf8"));
  });
}

await save("run.json", { version: 1, runId, endpointOrigin: endpoint.origin, accountId, bucketName, sourceKind: "hosted_ordinary_r2_binding" });
if (phase === "status") {
  await save("status.json", await control("status"));
  process.stdout.write(`Probe ${runId}: durable effect status retained in ${outputDir}.\n`);
} else if (phase === "cleanup") {
  const cleaned = await control("cleanup");
  await save("cleanup.json", cleaned);
  process.stdout.write(`Probe ${runId}: cleanup acknowledgement retained in ${outputDir}.\n`);
} else {
  const start = await control("start");
  const capability = new URL(start.url);
  if (capability.protocol !== "https:" || capability.hostname !== `${accountId}.r2.cloudflarestorage.com`
      || !capability.pathname.startsWith(`/${bucketName}/.aos-direct-qualification/${runId}/`)
      || start.method !== "PUT") {
    throw new Error("The exact scoped provider capability differs from operator coordinates.");
  }

  const bytes = Buffer.alloc(32768);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = (index * 17 + 3) % 251;
  if (sha256(bytes) !== start.part.sha256 || String(bytes.length) !== start.part.byteSize) {
    throw new Error("The probe source declaration differs.");
  }
  const headers = Object.fromEntries(start.requiredHeaders.map(({ name, value }) => [name, value]));
  headers["content-type"] = "application/octet-stream";
  if (browserOrigin) headers.origin = browserOrigin;
  await save("start.json", {
    version: 1,
    runId,
    scriptVersion: start.scriptVersion,
    part: start.part,
    capabilitySha256: sha256(start.url),
    requiredHeaderNames: Object.keys(headers),
  });

  const incorrect = Buffer.from(bytes);
  incorrect[0] ^= 1;
  if (browserOrigin) {
    const requestedHeaders = Object.keys(headers).filter((name) => !["origin", "content-length", "host"].includes(name.toLowerCase())).map((name) => name.toLowerCase()).sort();
    await observe("cors-preflight", { version: 1, runId, browserOrigin, requestedHeaders }, async (signal) => {
      const response = await fetch(start.url, { method: "OPTIONS", headers: {
        origin: browserOrigin, "access-control-request-method": "PUT",
        "access-control-request-headers": requestedHeaders.join(","),
      }, redirect: "manual", signal });
      await bounded(response, 16 * 1024);
      const allowedOrigin = response.headers.get("access-control-allow-origin");
      const methods = (response.headers.get("access-control-allow-methods") ?? "").split(",").map((value) => value.trim());
      const allowedHeaders = (response.headers.get("access-control-allow-headers") ?? "").split(",").map((value) => value.trim().toLowerCase());
      const positive = response.ok && allowedOrigin === browserOrigin && methods.includes("PUT")
        && requestedHeaders.every((name) => allowedHeaders.includes(name));
      await save("cors-preflight.json", { version: 1, runId, browserOrigin, requestedHeaders,
        allowedOrigin, methods, allowedHeaders, status: response.status, state: positive ? "positive" : "refused" });
      if (!positive) throw new Error("Exact browser preflight qualification failed.");
    });
  }

  const { rejected, denial } = await observe("checksum-negative", { version: 1, runId, sourceSha256: sha256(incorrect) }, async (signal) => {
    const rejected = await fetch(start.url, { method: "PUT", headers, body: incorrect, redirect: "manual", signal });
    return { rejected, denial: await bounded(rejected, 16 * 1024) };
  });
  const code = denial.toString("utf8").match(/<Code>([A-Za-z0-9]+)<\/Code>/)?.[1] ?? null;
  const rejection = { version: 1, runId, state: rejected.status === 400 && code === "BadDigest" ? "negative" : "unknown_or_unexpected", status: rejected.status, providerCode: code, responseSha256: sha256(denial), sourceSha256: sha256(incorrect) };
  await save("checksum-negative.json", rejection);
  if (rejection.state !== "negative") throw new Error("Provider checksum enforcement was not positively observed.");

  const { uploaded, uploadBody } = await observe("direct-part", { version: 1, runId, sourceSha256: sha256(bytes) }, async (signal) => {
    const uploaded = await fetch(start.url, { method: "PUT", headers, body: bytes, redirect: "manual", signal });
    return { uploaded, uploadBody: await bounded(uploaded, 16 * 1024) };
  });
  const etag = uploaded.headers.get("etag");
  const quotedEtag = etag && /^"[\x21\x23-\x5b\x5d-\x7e]+"$/.test(etag) && etag.length <= 1024;
  const exposed = (uploaded.headers.get("access-control-expose-headers") ?? "").split(",").map((value) => value.trim().toLowerCase());
  const corsVisible = !browserOrigin || (uploaded.headers.get("access-control-allow-origin") === browserOrigin && exposed.includes("etag"));
  await save("direct-part.json", { version: 1, runId, state: uploaded.ok && quotedEtag && corsVisible ? "positive" : "unknown_or_refused", status: uploaded.status, etag, browserOrigin: browserOrigin ?? null, etagCorsVisible: browserOrigin ? corsVisible : "unmeasured", responseSha256: sha256(uploadBody), sourceSha256: sha256(bytes) });
  if (!uploaded.ok || !quotedEtag || !corsVisible) throw new Error("Direct UploadPart has no positive exact browser-visible acknowledgement.");

  const document = await control("finish", { partEtag: etag, checksumRejectionSha256: sha256(Buffer.from(JSON.stringify(rejection))) });
  await save("sdk-document.json", document);
  await save("evidence-manifest.json", {
    version: 1,
    runId,
    sourceKind: document.sourceKind,
    scriptVersion: document.original.scriptVersion,
    collectedSdkDocumentSha256: sha256(Buffer.from(JSON.stringify(document))),
    collectedDirectChecksumEvidenceSha256: sha256(Buffer.from(JSON.stringify(rejection))),
    sdkClosureAccepted: document.latePartAfterComplete === "negative" && document.latePartAfterAbort === "negative",
    clockQualification: "unmeasured",
    bulkQueueQualification: "unmeasured",
    metadataQueueQualification: "unmeasured",
    privateProviderPolicyReadback: "requires_independent_collection",
    productionEnablement: "requires_independent_acceptance",
    browserCorsQualification: browserOrigin ? "observed_preflight_and_visible_etag" : "unmeasured",
  });
  process.stdout.write(`Probe ${runId}: actual provider/runtime evidence retained in ${outputDir}.\n`);
}
await outputHandle.close();
