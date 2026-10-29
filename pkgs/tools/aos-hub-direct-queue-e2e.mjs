// Controlled provider plus the actual signed Direct producer and queue consumer.
// This development test grants no provider or deployment qualification.
import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { readFile, writeFile, access } from "node:fs/promises";
import { createServer } from "node:net";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";

const [root, dist, tls] = process.argv.slice(2).map(value => resolve(value));
const { Miniflare, Response } = createRequire(import.meta.url)(process.env.AOS_DIRECT_MINIFLARE);
const setup = JSON.parse(await readFile(join(root, "setup.json"), "utf8"));
const b = setup.bootstrap;
// Protected bootstrap JSON is transported as a map. Reconstruct the signed
// Core DTO's declared field order rather than relying on input map order.
const ordered = (value, fields) => Object.fromEntries(fields.map(field => [field, value[field]]));
const credential = value => ordered(value, ["purpose", "credentialId", "generation", "secretVersionRef", "credentialFingerprint"]);
const selector = {
  physicalAuthorityId: b.selector.physicalAuthorityId,
  association: ordered(b.selector.association, ["association_id", "alias_id", "binding_id",
    "binding_stable_id", "binding_resource_version", "binding_write_revision", "binding_prefix"]),
  writeCredential: credential(b.selector.writeCredential), readCredential: credential(b.selector.readCredential),
  presignCredential: credential(b.selector.presignCredential),
};
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const hmac = (key, bytes) => createHmac("sha256", key).update(bytes).digest();
const canonical = value => JSON.stringify(Array.isArray(value) ? value.map(sort)
  : sort(value));
function sort(value) {
  return Array.isArray(value) ? value.map(sort) : value && typeof value === "object"
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])) : value;
}
const digest = value => sha(canonical(value));
const nonce = () => randomBytes(32).toString("hex");
const encode = value => encodeURIComponent(value).replace(/[!'()*]/g,
  byte => `%${byte.charCodeAt(0).toString(16).toUpperCase()}`);
const pause = millis => new Promise(done => setTimeout(done, millis));
const xml = body => new Response(body, { headers: { "content-type": "application/xml" } });
const uploads = new Map(), objects = new Map();
const counters = { signatures: 0, creates: 0, parts: 0, completes: 0, reads: 0 };

function authenticate(request, url, body) {
  const signature = url.searchParams.get("X-Amz-Signature");
  const credential = url.searchParams.get("X-Amz-Credential")?.split("/");
  const names = url.searchParams.get("X-Amz-SignedHeaders")?.split(";");
  assert(signature && credential?.length === 5 && names?.length);
  assert.equal(credential[0], "fixture-access");
  assert.equal(credential[2], "fixture-region");
  const headers = names.map(name => {
    const value = name === "host" ? url.host : request.headers.get(name);
    assert(value, "required signed provider header absent");
    return `${name}:${value.trim().replace(/\s+/g, " ")}\n`;
  }).join("");
  const query = [...url.searchParams].filter(([key]) => key !== "X-Amz-Signature")
    .map(([key, value]) => [encode(key), encode(value)])
    .sort(([ak, av], [bk, bv]) => ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0)
    .map(([key, value]) => `${key}=${value}`).join("&");
  const payload = request.headers.get("x-amz-content-sha256");
  if (payload && payload !== "UNSIGNED-PAYLOAD") assert.equal(payload, sha(body));
  const canonicalRequest = [request.method, url.pathname, query, headers, names.join(";"), "UNSIGNED-PAYLOAD"].join("\n");
  const signed = ["AWS4-HMAC-SHA256", url.searchParams.get("X-Amz-Date"),
    credential.slice(1).join("/"), sha(canonicalRequest)].join("\n");
  const key = hmac(hmac(hmac(hmac("AWS4fixture-secret", credential[1]), credential[2]), "s3"), "aws4_request");
  assert.equal(hmac(key, signed).toString("hex"), signature, "actual provider SigV4 differs");
  counters.signatures++;
}

async function provider(request) {
  const url = new URL(request.url);
  assert.equal(url.origin, "https://s3.fleet.test");
  const body = Buffer.from(await request.arrayBuffer());
  assert(body.length <= 16 * 1024 * 1024);
  authenticate(request, url, body);
  const latency = Number(process.env.AOS_DIRECT_QUEUE_PROVIDER_MILLIS ?? 0);
  assert(Number.isInteger(latency) && latency >= 0 && latency <= 250);
  if (latency) await pause(latency);
  const key = decodeURIComponent(url.pathname.replace(/^\/fixture-bucket\//, ""));
  assert(key.startsWith(b.staging_prefix + "/"), "provider escaped private fixture namespace");
  if (request.method === "POST" && url.searchParams.has("uploads")) {
    const id = nonce();
    uploads.set(id, { key, parts: new Map(), closed: false });
    counters.creates++;
    return xml(`<InitiateMultipartUploadResult><Bucket>fixture-bucket</Bucket><Key>${key}</Key><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`);
  }
  const id = url.searchParams.get("uploadId"), upload = uploads.get(id);
  if (upload) {
    assert.equal(upload.key, key);
    assert(!upload.closed, "closed UploadId used again");
    if (request.method === "PUT") {
      const number = Number(url.searchParams.get("partNumber"));
      assert(number > 0 && number <= 10000);
      assert.equal(request.headers.get("content-md5"), createHash("md5").update(body).digest("base64"));
      const etag = `"${sha(body)}"`;
      upload.parts.set(number, { body, etag });
      counters.parts++;
      return new Response(null, { headers: { etag } });
    }
    if (request.method === "POST") {
      const selected = [...body.toString().matchAll(/<Part><PartNumber>(\d+)<\/PartNumber><ETag>(.*?)<\/ETag><\/Part>/g)];
      assert(selected.length > 0 && selected.length === upload.parts.size);
      const bytes = Buffer.concat(selected.map(([, number, etag]) => {
        const part = upload.parts.get(Number(number));
        assert(part && etag.replaceAll("&quot;", '"') === part.etag);
        return part.body;
      }));
      const etag = `"${sha(bytes)}"`;
      objects.set(key, { bytes, etag });
      upload.closed = true;
      counters.completes++;
      return xml(`<CompleteMultipartUploadResult><Location>https://s3.fleet.test/fixture-bucket/${key}</Location><Bucket>fixture-bucket</Bucket><Key>${key}</Key><ETag>${etag}</ETag></CompleteMultipartUploadResult>`);
    }
  }
  if (request.method === "GET" || request.method === "HEAD") {
    const object = objects.get(key);
    if (!object) return new Response(null, { status: 404 });
    assert.equal(request.headers.get("if-match"), object.etag);
    counters.reads++;
    return new Response(request.method === "HEAD" ? null : object.bytes,
      { headers: { etag: object.etag, "content-length": String(object.bytes.length) } });
  }
  throw new Error("unexpected provider operation");
}

async function forwardIssuer(request) {
  try {
    // Node computes transport framing for the exact forwarded bytes.
    const headers = Object.fromEntries([...request.headers].filter(([name]) =>
      !["content-length", "transfer-encoding", "host"].includes(name)));
    const reply = await fetch(new URL(new URL(request.url).pathname, setup.issuer), {
      method: request.method,
      headers,
      body: Buffer.from(await request.arrayBuffer()),
    });
    const bytes = Buffer.from(await reply.arrayBuffer());
    if (reply.status !== 200) {
      await writeFile(join(root, "issuer-refusal.private.json"), JSON.stringify({
        status: reply.status, body: bytes.toString(),
      }), { mode: 0o600 });
    }
    return new Response(bytes, {
      status: reply.status, headers: Object.fromEntries(reply.headers),
    });
  } catch (error) {
    await writeFile(join(root, "issuer-handler-error.private.txt"),
      String(error.stack) + "\nCAUSE: " + String(error.cause?.stack), { mode: 0o600 });
    throw error;
  }
}

const reserve = createServer();
await new Promise(done => reserve.listen(0, "127.0.0.1", done));
const port = reserve.address().port;
await new Promise(done => reserve.close(done));
const origin = `https://localhost:${port}`;
const source = process.env.AOS_COPY_PROVIDER_SOURCE_DIGEST;
assert(/^[a-f0-9]{64}$/.test(source));
const version = `emulated-${source}`;
const journalKey = "queue-journal-private-key-at-least-thirty-two-bytes";
const controlKey = "queue-control-private-key-at-least-thirty-two-bytes";
const policy = { policyId: "controlled-provider-policy", policyDigest: "6".repeat(64), namespace: b.staging_prefix };
const objectConfig = {
  version: 1, guard_namespace_id: b.publication.authority.guard_namespace_id,
  executor_identity: b.issuer_installation.executor_identity,
  issuer_key_id: b.issuer_key_id, issuer_public_key: b.issuer_public_key,
  timing_profile: b.timing_profile, clock_uncertainty: b.clock_uncertainty,
  aliases: b.publication.aliases, cohorts: [b.write_cohort, b.read_cohort], publications: [b.publication],
};
const domain = {
  issuer_installation: b.issuer_installation, publication: b.publication,
  write_cohort: b.write_cohort, read_cohort: b.read_cohort,
  write_credential: b.selector.writeCredential, read_credential: b.selector.readCredential,
  presign_credential: b.selector.presignCredential, private_stage_policy: policy,
  staging_prefix: b.staging_prefix, checksum_algorithm: "md5", maximum_grant_lifetime: "30",
  provider_contract: { contract_id: "emulated-controlled-provider-development-only", evidence_digest: "7".repeat(64),
    private_completed_stage: true, completed_upload_id_rejects_late_parts: true,
    multipart_abort_closes_upload_id: true, multipart_copy_from_immutable_source: true,
    upload_part_checksum_enforced: true },
};
const bindings = {
  HUB_TOPOLOGY: "hybrid", HUB_DEPLOYMENT_ID: b.deployment_id,
  HUB_STORAGE_WORK_KEY: setup.application, HUB_AUTHORITY_RENEWAL_KEY: setup.renewal,
  HUB_EXTERNAL_OBJECT_GUARD_KEY: "queue-object-guard-private-key-at-least-thirty-two-bytes",
  HUB_EXTERNAL_STAGE_KEY: "queue-stage-private-key-at-least-thirty-two-bytes",
  HUB_EXTERNAL_OBJECT_CONSUMER: JSON.stringify(objectConfig),
  HUB_EXTERNAL_STAGING_CONSUMER: JSON.stringify({ version: 1, domains: [domain] }),
  HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN: origin, HUB_DIRECT_UPLOAD_MANAGED_R2: "false",
  HUB_DIRECT_UPLOAD_QUALIFICATION_ENABLED: "true",
  HUB_DIRECT_UPLOAD_CONFORMANCE_KEY: controlKey, HUB_DIRECT_UPLOAD_JOURNAL_KEY: journalKey,
  HUB_DIRECT_UPLOAD_CLOCK_MODE: "bounded_utc", HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS: "1",
  HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION: "39b56754e1529d7090138c9798df5b4c045338cce500548f095a08220f7bfe40",
  HUB_DIRECT_VERIFY_BULK_NAME: "queue-bulk", HUB_DIRECT_VERIFY_METADATA_NAME: "queue-metadata",
  HUB_DIRECT_VERIFY_BULK_MAX_BATCH_SIZE: "2", HUB_DIRECT_VERIFY_METADATA_MAX_BATCH_SIZE: "3",
  HUB_DIRECT_VERIFY_BULK_MAX_CONCURRENT_INVOCATIONS: "unsupported",
  HUB_DIRECT_VERIFY_METADATA_MAX_CONCURRENT_INVOCATIONS: "unsupported",
  HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS: "3", HUB_DIRECT_QUALIFY_MAX_PROVIDER_REQUESTS: "3",
  HUB_DIRECT_QUALIFY_MAX_OBJECT_BYTES: "16777216",
  HUB_PROVIDER_CAPACITY_POLICY: JSON.stringify({ version: 1, deployment_id: b.deployment_id,
    source_digest: source, script_version: version, maximum_provider_requests: 3 }),
};
const durableObjects = Object.fromEntries([
  ["HYBRID_OBJECT_GUARD", "HybridObjectGuard"], ["HYBRID_BINDING_STATE", "HybridBindingState"],
  ["HYBRID_AUTHORITY_STATE", "HybridAuthorityState"], ["EXTERNAL_OBJECT_GUARD", "ExternalObjectGuard"],
  ["HYBRID_DIRECT_UPLOAD", "HybridDirectUpload"],
].map(([name, className]) => [name, { className, useSQLite: true }]));
const runtime = new Miniflare({
  rootPath: root,
  scriptPath: join(dist, "shim.mjs"), modulesRoot: dist, modules: true,
  modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"], fallthrough: true }],
  compatibilityDate: "2024-09-23", compatibilityFlags: ["nodejs_compat", "enable_request_signal"],
  host: "127.0.0.1", port, cf: false, https: true,
  httpsCert: await readFile(join(tls, "hub-hybrid-fleet-server.crt"), "utf8"),
  httpsKey: await readFile(join(tls, "hub-hybrid-fleet-server.key"), "utf8"),
  durableObjects, durableObjectsPersist: join(root, "state"), bindings,
  kvNamespaces: ["HUB_DIRECT_UPLOAD_ACCEPTANCE"],
  queueProducers: { HUB_DIRECT_VERIFY_BULK: "queue-bulk", HUB_DIRECT_VERIFY_METADATA: "queue-metadata" },
  queueConsumers: { "queue-bulk": { maxBatchSize: 2, maxBatchTimeout: 0 }, "queue-metadata": { maxBatchSize: 3, maxBatchTimeout: 0 } },
  serviceBindings: { HUB_AUTHORITY_ISSUER: forwardIssuer },
  outboundService: provider,
});

let runId;
const mac = (domain, body) => createHmac("sha256", controlKey).update("aos-storage-work-v1\0").update(domain).update(body).digest("hex");
async function control(action, selectedRun = runId) {
  const request = { version: 1, runId: selectedRun, nonce: nonce(), sourceDigest: source, scriptVersion: version,
    expiresAt: String(Math.floor(Date.now() / 1000) + 30), action };
  const body = JSON.stringify(request);
  const response = await runtime.dispatchFetch(origin + "/_internal/storage/direct-upload-qualification", {
    method: "POST", body, headers: { "x-aos-direct-qualification-signature": mac("aos.direct-upload.qualification-request.v1\0", body) },
  });
  const bytes = await response.text();
  if (response.status !== 200) {
    await writeFile(join(root, "control-refusal.private.json"), JSON.stringify({
      action: action.kind, status: response.status,
      authenticated: response.headers.has("x-aos-direct-qualification-signature"), body: bytes,
    }), { mode: 0o600 });
  }
  assert.equal(response.status, 200, `control ${action.kind} refused`);
  assert.equal(response.headers.get("x-aos-direct-qualification-signature"), mac("aos.direct-upload.qualification-reply.v1\0", bytes), "control reply signature differs");
  const reply = JSON.parse(bytes);
  assert.equal(reply.nonce, request.nonce);
  assert.equal(reply.requestSha256, sha(body));
  return reply.result;
}

async function run() {
  runId = nonce();
  const count = Number(process.env.AOS_DIRECT_QUEUE_OBJECTS ?? 24);
  assert(Number.isInteger(count) && count >= 3 && count <= 32);
  const bulkCount = Number(process.env.AOS_DIRECT_QUEUE_BULK_OBJECTS ?? 0);
  assert(Number.isInteger(bulkCount) && bulkCount >= 0 && bulkCount < count);
  const sources = Array.from({ length: count }, (_, index) => {
    const body = Buffer.from(`StorePath: /nix/store/${"0".repeat(32)}-queue-${index}\nURL: nar/queue-${index}.nar\nCompression: none\nFileHash: sha256:${"0".repeat(52)}\nFileSize: 1\nNarHash: sha256:${"0".repeat(52)}\nNarSize: 1\nReferences: \n`);
    return { body, objectId: nonce(), byteSize: String(body.length), expectedSha256: sha(body), partSize: "8388608", metadata: index >= bulkCount };
  });
  const started = Date.now();
  await control({ kind: "start", provider: { kind: "external", selector }, objects: sources.map(({ body, ...plan }) => plan) });
  async function stage(object, selectedRun = runId) {
    const objectId = object.objectId;
    await control({ kind: "begin", objectId }, selectedRun);
    const part = { partNumber: 1, offset: "0", byteSize: object.byteSize, sha256: object.expectedSha256,
      checksum: { algorithm: "md5", value: createHash("md5").update(object.body).digest("base64") } };
    const { grants } = await control({ kind: "grant", objectId, parts: [part] }, selectedRun);
    assert.equal(grants.length, 1);
    const grant = grants[0];
    const uploaded = await provider(new Request(grant.url, { method: "PUT", body: object.body,
      headers: Object.fromEntries(grant.requiredHeaders.map(({ name, value }) => [name, value])) }));
    assert.equal(uploaded.status, 200);
    const fields = ["placementId", "placementFingerprint", "placementResourceVersion", "writeSpecVersion", "bindingId",
      "bindingResourceVersion", "bindingWriteRevision", "profileFingerprint", "privatePolicyDigest", "checksumAlgorithm"];
    await control({ kind: "report", objectId, reports: [{
      session: { sessionId: grant.sessionId, logicalFingerprint: grant.logicalFingerprint },
      placement: Object.fromEntries(fields.map(field => [field, grant.placement[field]])),
      operationId: digest([objectId, "report", 1]), grantId: grant.grantId, grantRevision: grant.grantRevision,
      observed: { part, etag: uploaded.headers.get("etag") },
    }] }, selectedRun);
    await control({ kind: "close", objectId, deferEnqueue: true }, selectedRun);
  }
  for (const object of sources) await stage(object);
  const queued = Date.now();
  await control({ kind: "enqueue", objectIds: sources.map(item => item.objectId) });
  const foregroundRounds = Number(process.env.AOS_DIRECT_QUEUE_FOREGROUND_ROUNDS ?? 0);
  assert(Number.isInteger(foregroundRounds) && foregroundRounds >= 0 && foregroundRounds <= 16);
  const foregroundCount = Number(process.env.AOS_DIRECT_QUEUE_FOREGROUND_OBJECTS ?? count);
  assert(Number.isInteger(foregroundCount) && foregroundCount >= 1 && foregroundCount <= 64);
  const foregroundStarted = Date.now();
  const foreground = (async () => {
    for (let round = 0; round < foregroundRounds; round++) {
      await Promise.all(Array.from({length: foregroundCount}, (_, index) => sources[index % sources.length]).map(async object => {
        const selectedRun = nonce();
        const plan = {...object, objectId: nonce()};
        const {body, ...wirePlan} = plan;
        await control({kind: "start", provider: {kind: "external", selector}, objects: [wirePlan]}, selectedRun);
        await stage(plan, selectedRun);
      }));
    }
  })();
  const deadline = queued + 60000;
  let status;
  do {
    status = await control({ kind: "status" });
    if (status.objects.every(item => item.verified)) break;
    await pause(100);
  } while (Date.now() < deadline);
  const drained = Date.now();
  await foreground;
  const rows = [];
  for (const { objectId, expectedSha256, byteSize, metadata } of sources) {
    const page = await control({ kind: "inspect", objectId, afterAttempt: 0 });
    const receipt = page.attempts[0]?.receipt;
    if (receipt) {
      assert.equal(receipt.verificationReplayed, false);
      assert.equal(receipt.proof.sha256, expectedSha256);
      assert.equal(receipt.proof.byte_size, byteSize);
      assert.equal(receipt.providerAfter.maximum, 3);
      assert(receipt.providerAfter.peakActive <= 3, "verification exceeded the provider request bound");
      assert.equal(receipt.queueName, metadata ? "queue-metadata" : "queue-bulk");
      assert(receipt.objects.aggregateActive <= 3 && receipt.objects.bulkActive <= 2);
      rows.push({ peakProviderRequests: receipt.providerAfter.peakActive, waitMillis: Number(receipt.attempt.startedAtMillis) - Number(receipt.queuedAtMillis),
        activeMillis: Number(receipt.finishedAtMillis) - Number(receipt.attempt.startedAtMillis),
        metadata, bulkActive: receipt.objects.bulkActive });
    }
  }
  const verified = status.objects.filter(item => item.verified).length;
  await writeFile(join(root, "queue-summary.json"), JSON.stringify({
    objects: count, bulkObjects: bulkCount, metadataObjects: count - bulkCount,
    verified, uploadMillis: queued - started, drainMillis: drained - queued,
    foregroundRounds, foregroundCount, foregroundMillis: Date.now() - foregroundStarted, rows, counters,
    scope: "controlled-provider-production-verification-path-no-runtime-acceptance",
  }, null, 2), { mode: 0o600 });
  assert.equal(verified, count, "verification queue did not drain within sixty seconds");
  assert.equal(rows.length, count, "fresh positively verified queue receipts absent");
  if (foregroundRounds && foregroundCount === 64) {
    assert(Math.max(...rows.map(row => row.waitMillis)) < 8000,
      "foreground fanout delayed the verification queue beyond eight seconds");
    assert(Math.max(...rows.map(row => row.waitMillis + row.activeMillis)) < 10000,
      "cross-queue object contention delayed verification beyond ten seconds");
  }
  if (bulkCount) assert(rows.some(row => row.metadata && row.bulkActive > 0),
    "metadata did not enter verification during bulk work");
  assert.equal(counters.completes, count + foregroundRounds * foregroundCount);
  assert(counters.reads >= bulkCount + (count - bulkCount) * 2,
    "original integrity or metadata semantic source reads absent");
}

try {
  await runtime.ready;
  await writeFile(join(root, "ready.json"), JSON.stringify({ origin }), { mode: 0o600 });
  for (;;) {
    try { await access(join(root, "hydrated")); break; } catch (error) { if (error.code !== "ENOENT") throw error; }
    await pause(25);
  }
  await run();
} finally {
  await runtime.dispose();
}
