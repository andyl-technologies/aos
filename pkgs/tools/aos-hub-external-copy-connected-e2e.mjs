// Controlled actual provider transport and persistent production Worker guards.
// Native prepares this fixture from reviewed SQL and serves the real issuer.
// No hosted provider or deployment acceptance is established by this process.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { createServer as httpServer } from "node:http";
import { createServer as httpsServer } from "node:https";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const [root, dist, workerd, tls] = process.argv.slice(2).map(value => resolve(value));
assert(process.execPath.startsWith("/nix/store/") && workerd.startsWith("/nix/store/"));
const setup = JSON.parse(await readFile(join(root, "setup.json"), "utf8"));
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const b64sha = bytes => createHash("sha256").update(bytes).digest("base64");
const hmac = (key, bytes) => createHmac("sha256", key).update(bytes).digest();
const quote = value => JSON.stringify(value);
const escape = value => value.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
const encode = value => encodeURIComponent(value).replace(/[!'()*]/g, byte => `%${byte.charCodeAt(0).toString(16).toUpperCase()}`);
const source = Buffer.alloc(8 * 1024 * 1024);
for (let index = 0; index < source.length; index++) source[index] = index % 251;
const replacementSource = Buffer.from(source);
replacementSource[0] ^= 0xff;
const counters = { creates: 0, parts: 0, completes: 0, completeRequests: 0, aborts: 0, conditionalReads: 0,
  unconditionalReads: 0, signatures: 0, workerLifetimes: 0,
  listRequests: 0, maximumListLimit: 0, credentialProbes: 0 };
const uploads = new Map();
const destinations = new Map();
const sourceAliases = new Set([setup.sourceKey]);
let catalogueRace = false;
let currentSourceVersion = "source-version-1";
let scanTail = false;
let loseCreateReply = false;
let nullSourceVersion = false;
let mismatchSource = false;
const nativeBoundary = { records: [], calls: 0, requestBytes: 0, replyBytes: 0, bodyForwardingCalls: 0 };
counters.nativeBoundary = nativeBoundary;
let child;
let workerPort;

function verifySignature(request, url, body) {
  const signature = url.searchParams.get("X-Amz-Signature");
  const credential = url.searchParams.get("X-Amz-Credential")?.split("/");
  const names = url.searchParams.get("X-Amz-SignedHeaders")?.split(";");
  assert(signature && credential?.length === 5 && names?.length);
  assert.equal(credential[0], "fixture-access");
  assert.equal(credential[2], "fixture-region");
  assert.equal(credential[3], "s3");
  const headers = names.map(name => {
    assert(request.headers[name], `Missing signed ${name}`);
    return `${name}:${String(request.headers[name]).trim().replace(/\s+/g, " ")}\n`;
  }).join("");
  const query = [...url.searchParams].filter(([key]) => key !== "X-Amz-Signature")
    .map(([key, value]) => [encode(key), encode(value)])
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0)
    .map(([key, value]) => `${key}=${value}`).join("&");
  const payload = request.headers["x-amz-content-sha256"] ?? "UNSIGNED-PAYLOAD";
  if (payload !== "UNSIGNED-PAYLOAD") assert.equal(payload, sha(body));
  const canonical = [request.method, url.pathname, query, headers, names.join(";"), "UNSIGNED-PAYLOAD"].join("\n");
  const scope = credential.slice(1).join("/");
  const stringToSign = ["AWS4-HMAC-SHA256", url.searchParams.get("X-Amz-Date"), scope, sha(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac("AWS4fixture-secret", credential[1]), credential[2]), "s3"), "aws4_request");
  assert.equal(hmac(key, stringToSign).toString("hex"), signature, "Actual provider request SigV4");
  counters.signatures++;
}

function object(key, version) {
  if (sourceAliases.has(key) && (!version || version === "source-version-1" || version === "source-version-2")) {
    const selected = version ?? currentSourceVersion;
    return { bytes: selected === "source-version-1" ? source : replacementSource,
      version: selected, etag: selected === "source-version-1" ? '"source-etag-1"' : '"source-etag-2"' };
  }
  const destination = destinations.get(key);
  if (destination && (!version || version === destination.version)) return destination;
  if (scanTail && key.startsWith("managed/binding/objects/destination/aux/")) {
    return { bytes: Buffer.alloc(0), version: "aux-version", etag: '"aux-etag"' };
  }
}

async function provider(request, response) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
    assert(chunks.reduce((total, value) => total + value.length, 0) <= 64 * 1024 * 1024);
  }
  const body = Buffer.concat(chunks);
  const url = new URL(request.url, "https://s3.fleet.test");
  verifySignature(request, url, body);
  const key = decodeURIComponent(url.pathname.replace(/^\/fixture-bucket\//, ""));
  const xml = value => { response.setHeader("content-type", "application/xml"); response.end(value); };
  // The real credential custody write probe uses its reserved private key,
  // distinct from business copy effects and their measured counters.
  if (request.method === "GET" && url.searchParams.has("uploads")) {
    assert.equal(url.pathname, "/fixture-bucket");
    assert.equal(url.searchParams.get("max-uploads"), "1000");
    const prefix = url.searchParams.get("prefix");
    assert(prefix);
    const matches = [...uploads.entries()].filter(([, upload]) => !upload.closed && upload.key.startsWith(prefix));
    assert(matches.length <= 1000);
    counters.credentialProbes++;
    xml(`<ListMultipartUploadsResult><Bucket>fixture-bucket</Bucket><Prefix>${escape(prefix)}</Prefix><IsTruncated>false</IsTruncated>${matches.map(([id, upload]) => `<Upload><Key>${escape(upload.key)}</Key><UploadId>${id}</UploadId></Upload>`).join("")}</ListMultipartUploadsResult>`);
    return;
  }
  if (request.method === "POST" && url.searchParams.has("uploads") && key.startsWith("managed/binding/.aos/credential-probes/")) {
    counters.credentialProbes++;
    const upload = `credential-probe-${counters.credentialProbes}`;
    uploads.set(upload, { key, parts: new Map(), closed: false, probe: true });
    xml(`<InitiateMultipartUploadResult><Bucket>fixture-bucket</Bucket><Key>${escape(key)}</Key><UploadId>${upload}</UploadId></InitiateMultipartUploadResult>`);
    return;
  }
  const probeUpload = uploads.get(url.searchParams.get("uploadId"));
  if (probeUpload?.probe) {
    assert.equal(request.method, "DELETE");
    assert.equal(key, probeUpload.key);
    assert(!probeUpload.closed);
    probeUpload.closed = true;
    counters.credentialProbes++;
    response.statusCode = 204;
    response.end();
    return;
  }
  if (request.method === "GET" && url.searchParams.get("list-type") === "2") {
    const prefix = url.searchParams.get("prefix");
    const tail = scanTail ? Array.from({length:129}, (_, index) => `managed/binding/objects/destination/aux/${String(index).padStart(3,"0")}`) : [];
    const all = [...sourceAliases, ...destinations.keys(), ...tail].filter(value => value.startsWith(prefix)).sort();
    const limit = Number(url.searchParams.get("max-keys"));
    assert(limit > 0 && limit <= 128, "Installed provider list bound");
    counters.listRequests++;
    counters.maximumListLimit = Math.max(counters.maximumListLimit, limit);
    const prior = url.searchParams.get("continuation-token");
    assert(!prior || /^after:\d+$/.test(prior));
    const first = prior ? Number(prior.slice(6)) : 0;
    const entries = all.slice(first, first + limit);
    const truncated = first + entries.length < all.length;
    xml(`<ListBucketResult><Name>fixture-bucket</Name><Prefix>${escape(prefix)}</Prefix><KeyCount>${entries.length}</KeyCount><MaxKeys>${limit}</MaxKeys><IsTruncated>${truncated}</IsTruncated>${truncated ? `<NextContinuationToken>after:${first + entries.length}</NextContinuationToken>` : ""}${entries.map(value => {
      const selected = object(value);
      return `<Contents><Key>${escape(value)}</Key><Size>${selected.bytes.length}</Size><ETag>${escape(selected.etag)}</ETag></Contents>`;
    }).join("")}</ListBucketResult>`);
    return;
  }
  if (request.method === "HEAD" || (request.method === "GET" && !url.searchParams.has("uploadId"))) {
    const selected = object(key, url.searchParams.get("versionId"));
    if (!selected) { response.statusCode = 404; response.end(); return; }
    response.setHeader("etag", selected.etag);
    response.setHeader("x-amz-version-id", nullSourceVersion && key === setup.sourceKey && request.method === "HEAD" ? "null" : selected.version);
    if (request.method === "HEAD") { response.setHeader("content-length", selected.bytes.length); response.end(); return; }
    if (!url.searchParams.has("versionId") || !request.headers["if-match"] || !request.headers.range) {
      counters.unconditionalReads++; response.statusCode = 403; response.end(); return;
    }
    if (request.headers["if-match"] !== selected.etag) { response.statusCode = 412; response.end(); return; }
    const range = /^bytes=(\d+)-(\d+)$/.exec(request.headers.range);
    assert(range);
    const begin = Number(range[1]);
    const end = Number(range[2]) + 1;
    assert(begin < end && end <= selected.bytes.length);
    counters.conditionalReads++;
    response.statusCode = 206;
    response.setHeader("content-length", end - begin);
    response.setHeader("content-range", `bytes ${begin}-${end - 1}/${selected.bytes.length}`);
    for (let offset = begin; offset < end; offset += 65536) {
      if (!response.write(selected.bytes.subarray(offset, Math.min(offset + 65536, end)))) {
        await new Promise(resolve => response.once("drain", resolve));
      }
    }
    response.end(); return;
  }
  if (request.method === "POST" && url.searchParams.has("uploads")) {
    const sourceKey = key.replace("/objects/destination/", "/objects/source/");
    assert.notEqual(sourceKey, key);
    assert(sourceAliases.has(sourceKey), "Destination belongs to an actual enabled source");
    counters.creates++;
    const upload = `actual-upload-${counters.creates}`;
    uploads.set(upload, { key, parts: new Map(), closed: false });
    if (loseCreateReply) {
      loseCreateReply = false;
      response.destroy();
      return;
    }
    xml(`<InitiateMultipartUploadResult><Bucket>fixture-bucket</Bucket><Key>${escape(key)}</Key><UploadId>${upload}</UploadId></InitiateMultipartUploadResult>`);
    return;
  }
  const uploadId = url.searchParams.get("uploadId");
  const upload = uploads.get(uploadId);
  if (!upload || upload.closed || upload.key !== key) { response.statusCode = 404; response.end(); return; }
  if (request.method === "PUT") {
    assert.equal(request.headers["x-amz-checksum-sha256"], b64sha(body));
    const number = Number(url.searchParams.get("partNumber"));
    const etag = `"part-${number}-${sha(body).slice(0, 16)}"`;
    assert(!upload.parts.has(number));
    upload.parts.set(number, { bytes: body, etag });
    counters.parts++;
    response.setHeader("etag", etag); response.end(); return;
  }
  if (request.method === "POST") {
    counters.completeRequests++;
    const numbers = [...body.toString().matchAll(/<PartNumber>(\d+)<\/PartNumber>/g)].map(value => Number(value[1]));
    assert.deepEqual(numbers, [...upload.parts.keys()].sort((left, right) => left - right));
    for (const match of body.toString().matchAll(/<Part><PartNumber>(\d+)<\/PartNumber><ETag>([^<]*)<\/ETag><ChecksumSHA256>([^<]*)<\/ChecksumSHA256><\/Part>/g)) {
      const part = upload.parts.get(Number(match[1]));
      assert.equal(match[2], escape(part.etag));
      assert.equal(match[3], b64sha(part.bytes));
    }
    const bytes = Buffer.concat(numbers.map(number => upload.parts.get(number).bytes));
    assert.deepEqual(bytes, source);
    upload.closed = true;
    counters.completes++;
    const destination = { bytes, etag: '"destination-etag-1"', version: `destination-version-${counters.completes}` };
    response.setHeader("x-amz-version-id", destination.version);
    destinations.set(key, destination);
    xml(`<CompleteMultipartUploadResult><Location>https://s3.fleet.test/fixture-bucket/${key}</Location><Bucket>fixture-bucket</Bucket><Key>${escape(key)}</Key><ETag>${escape(destination.etag)}</ETag></CompleteMultipartUploadResult>`);
    return;
  }
  if (request.method === "DELETE") { upload.closed = true; counters.aborts++; response.statusCode = 204; response.end(); return; }
  response.statusCode = 405; response.end();
}

await mkdir(join(root, "do-storage"), { mode: 0o700 });
for (const name of ["shim.mjs", "index.wasm"]) {
  await writeFile(join(root, name), await readFile(join(dist, name)), { flag: "wx", mode: 0o600 });
}
for (const [target, name] of [["ca.crt", "hub-hybrid-fleet-s3-ca.crt"], ["server.crt", "hub-hybrid-fleet-s3.crt"], ["server.key", "hub-hybrid-fleet-s3.key"]]) {
  await writeFile(join(root, target), await readFile(join(tls, name)), { flag: "wx", mode: 0o600 });
}
const sourceServer = httpsServer({ cert: await readFile(join(root, "server.crt")), key: await readFile(join(root, "server.key")) }, (request, response) => {
  provider(request, response).catch(error => { console.error("PROVIDER_REFUSAL", error); response.destroy(error); });
});
await new Promise(resolve => sourceServer.listen(0, "127.0.0.1", resolve));
const providerPort = sourceServer.address().port;
const reserve = httpServer();
await new Promise(resolve => reserve.listen(0, "127.0.0.1", resolve));
workerPort = reserve.address().port;
await new Promise(resolve => reserve.close(resolve));
const config = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
 services=[(name="main",worker = .main),(name="do-disk",disk=(path="do-storage",writable=true)),
 (name="issuer",external=(address=${quote(setup.issuer)},http=(style=host))),
 (name="provider",external=(address="127.0.0.1:${providerPort}",https=(options=(style=host),certificateHost="s3.fleet.test",tlsOptions=(trustBrowserCas=false,trustedCertificates=[embed "ca.crt"]))))],
 sockets=[(name="http",address="127.0.0.1:${workerPort}",http=(),service="main")]
);
const main :Workerd.Worker = (
 modules=[(name="shim.mjs",esModule=embed "shim.mjs"),(name="index.wasm",wasm=embed "index.wasm")],
 compatibilityDate="2024-09-09",compatibilityFlags=["nodejs_compat","enable_request_signal"],globalOutbound="provider",
 durableObjectNamespaces=[(className="ExternalObjectGuard",uniqueKey="copy-guard",enableSql=true),(className="HybridBindingState",uniqueKey="copy-bindings",enableSql=true)],
 durableObjectStorage=(localDisk="do-disk"),
 bindings=[(name="EXTERNAL_OBJECT_GUARD",durableObjectNamespace="ExternalObjectGuard"),(name="HYBRID_BINDING_STATE",durableObjectNamespace="HybridBindingState"),
 (name="HUB_AUTHORITY_ISSUER",service="issuer"),(name="HUB_TOPOLOGY",text="hybrid"),(name="HUB_DEPLOYMENT_ID",text="fixture-deployment"),
 (name="HUB_STORAGE_WORK_KEY",text=${quote(setup.application)}),(name="HUB_EXTERNAL_OBJECT_GUARD_KEY",text=${quote(setup.guard)}),
 (name="HUB_AUTHORITY_RENEWAL_KEY",text=${quote(setup.renewal)}),
 (name="HUB_EXTERNAL_OBJECT_CONSUMER",text=${quote(JSON.stringify(setup.object))}),
 (name="HUB_EXTERNAL_COPY_CONSUMER",text=${quote(JSON.stringify(setup.copy))})]
);
`;
await writeFile(join(root, "worker.capnp"), config, { flag: "wx", mode: 0o600 });

async function stopWorker() {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const stopped = new Promise(resolve => child.once("exit", resolve));
  child.kill("SIGKILL"); await stopped;
}

async function startWorker() {
  counters.workerLifetimes++;
  const log = await open(join(root, `workerd-${counters.workerLifetimes}.log`), "wx", 0o600);
  child = spawn(workerd, ["serve", "worker.capnp"], { cwd: root, stdio: ["ignore", log.fd, log.fd] });
  await log.close();
  for (let attempt = 0; attempt < 200; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error("Worker exited before readiness");
    try { await fetch(`http://127.0.0.1:${workerPort}/`, { signal: AbortSignal.timeout(500) }); return; }
    catch { await new Promise(resolve => setTimeout(resolve, 50)); }
  }
  throw new Error("Worker readiness deadline elapsed");
}

const administrative = httpServer((request, response) => {
  const handle = async () => {
    if (request.method !== "POST") { response.statusCode = 405; response.end(); return; }
    if (request.url === "/fixture/restart-replace-source") {
      await stopWorker(); currentSourceVersion = "source-version-2"; await startWorker();
    } else if (request.url === "/fixture/select-source-version-2") {
      currentSourceVersion = "source-version-2";
    } else if (request.url === "/fixture/restore-source-version-1") {
      currentSourceVersion = "source-version-1";
    } else if (request.url === "/fixture/enable-mismatch-source") {
      mismatchSource = true;
      sourceAliases.add(setup.sourceKey.replace("source.nar", "mismatch.nar"));
    } else if (request.url === "/fixture/enable-race-source") {
      sourceAliases.add(setup.sourceKey.replace("source.nar", "race.nar"));
      catalogueRace = true;
    } else if (request.url === "/fixture/enable-legacy-source") {
      sourceAliases.add(setup.sourceKey.replace("source.nar", "legacy.nar"));
    } else if (request.url === "/fixture/populate-scan-tail") {
      scanTail = true;
    } else if (request.url === "/fixture/lose-create-reply") {
      loseCreateReply = true;
    } else if (request.url === "/fixture/null-source-version") {
      nullSourceVersion = true;
    } else assert.equal(request.url, "/fixture/inspect");
    response.setHeader("content-type", "application/json"); response.end(JSON.stringify(counters));
  };
  handle().catch(error => { console.error(error); response.statusCode = 500; response.end(); });
});
await new Promise(resolve => administrative.listen(0, "127.0.0.1", resolve));
await startWorker();
// Observe the actual Native-facing transport, including every offered and
// returned body. The byte stream goes between Worker and provider, never here.
const metadataRoutes = new Set([
  "/_internal/storage/v1/bindings", "/_internal/storage/v1/binding-adoption", "/_internal/storage/v1/execute",
  "/_internal/storage/v1/credential-custody/probe",
  "/_internal/storage/external-copy-metadata/v1", "/_internal/storage/external-copy/v1",
]);
const nativeRelay = httpsServer({ cert: await readFile(join(root, "server.crt")),
  key: await readFile(join(root, "server.key")) }, (request, response) => {
  const observe = async () => {
    const chunks = [];
    let requestBytes = 0;
    for await (const chunk of request) {
      requestBytes += chunk.length;
      assert(requestBytes <= 1024 * 1024, "Native metadata request bound");
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);
    const value = JSON.parse(body.toString("utf8"));
    const path = new URL(request.url, "http://relay.invalid").pathname;
    const operation = path === "/_internal/storage/v1/execute" ? value.operation?.kind : null;
    const operatorStage = request.method === "POST" && path === "/_internal/storage/v1/credential-custody";
    const metadata = request.method === "POST" && metadataRoutes.has(path)
      && (!operation || ["head", "list_page", "inspect_sha256"].includes(operation));
    const record = { method: request.method, path, operation, requestBytes,
      metadata, replyBytes: 0, status: null };
    if (operatorStage) {
      record.operatorCredentialStage = true;
      nativeBoundary.operatorCredentialStages = (nativeBoundary.operatorCredentialStages ?? 0) + 1;
    }
    nativeBoundary.records.push(record);
    nativeBoundary.calls++;
    nativeBoundary.requestBytes += requestBytes;
    if (!metadata && !operatorStage) nativeBoundary.bodyForwardingCalls++;
    assert(metadata || operatorStage, "Native transport must offer only closed metadata or explicit operator credential staging");
    const headers = { ...request.headers };
    for (const name of ["host", "connection", "transfer-encoding"]) delete headers[name];
    const result = await fetch(`http://127.0.0.1:${workerPort}${request.url}`, {
      method: "POST", headers, body, signal: AbortSignal.timeout(60_000),
    });
    const reply = Buffer.from(await result.arrayBuffer());
    assert(reply.length <= 256 * 1024, "Native metadata reply bound");
    if (result.ok) {
      const declaredType = result.headers.get("content-type");
      assert(!declaredType || declaredType.startsWith("application/json"));
      const decoded = JSON.parse(reply.toString("utf8"));
      if (operation) {
        const expected = {
          head: ["head", "not_found"],
          list_page: ["list_page"],
          inspect_sha256: ["sha256_evidence", "not_found"],
        };
        assert(expected[operation]?.includes(decoded.outcome?.kind), "Exact closed metadata outcome");
      }
    } else assert(reply.length <= 4096, "Bounded metadata refusal");
    record.replyBytes = reply.length;
    record.status = result.status;
    nativeBoundary.replyBytes += reply.length;
    if (catalogueRace && path === "/_internal/storage/external-copy-metadata/v1" && value.path === "nar/race.nar") {
      catalogueRace = false;
      const changed = await fetch(setup.catalogueMutation, { method: "POST" });
      assert.equal(changed.status, 204, "Actual concurrent SQL catalogue mutation");
    }
    record.refusal = result.ok ? null : reply.toString("utf8");
    await writeFile(join(root, "observed-counters.json"), JSON.stringify(counters), { mode: 0o600 });
    response.statusCode = result.status;
    for (const [name, value] of result.headers) {
      if (!["connection", "transfer-encoding", "content-encoding", "content-length"].includes(name)) {
        response.setHeader(name, value);
      }
    }
    response.end(reply);
  };
  observe().catch(error => { console.error("NATIVE_BOUNDARY_REFUSAL", error); response.destroy(error); });
});
await new Promise(resolve => nativeRelay.listen(0, "127.0.0.1", resolve));
await writeFile(join(root, "ready.json"), JSON.stringify({ workerOrigin: `https://s3.fleet.test:${nativeRelay.address().port}`,
  relayAddress: `127.0.0.1:${nativeRelay.address().port}`,
  administrativeOrigin: `http://127.0.0.1:${administrative.address().port}`, sourceSha256: sha(source) }), { flag: "wx", mode: 0o600 });
async function shutdown() {
  await writeFile(join(root, "observed-counters.json"), JSON.stringify(counters), { mode: 0o600 });
  await stopWorker();
  sourceServer.closeAllConnections();
  administrative.closeAllConnections();
  nativeRelay.closeAllConnections();
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.stdin.on("end", shutdown);
process.stdin.resume();
process.on("exit", () => child?.kill("SIGKILL"));
