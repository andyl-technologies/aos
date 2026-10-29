// Controlled actual provider transport and persistent production Worker guards.
// Native prepares this fixture from reviewed SQL and serves the real issuer.
// No hosted provider or deployment acceptance is established by this process.

import assert from "node:assert/strict";
import { VersionedObjects } from "./aos-hub-external-oci-provider.mjs";
import { spawn } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { createServer as httpServer } from "node:http";
import { createServer as httpsServer, request as httpsRequest } from "node:https";
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
  providerReceivedBytes: 0, providerOfferedReadBytes: 0, maximumPartBytes: 0, readRecords: [],
  listRequests: 0, maximumListLimit: 0, credentialProbes: 0 };
const uploads = new Map();
const destinations = new VersionedObjects(setup.physicalPrefix);
let loseCleanupReply = false;
let loseDeleteReply = false;
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
let workerHttpsPort;

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
  const destination = destinations.get(key, version);
  if (destination) return destination;
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
  counters.providerReceivedBytes += body.length;
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
  // The credential purpose probe is an absent service-owned key. It grants
  // no conditional-delete capability and can never remove a business object.
  if (request.method === "DELETE" && key.startsWith("managed/binding/.aos/credential-probes/delete/")) {
    assert(!object(key) && !url.searchParams.has("versionId") && !request.headers["if-match"]);
    counters.credentialProbes++;
    response.statusCode = 204; response.end(); return;
  }
  if (request.method === "DELETE" && !url.searchParams.has("uploadId")) {
    assert.equal(body.length, 0);
    const version = url.searchParams.get("versionId");
    const etag = request.headers["if-match"];
    const result = destinations.conditionalDelete(key, version, etag);
    counters.conditionalDeleteRequests = (counters.conditionalDeleteRequests ?? 0) + 1;
    counters.unconditionalObjectDeletes = (counters.unconditionalObjectDeletes ?? 0) + Number(!version || !etag);
    const records = counters.deleteRecords ??= [];
    assert(records.length < 128, "Controlled delete observation bound");
    records.push({keySha256:sha(key), versionSha256:version ? sha(version) : null,
      etagSha256:etag ? sha(etag) : null, status:result.status, deleted:result.deleted});
    if (result.deleted) {
      counters.deletedVersions = (counters.deletedVersions ?? 0) + 1;
      response.setHeader("x-amz-version-id", result.object.version);
      response.setHeader("etag", result.object.etag);
      if (loseDeleteReply) {
        loseDeleteReply = false;
        counters.lostDeleteReplies = (counters.lostDeleteReplies ?? 0) + 1;
        response.destroy(); return;
      }
    }
    response.statusCode = result.status; response.end(); return;
  }
  if (request.method === "PUT" && !url.searchParams.has("uploadId")
      && key.startsWith(`${setup.physicalPrefix}/.aos-internal/conditional-delete-probes/`)) {
    assert(body.length > 0 && body.length <= 4096);
    const selected = destinations.put(key, body);
    counters.capabilityProbePuts = (counters.capabilityProbePuts ?? 0) + 1;
    response.setHeader("etag", selected.etag); response.setHeader("x-amz-version-id", selected.version);
    response.end(); return;
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
    if (request.headers["if-match"] && request.headers["if-match"] !== selected.etag) {
      response.statusCode = 412; response.end(); return;
    }
    response.setHeader("etag", selected.etag);
    response.setHeader("x-amz-version-id", nullSourceVersion && key === setup.sourceKey && request.method === "HEAD" ? "null" : selected.version);
    if (request.method === "HEAD") { response.setHeader("content-length", selected.bytes.length); response.end(); return; }
    if (!url.searchParams.has("versionId") || !request.headers["if-match"]) {
      counters.unconditionalReads++; response.statusCode = 403; response.end(); return;
    }
    if (request.headers["if-match"] !== selected.etag) { response.statusCode = 412; response.end(); return; }
    const range = request.headers.range ? /^bytes=(\d+)-(\d+)$/.exec(request.headers.range) : null;
    assert(!request.headers.range || range);
    const begin = range ? Number(range[1]) : 0;
    const end = range ? Number(range[2]) + 1 : selected.bytes.length;
    assert((begin < end || (!range && selected.bytes.length === 0)) && end <= selected.bytes.length);
    assert(counters.readRecords.length < 256, "Controlled read observation bound");
    counters.readRecords.push({ keySha256: sha(key), versionSha256: sha(selected.version),
      range: range ? { begin, end } : null, offeredBytes: end - begin });
    counters.conditionalReads++;
    response.statusCode = range ? 206 : 200;
    response.setHeader("content-length", end - begin);
    if (range) response.setHeader("content-range", `bytes ${begin}-${end - 1}/${selected.bytes.length}`);
    for (let offset = begin; offset < end; offset += 65536) {
      const offered = selected.bytes.subarray(offset, Math.min(offset + 65536, end));
      counters.providerOfferedReadBytes += offered.length;
      if (!response.write(offered)) {
        await new Promise(resolve => response.once("drain", resolve));
      }
    }
    response.end(); return;
  }
  if (request.method === "POST" && url.searchParams.has("uploads")) {
    assert(key.startsWith(setup.physicalPrefix + "/oci/"), "OCI effect stays in the exact reserved placement");
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
  if (request.method === "PUT" && !url.searchParams.has("uploadId")) {
    assert(key.startsWith(setup.physicalPrefix + "/oci/blobs/sha256/"));
    assert.equal(request.headers["if-none-match"], "*");
    assert.equal(body.length, 0);
    assert.equal(request.headers["content-md5"], "1B2M2Y8AsgTpgAmY7PhCfg==");
    if (destinations.get(key)) { response.statusCode = 412; response.end(); return; }
    const selected = destinations.put(key, body); counters.emptyPuts = (counters.emptyPuts ?? 0) + 1;
    response.setHeader("etag", selected.etag); response.setHeader("x-amz-version-id", selected.version);
    response.end(); return;
  }
  const uploadId = url.searchParams.get("uploadId");
  const upload = uploads.get(uploadId);
  if (!upload || upload.closed || upload.key !== key) { response.statusCode = 404; response.end(); return; }
  if (request.method === "PUT") {
    if (request.headers["x-amz-checksum-sha256"]) assert.equal(request.headers["x-amz-checksum-sha256"], b64sha(body));
    assert.equal(request.headers["content-md5"], createHash("md5").update(body).digest("base64"));
    const number = Number(url.searchParams.get("partNumber"));
    const etag = `"part-${number}-${sha(body).slice(0, 16)}"`;
    assert(!upload.parts.has(number));
    upload.parts.set(number, { bytes: body, etag });
    counters.parts++;
    counters.maximumPartBytes = Math.max(counters.maximumPartBytes, body.length);
    response.setHeader("etag", etag); response.end(); return;
  }
  if (request.method === "POST") {
    counters.completeRequests++;
    const numbers = [...body.toString().matchAll(/<PartNumber>(\d+)<\/PartNumber>/g)].map(value => Number(value[1]));
    assert.deepEqual(numbers, [...upload.parts.keys()].sort((left, right) => left - right));
    const completedParts = [...body.toString().matchAll(/<Part><PartNumber>(\d+)<\/PartNumber><ETag>([^<]*)<\/ETag>(?:<ChecksumSHA256>([^<]*)<\/ChecksumSHA256>)?<\/Part>/g)];
    assert.equal(completedParts.length, numbers.length, "Every completion part carries its exact ETag");
    for (const match of completedParts) {
      const part = upload.parts.get(Number(match[1]));
      // Quotes are legal literal XML text; the equivalent entity spelling is
      // also accepted. Both forms still bind the exact positive part receipt.
      assert(match[2] === part.etag || match[2] === escape(part.etag), "Exact completed part ETag");
      if (match[3]) assert.equal(match[3], b64sha(part.bytes));
    }
    const bytes = Buffer.concat(numbers.map(number => upload.parts.get(number).bytes));
    assert(bytes.length <= 20 * 1024 * 1024, "Existing OCI chunk cap");
    upload.closed = true;
    counters.completes++;
    const destination = destinations.put(key, bytes);
    response.setHeader("x-amz-version-id", destination.version);
    xml(`<CompleteMultipartUploadResult><Location>https://s3.fleet.test/fixture-bucket/${key}</Location><Bucket>fixture-bucket</Bucket><Key>${escape(key)}</Key><ETag>${escape(destination.etag)}</ETag></CompleteMultipartUploadResult>`);
    return;
  }
  if (request.method === "DELETE") { upload.closed = true; counters.aborts++; response.statusCode = 204; response.end(); return; }
  response.statusCode = 405; response.end();
}

async function nativeOrigin(request, response) {
  const chunks = []; let offered = 0;
  for await (const chunk of request) {
    offered += chunk.length; assert(offered <= 256 * 1024, "Native OCI control cap"); chunks.push(chunk);
  }
  const body = Buffer.concat(chunks);
  const phase = request.headers["x-aos-hybrid-upload-phase"] ?? null;
  const record = {method:request.method, phase, requestBytes:offered, requestSha256:sha(body)};
  if (phase === "authorize" || phase === "authorize-final") assert.equal(offered, 0);
  if (phase === "complete") {
    if (request.method === "PATCH" && new URL(request.url, "http://fixture.invalid").pathname.includes("/blobs/uploads/")) {
      const completion = JSON.parse(body);
      assert.deepEqual(Object.keys(completion).sort(), ["admission", "byte_size", "chunk_sha256", "next_sha256_state"]);
      assert(Number.isSafeInteger(completion.byte_size) && completion.byte_size > 0);
      assert(/^[0-9a-f]{64}$/.test(completion.chunk_sha256));
      assert(completion.admission.external && completion.next_sha256_state.version === 1);
    } else {
      assert.equal(request.method, "PUT");
      assert(new URL(request.url, "http://fixture.invalid").pathname.includes("/manifests/"));
      assert.equal(body.toString(), "{}");
    }
  }
  const headers = {...request.headers};
  for (const name of ["host", "connection", "transfer-encoding"]) delete headers[name];
  const result = await fetch(`http://${setup.native}${request.url}`, {
    method:request.method, headers, ...(offered ? {body} : {}), signal:AbortSignal.timeout(60_000),
  });
  const reply = Buffer.from(await result.arrayBuffer());
  assert(reply.length <= 256 * 1024);
  record.replyBytes = reply.length; record.replySha256 = sha(reply); record.status = result.status;
  counters.nativeBusiness ??= []; counters.nativeBusiness.push(record);
  response.statusCode = result.status;
  for (const [name,value] of result.headers) {
    if (!["connection", "transfer-encoding", "content-length", "content-encoding"].includes(name)) response.setHeader(name,value);
  }
  response.end(reply);
}

await mkdir(join(root, "do-storage"), { mode: 0o700 });
for (const name of ["shim.mjs", "index.wasm"]) await writeFile(join(root, name), await readFile(join(dist, name)), { flag: "wx", mode: 0o600 });
for (const [target, name] of [["ca.crt", "hub-hybrid-fleet-s3-ca.crt"], ["server.crt", "hub-hybrid-fleet-s3.crt"], ["server.key", "hub-hybrid-fleet-s3.key"]]) {
  await writeFile(join(root, target), await readFile(join(tls, name)), { flag: "wx", mode: 0o600 });
}
const workerCa = await readFile(join(root, "ca.crt"));
const sourceServer = httpsServer({ cert: await readFile(join(root, "server.crt")), key: await readFile(join(root, "server.key")) }, (request, response) => {
  const operation = request.headers.host === "native.fixture.test"
    ? nativeOrigin(request, response) : provider(request, response);
  operation.catch(error => { console.error("FIXTURE_REFUSAL", error); response.destroy(error); });
});
await new Promise(resolve => sourceServer.listen(0, "127.0.0.1", resolve));
const providerPort = sourceServer.address().port;
const reserve = httpServer();
await new Promise(resolve => reserve.listen(0, "127.0.0.1", resolve));
workerPort = reserve.address().port;
await new Promise(resolve => reserve.close(resolve));
const publicReserve = httpServer();
await new Promise(resolve => publicReserve.listen(0, "127.0.0.1", resolve));
workerHttpsPort = publicReserve.address().port;
await new Promise(resolve => publicReserve.close(resolve));
assert.equal(setup.guardClockPolicy.version, 1);
assert.equal(setup.guardClockPolicy.mode, "bounded_utc");
assert.equal(setup.guardClockPolicy.uncertaintySeconds, "2");
assert.match(setup.guardClockQualification, /^[0-9a-f]{64}$/);

const config = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
 services=[(name="main",worker = .main),(name="do-disk",disk=(path="do-storage",writable=true)),
 (name="issuer",external=(address=${quote(setup.issuer)},http=(style=host))),
 (name="provider",external=(address="127.0.0.1:${providerPort}",https=(options=(style=host),certificateHost="s3.fleet.test",tlsOptions=(trustBrowserCas=false,trustedCertificates=[embed "ca.crt"]))))],
 sockets=[(name="http",address="127.0.0.1:${workerPort}",http=(),service="main"),
 (name="https",address="127.0.0.1:${workerHttpsPort}",https=(options=(),tlsOptions=(keypair=(privateKey=embed "server.key",certificateChain=embed "server.crt"))),service="main")]
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
 ${setup.bootstrapOnly ? "" : ` (name="HUB_EXTERNAL_OBJECT_CONSUMER",text=${quote(JSON.stringify(setup.object))}),
 (name="HUB_EXTERNAL_DELETE_CONSUMER",text=${quote(JSON.stringify(setup.delete))}),
 (name="HUB_EXTERNAL_OCI_CONSUMER",text=${quote(JSON.stringify(setup.oci))}),
 (name="HUB_EXTERNAL_OCI_CANDIDATE_KEY",text=${quote(setup.candidateKey)}),
 (name="HUB_EXTERNAL_OCI_CANDIDATE",text=${quote(setup.candidate)}),
 (name="HUB_EXTERNAL_OCI_CANDIDATE_SIGNATURE",text=${quote(setup.candidateSignature)}),
`}
 (name="HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS",text=${quote(setup.guardClockPolicy.uncertaintySeconds)}),
 (name="HUB_DIRECT_UPLOAD_CLOCK_MODE",text=${quote(setup.guardClockPolicy.mode)}),
 (name="HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION",text=${quote(setup.guardClockQualification)}),
 (name="HUB_HYBRID_ORIGIN_URL",text="https://native.fixture.test"),
 (name="HUB_HYBRID_INGRESS_KEY",text=${quote(setup.ingress)})]
);
`;
await writeFile(join(root, "worker.capnp"), config, { flag: "wx", mode: 0o600 });

// Public OCI reaches the real TLS socket, preserving the authenticated public
// authority. Internal controls retain their original private HTTP transport.
async function publicWorker(requestUrl, method, headers, body) {
  return await new Promise((resolve, reject) => {
    const outgoing = httpsRequest({
      hostname: "127.0.0.1", port: workerHttpsPort, path: requestUrl,
      method, headers, servername: "s3.fleet.test", ca: workerCa,
    }, incoming => {
      const receive = async () => {
        const chunks = [];
        let length = 0;
        for await (const chunk of incoming) {
          length += chunk.length;
          assert(length <= 256 * 1024, "Public OCI metadata response bound");
          chunks.push(chunk);
        }
        const responseHeaders = new Headers();
        for (const [name, value] of Object.entries(incoming.headers)) {
          if (value !== undefined) responseHeaders.set(name, String(value));
        }
        const reply = Buffer.concat(chunks);
        resolve({status: incoming.statusCode, ok: incoming.statusCode >= 200 && incoming.statusCode < 300,
          headers: responseHeaders, arrayBuffer: async () => reply});
      };
      receive().catch(error => { incoming.destroy(); reject(error); });
    });
    outgoing.on("error", reject);
    outgoing.setTimeout(60_000, () => outgoing.destroy(new Error("Public OCI TLS deadline elapsed")));
    outgoing.end(body);
  });
}

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
    try { await fetch(`http://127.0.0.1:${workerPort}/_internal/storage/external-oci/v1`, { signal: AbortSignal.timeout(500) }); return; }
    catch { await new Promise(resolve => setTimeout(resolve, 50)); }
  }
  throw new Error("Worker readiness deadline elapsed");
}

const administrative = httpServer((request, response) => {
  const handle = async () => {
    if (request.method !== "POST") { response.statusCode = 405; response.end(); return; }
    if (request.url === "/fixture/restart-replace-source") {
      await stopWorker(); currentSourceVersion = "source-version-2"; await startWorker();
    } else if (request.url === "/fixture/lose-cleanup-reply") {
      loseCleanupReply = true;
    } else if (request.url === "/fixture/lose-delete-reply") {
      loseDeleteReply = true;
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
  "/_internal/storage/external-oci-cleanup/v1", "/_internal/storage/external-oci-source/v1", "/_internal/storage/external-oci/v1", "/_internal/storage/oci-document-projection",
]);
const nativeRelay = httpsServer({ cert: await readFile(join(root, "server.crt")),
  key: await readFile(join(root, "server.key")) }, (request, response) => {
  const observe = async () => {
    const chunks = [];
    let requestBytes = 0;
    for await (const chunk of request) {
      requestBytes += chunk.length;
      assert(requestBytes <= 20 * 1024 * 1024, "Public existing OCI chunk bound");
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);
    const publicOci = request.url.startsWith("/v2/");
    const value = publicOci ? null : JSON.parse(body.toString("utf8"));
    const path = new URL(request.url, "http://relay.invalid").pathname;
    const operation = path === "/_internal/storage/v1/execute" ? value?.operation?.kind : null;
    const operatorStage = request.method === "POST" && path === "/_internal/storage/v1/credential-custody";
    const capabilityProbe = ["put_probe", "delete_if_matches"].includes(operation)
      && /^\.aos-internal\/conditional-delete-probes\/[1-9]\d*-[1-9]\d*$/.test(value.operation.path);
    const metadata = request.method === "POST" && metadataRoutes.has(path)
      && (!operation || ["head", "list_page", "inspect_sha256"].includes(operation) || capabilityProbe);
    const record = { method: request.method, path, operation, requestBytes,
      metadata, replyBytes: 0, status: null };
    if (operatorStage) {
      record.operatorCredentialStage = true;
      nativeBoundary.operatorCredentialStages = (nativeBoundary.operatorCredentialStages ?? 0) + 1;
    }
    if (!publicOci) {
      assert(requestBytes <= 1024 * 1024);
      nativeBoundary.records.push(record); nativeBoundary.calls++; nativeBoundary.requestBytes += requestBytes;
      if (!metadata && !operatorStage) nativeBoundary.bodyForwardingCalls++;
    }
    assert(publicOci || metadata || operatorStage, "Native transport must offer only closed metadata or explicit operator credential staging");
    const headers = { ...request.headers };
    for (const name of ["host", "connection", "transfer-encoding"]) delete headers[name];
    if (publicOci) headers.host = request.headers.host;
    const result = publicOci
      ? await publicWorker(request.url, request.method, headers, body)
      : await fetch(`http://127.0.0.1:${workerPort}${request.url}`, {
        method: request.method, headers, ...(!["GET","HEAD"].includes(request.method) ? {body} : {}), signal: AbortSignal.timeout(60_000),
      });
    const reply = Buffer.from(await result.arrayBuffer());
    assert(reply.length <= 256 * 1024, "Native metadata reply bound");
    if (result.ok && !publicOci) {
      const declaredType = result.headers.get("content-type");
      assert(!declaredType || declaredType.startsWith("application/json"));
      const decoded = JSON.parse(reply.toString("utf8"));
      if (operation) assert(["head", "list_page", "sha256", "probe_acknowledged", "object_deleted", "delete_precondition_failed", "not_found"].includes(decoded.outcome?.kind));
    } else assert(reply.length <= 4096, "Bounded metadata refusal");
    record.replyBytes = reply.length;
    record.status = result.status;
    if (!publicOci) nativeBoundary.replyBytes += reply.length;
    if (catalogueRace && path === "/_internal/storage/external-copy-metadata/v1" && value.path === "nar/race.nar") {
      catalogueRace = false;
      const changed = await fetch(setup.catalogueMutation, { method: "POST" });
      assert.equal(changed.status, 204, "Actual concurrent SQL catalogue mutation");
    }
    if (loseCleanupReply && path === "/_internal/storage/external-oci-cleanup/v1" && result.ok) {
      loseCleanupReply = false;
      counters.lostCleanupReplies = (counters.lostCleanupReplies ?? 0) + 1;
      record.replyWithheldAfterPositive = true;
      response.destroy(); return;
    }
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
