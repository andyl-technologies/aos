// Exercises the operator driver against an authenticated HTTPS control peer.
// This is a protocol/stream/cancellation test, not provider qualification.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { createServer } from "node:https";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { createResponseHold } from "../../tests/fleet/_hub-direct-provider-response-hold.mjs";
import { chmod, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const openssl = process.argv[2];
const driver = resolve(process.argv[3] ?? "pkgs/tools/aos-hub-direct-qualification.mjs");
if (!openssl?.startsWith("/nix/store/")) throw new Error("Supply the source-built AOS OpenSSL path.");
const python = process.argv[4];
const collector = resolve(process.argv[5] ?? "tests/fleet/_hub-direct-qualification.py");
if (!python?.startsWith("/nix/store/")) throw new Error("Supply the source-built AOS Python path.");
const root = await mkdtemp("/tmp/aos-direct-qualification-driver-tests-");
await chmod(root, 0o700);
const cert = join(root, "test.crt"), privateKey = join(root, "test.key");
const generated = spawnSync(openssl, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
  "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", privateKey, "-out", cert],
  { stdio: "ignore" });
assert.equal(generated.status, 0);
await chmod(privateKey, 0o600);
const secret = "driver-protocol-test-private-key-0001";
const keyFile = join(root, "control.key");
await writeFile(keyFile, secret, { mode: 0o600 });
const payload = Buffer.alloc(16 * 1024 * 1024 + 17, 0x36), payloadFile = join(root, "payload");
await writeFile(payloadFile, payload, { mode: 0o600 });
const secondPayload = Buffer.alloc(payload.length, 0x37), secondPayloadFile = join(root, "second-payload");
await writeFile(secondPayloadFile, secondPayload, { mode: 0o600 });
const secondPayloadDigest = createHash("sha256").update(secondPayload).digest("hex");
// These are protocol bytes, not a claim of narinfo semantic verification.
const metadataPayload = Buffer.alloc(256 * 1024, 0x6d), metadataFile = join(root, "metadata-payload");
await writeFile(metadataFile, metadataPayload, { mode: 0o600 });
const sourceBytes = object => object.metadata ? metadataPayload
  : object.expectedSha256 === secondPayloadDigest ? secondPayload : payload;
const uploadedByObject = new Map(), uploadRoutes = new Set();
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
// Production Grant replies pass through serde_json::Value's sorted maps.
const sorted = value => Array.isArray(value) ? value.map(sorted)
  : value !== null && typeof value === "object"
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
const placement = { placementId: "1", placementFingerprint: "bb".repeat(32),
  placementResourceVersion: "2", writeSpecVersion: "3", bindingId: "4",
  bindingResourceVersion: "5", bindingWriteRevision: "6", profileFingerprint: "dd".repeat(32),
  privatePolicyDigest: "ee".repeat(32), checksumAlgorithm: "md5" };
const mac = (domain, bytes) => createHmac("sha256", secret).update("aos-storage-work-v1\0").update(domain).update(bytes).digest("hex");
const baselineDriver = process.argv[6];
let scenario, child, origin, original, uploaded, receipt;
let mixedFixture = null;
const mixedEntries = new Map();
let mixedDispatches = 0, mixedBulkActive = 0, mixedMetadataAdmissions = 0, mixedPeakActive = 0;

async function verifyMixedObject(object) {
  const before = { isolateId: "driver-isolate", dispatches: mixedDispatches,
    metadataAdmissionsDuringBulk: mixedMetadataAdmissions };
  const attempt = { nonce: digest(Buffer.from(object.objectId + "-attempt")),
    startedAtMillis: String(Date.now()), providerBefore: before };
  const entry = mixedEntries.get(object.objectId);
  entry.attempt = attempt;
  if (!object.metadata) mixedBulkActive += 1;
  else if (mixedBulkActive > 0) mixedMetadataAdmissions += 1;
  mixedDispatches += 1;
  const observedObjects = { aggregateActive: mixedBulkActive + Number(object.metadata),
    bulkActive: mixedBulkActive, metadataActive: Number(object.metadata) };
  mixedPeakActive = Math.max(mixedPeakActive, observedObjects.aggregateActive);
  const observed = await new Promise((done, reject) => {
    const outgoing = httpRequest({ host: "127.0.0.1", port: mixedFixture.listenerPort,
      path: object.metadata ? "/metadata-payload" : scenario === "mixed-saturation"
        && object.objectId !== original.objects[0].objectId ? "/bulk-second-payload" : "/bulk-payload", agent: false,
      headers: { host: "s3.fleet.test", "if-match": '"actual-etag"',
        authorization: "AWS4-HMAC-SHA256 Credential=test/20261002/garage/s3/aws4_request, "
          + "SignedHeaders=host;if-match;x-amz-content-sha256;x-amz-date, Signature=" + "a".repeat(64),
        "x-amz-date": "20261002T010000Z", "x-amz-content-sha256": digest(Buffer.alloc(0)) } }, incoming => {
      assert.equal(incoming.statusCode, 200);
      let byteSize = 0;
      const hash = createHash("sha256");
      incoming.on("data", block => { byteSize += block.length; hash.update(block); });
      incoming.once("error", reject);
      incoming.once("end", () => done({ sha256: hash.digest("hex"), byte_size: String(byteSize) }));
    });
    outgoing.once("error", reject); outgoing.end();
  });
  const expected = sourceBytes(object);
  assert.equal(object.expectedSha256, digest(expected));
  assert.equal(object.byteSize, String(expected.length));
  assert.deepEqual(observed, { sha256: digest(expected), byte_size: String(expected.length) });
  entry.receipt = { attempt, finishedAtMillis: String(Date.now()), queueName: object.metadata ? "driver-metadata" : "driver-bulk",
    messageId: object.objectId, providerAfter: { isolateId: "driver-isolate", dispatches: mixedDispatches,
      peakActive: mixedPeakActive, metadataAdmissionsDuringBulk: mixedMetadataAdmissions }, objects: observedObjects,
    verificationReplayed: false, proof: observed };
  if (!object.metadata) mixedBulkActive -= 1;
}

async function mixedPeer(action) {
  if (action.kind === "enqueue") {
    const objects = original.objects.filter(object => action.objectIds.includes(object.objectId));
    if (scenario === "mixed-saturation" && objects.some(object => !object.metadata)) {
      assert.equal(objects.length, 2, "Both bulk originals must share one queue delivery batch");
    }
    if (scenario === "mixed-baseline" && objects.length === 2) {
      // Actual old producer batch reaches a controlled metadata-first scheduler.
      await verifyMixedObject(objects.find(object => object.metadata));
      mixedFixture.tasks.push(verifyMixedObject(objects.find(object => !object.metadata)));
    } else for (const object of objects) mixedFixture.tasks.push(verifyMixedObject(object));
    return {};
  }
  if (action.kind === "status") return { original, objects: original.objects.map(object => ({
    objectId: object.objectId, closed: true, verified: mixedEntries.get(object.objectId).receipt !== null,
    attemptCount: mixedEntries.get(object.objectId).attempt ? 1 : 0 })) };
  const entry = mixedEntries.get(action.objectId);
  return { original, objectId: action.objectId, closed: entry.closed,
    attempts: action.afterAttempt === 0 && entry.attempt ? [{ attempt: entry.attempt, receipt: entry.receipt }] : [], nextAttempt: null };
}

async function pumpMixed(output) {
  let arm, ready, resumed = false;
  const timeout = Date.now() + 15000;
  const json = async name => {
    try { return JSON.parse(await readFile(join(output, name))); }
    catch (error) { if (error.code !== "ENOENT") throw error; return null; }
  };
  const save = (name, value) => writeFile(resolve(output, "..", name), JSON.stringify(sorted(value)), { mode: 0o600, flag: "wx" });
  while (Date.now() < timeout) {
    const arming = await json("mixed-arm-ready.json");
    if (arming && !arm) {
      arm = { version: 1, kind: "arm_mixed_read", cohortNonce: arming.cohortNonce,
        bindings: Object.fromEntries(["runId", "objectId", "originalSha256", "closedSha256", "jobProjectionSha256"].map(key => [key, arming[key]])),
        selection: { target: "/bulk-payload", host: "s3.fleet.test", etag: '"actual-etag"' },
        expectedSourceSha256: digest(payload), expectedSourceBytes: String(payload.length),
        expectedPrefixSha256: digest(payload.subarray(0, 65536)), selectionContextSha256: digest(Buffer.from(JSON.stringify(sorted(arming)))),
        selectionDeadlineUnixMillis: Date.now() + 15000, pauseMillis: 15000, streamMillis: 15000 };
      assert.equal((await mixedFixture.listener.command(arm)).status, "armed");
      await save("mixed-arm-release.json", { version: 1, runId: arming.runId,
        readySha256: digest(Buffer.from(JSON.stringify(sorted(arming)))), heldReceiptSha256: digest(Buffer.from(JSON.stringify(arm))) });
    }
    const candidate = await json("mixed-admission-ready.json");
    const command = arm && { version: 1, kind: "mixed_state", cohortNonce: arm.cohortNonce, bindings: arm.bindings };
    if (candidate && !ready) {
      const state = await mixedFixture.listener.command(command);
      if (state.state === "held") {
        assert.equal(mixedEntries.get(candidate.objectId).attempt.nonce, candidate.attemptNonce);
        assert.equal(mixedBulkActive, scenario === "mixed-saturation" ? 2 : 1);
        assert.equal(state.receipt.downstreamOfferedBytes, "0");
        await mixedFixture.listener.command({ ...command, kind: "bind_mixed_begin", beginNonce: candidate.attemptNonce });
        await save("mixed-admission-release.json", { version: 1, runId: candidate.runId,
          readySha256: digest(Buffer.from(JSON.stringify(sorted(candidate)))), heldReceiptSha256: state.receiptFile.sha256 });
        ready = candidate;
      }
    }
    const finish = await json("mixed-admission-metadata-finish.json");
    if (finish && !resumed) {
      const state = await mixedFixture.listener.command(command);
      assert.equal(state.state, "held");
      assert.equal(finish.record.receipt.objects.bulkActive, scenario === "mixed-saturation" ? 2 : 1);
      assert.equal(finish.record.object.metadata, true);
      assert.equal(finish.record.receipt.proof.sha256, digest(metadataPayload));
      assert.equal(finish.record.receipt.proof.byte_size, String(metadataPayload.length));
      assert.equal((await mixedFixture.listener.command({ ...command, kind: "resume_mixed_read",
        beginNonce: ready.attemptNonce, heldReceiptSha256: state.receiptFile.sha256,
        metadataReceiptSha256: digest(Buffer.from(JSON.stringify(sorted(finish.record.receipt)))) })).status, "resume_dispatched");
      resumed = true;
    }
    if (resumed && (await mixedFixture.listener.command(command)).state === "eof") return;
    if (child.exitCode !== null) throw new Error("actual producer exited before mixed stream EOF");
    await new Promise(done => setTimeout(done, 5));
  }
  throw new Error("controlled mixed pump deadline");
}
const calls = [], partOrder = [];
const server = createServer({ cert: await readFile(cert), key: await readFile(privateKey) }, async (request, response) => {
  try {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const bytes = Buffer.concat(chunks);
    if (request.url.startsWith("/part/")) {
      const match = /^\/part\/([a-f0-9]{64})\/([1-9][0-9]*)$/.exec(request.url);
      assert.ok(match);
      assert.equal(uploadRoutes.has(request.url), false);
      uploadRoutes.add(request.url);
      const object = original.objects.find(candidate => candidate.objectId === match[1]);
      assert.ok(object);
      const expected = sourceBytes(object), number = Number(match[2]);
      assert.equal(request.headers["content-length"], String(bytes.length));
      assert.equal(request.headers["content-md5"], createHash("md5").update(bytes).digest("base64"));
      const offset = (number - 1) * 8 * 1024 * 1024;
      assert.equal(bytes.length, Math.min(8 * 1024 * 1024, expected.length - offset));
      assert.equal(digest(bytes), digest(expected.subarray(offset, offset + bytes.length)));
      uploadedByObject.set(object.objectId, (uploadedByObject.get(object.objectId) ?? 0) + bytes.length);
      if (number === 1) await new Promise(done => setTimeout(done, 50));
      uploaded += bytes.length; partOrder.push(number);
      response.writeHead(200, { etag: `"part-${number}"` }); response.end(); return;
    }
    assert.equal(request.headers["x-aos-direct-qualification-signature"], mac("aos.direct-upload.qualification-request.v1\0", bytes));
    const control = JSON.parse(bytes), action = control.action; calls.push(action.kind);
    if (scenario === "unknown" && action.kind === "begin") { request.socket.destroy(); return; }
    if (scenario === "timeout-inspect-failure" && action.kind === "inspect" && action.afterAttempt === 1) {
      request.socket.destroy(); return;
    }
    if (scenario === "cancel" && action.kind === "clock") { child.kill("SIGTERM"); await new Promise(done => setTimeout(done, 30)); }
    let result = {}, responseStatus = 200;
    if (scenario.startsWith("mixed-") && ["enqueue", "status", "inspect"].includes(action.kind)) {
      result = await mixedPeer(action);
    } else switch (action.kind) {
      case "start":
        original = { version: 1, runId: control.runId, sourceDigest: control.sourceDigest, scriptVersion: control.scriptVersion,
          deploymentId: "driver-test", publicOrigin: origin, executionKind: "hosted", objects: action.objects,
          bulkQueueName: "driver-bulk", metadataQueueName: "driver-metadata", material: { profile: { checksumAlgorithm: "md5" } } };
        if (scenario.startsWith("mixed-")) for (const object of original.objects) {
          mixedEntries.set(object.objectId, { attempt: null, receipt: null,
            closed: { settlementMillis: "5", job: { objectId: object.objectId, fixture: "authenticated local peer only" } } });
        }
        result = { original }; break;
      case "clock": result = { kind: "clock", observedAtMillis: String(Date.now()),
        uncertaintySeconds: scenario === "clock-wrong-uncertainty" ? "2" : "1", nonce: control.nonce }; break;
      case "expired_mutation": result = { observedAt: String(Math.floor(Date.now() / 1000)),
        providerBefore: { isolateId: "driver-isolate", dispatches: 0 }, providerAfter: { isolateId: "driver-isolate", dispatches: 0 } }; break;
      case "begin": break;
      case "grant": result = { grants: action.parts.map(part => ({ sessionId: "session", logicalFingerprint: "aa".repeat(32),
        placement,
        grantId: "cc".repeat(32), grantRevision: "1", part, method: "PUT", url: `${origin}/part/${action.objectId}/${part.partNumber}`,
        requiredHeaders: [{ name: "content-md5", value: part.checksum.value }] })) }; break;
      case "report": {
        const object = original.objects.find(candidate => candidate.objectId === action.objectId);
        assert.ok(object);
        assert.equal(action.reports.length, Math.ceil(sourceBytes(object).length / (8 * 1024 * 1024)));
        for (const report of action.reports) {
          const fields = Object.keys(placement);
          const part = report.observed.part;
          const orderedPart = { partNumber: part.partNumber, offset: part.offset,
            byteSize: part.byteSize, sha256: part.sha256,
            checksum: { algorithm: part.checksum.algorithm, value: part.checksum.value } };
          const canonical = { session: { sessionId: report.session.sessionId,
            logicalFingerprint: report.session.logicalFingerprint },
            placement: Object.fromEntries(fields.map(field => [field, report.placement[field]])),
            operationId: report.operationId, grantId: report.grantId, grantRevision: report.grantRevision,
            observed: { part: orderedPart, etag: report.observed.etag } };
          if (JSON.stringify(report) !== JSON.stringify(canonical)) {
            console.error("Controlled peer refused noncanonical Report field ordering or schema.");
            throw new Error("Noncanonical typed Report.");
          }
          assert.deepEqual(report.placement, placement);
        }
        break;
      }
      case "close": {
        const object = original.objects.find(candidate => candidate.objectId === action.objectId);
        assert.ok(object);
        assert.equal(uploadedByObject.get(object.objectId), sourceBytes(object).length);
        if (!scenario.startsWith("mixed-")) assert.equal(uploaded, payload.length);
        assert.equal(action.deferEnqueue, true);
        break;
      }
      case "enqueue": {
        if (scenario.startsWith("requeue-refused")) {
          responseStatus = 409;
          result = { state: "refused_or_unknown", failurePhase: "fallback_begin" };
          if (scenario === "requeue-refused-recovery") result.recoveryFailurePhase = "read_lease";
          break;
        }
        const started = Date.now() - 20, finished = Date.now();
        receipt = { attempt: { nonce: "dd".repeat(32), startedAtMillis: String(started),
          providerBefore: { isolateId: "driver-isolate", dispatches: 10, metadataAdmissionsDuringBulk: 0 } },
          finishedAtMillis: String(finished), messageId: "message", queueName: "driver-bulk",
          providerAfter: { isolateId: "driver-isolate", dispatches: 11, peakActive: 1, metadataAdmissionsDuringBulk: 0 },
          objects: { aggregateActive: 1, bulkActive: 1, metadataActive: 0 }, verificationReplayed: scenario === "replay",
          proof: { sha256: digest(payload), byte_size: String(payload.length) } };
        break;
      }
      case "status": {
        const objects = original.objects.map(object => ({ objectId: object.objectId,
          closed: true, verified: Boolean(receipt) && !scenario.startsWith("timeout-"), attemptCount: receipt ? 1 : 0 }));
        result = { original, objects: scenario === "missing-status" ? []
          : scenario === "duplicate-status" ? [...objects, ...objects] : objects };
        break;
      }
      case "inspect":
        assert.ok(original.objects.some(object => object.objectId === action.objectId));
        result = { original: scenario === "timeout-foreign-original" ? { ...original, runId: "00".repeat(32) } : original,
        objectId: action.objectId, closed: { settlementMillis: "5" },
        attempts: action.afterAttempt === 0 ? [{ attempt: { nonce: "ee".repeat(32) }, receipt: null }]
          : receipt ? [{ attempt: receipt.attempt, receipt }] : [],
        nextAttempt: scenario === "timeout-stale-cursor" ? 0
          : scenario === "timeout-page-bound" ? action.afterAttempt + 1 : action.afterAttempt === 0 ? 1 : null }; break;
      default: throw new Error("Unexpected control action.");
    }
    const reply = Buffer.from(JSON.stringify(sorted({ version: 1, requestSha256: digest(bytes), nonce: control.nonce,
      sourceDigest: control.sourceDigest, scriptVersion: scenario === "wrong-runtime" ? "different-script" : control.scriptVersion,
      observedAtMillis: String(Date.now()), result })));
    response.writeHead(responseStatus, { "content-type": "application/json",
      "x-aos-direct-qualification-signature": mac("aos.direct-upload.qualification-reply.v1\0", reply) });
    response.end(reply);
  } catch (error) { response.writeHead(500); response.end(); }
});
await new Promise(done => server.listen(0, "127.0.0.1", done));
origin = `https://127.0.0.1:${server.address().port}`;
const identityFile = join(root, "identity.json"), manifestFile = join(root, "manifest.json");
await writeFile(identityFile, JSON.stringify({ sourceDigest: "ab".repeat(32), scriptVersion: "script-1", publicOrigin: origin }), { mode: 0o600 });
await writeFile(manifestFile, JSON.stringify({ provider: { kind: "managed" }, objects: [{ file: payloadFile, metadata: false }] }), { mode: 0o600 });
async function run(name, mode, phase = "run") {
  scenario = mode; calls.length = 0; partOrder.length = 0; uploaded = 0; receipt = null;
  uploadedByObject.clear(); uploadRoutes.clear();
  const invocation = join(root, name); await mkdir(invocation, { mode: 0o700 });
  const output = mode.startsWith("mixed-") ? join(invocation, "evidence") : invocation;
  if (output !== invocation) await mkdir(output, { mode: 0o700 });
  if (mode.startsWith("mixed-")) {
    mixedEntries.clear(); mixedFixture.gets.clear();
    mixedDispatches = 0; mixedBulkActive = 0; mixedMetadataAdmissions = 0; mixedPeakActive = 0;
    await writeFile(manifestFile, JSON.stringify({ provider: { kind: "managed" }, objects: [
      { file: payloadFile, metadata: false },
      ...(mode === "mixed-saturation" ? [{ file: secondPayloadFile, metadata: false }] : []),
      { file: metadataFile, metadata: true }] }), { mode: 0o600 });
  }
  child = spawn(process.execPath, [mode === "mixed-baseline" ? baselineDriver : driver, "--origin", origin, "--control-key-file", keyFile,
    "--identity-file", identityFile, "--manifest-file", manifestFile, "--output-dir", output,
    "--wait-seconds", mode.startsWith("mixed-") ? "15" : "0",
    ...(["mixed-barrier", "mixed-saturation"].includes(mode) ? ["--mixed-admission-file", resolve(output, "..", "mixed-admission-release.json")] : []), ...(phase === "clock" ? ["--phase", "clock", "--run-id", "ef".repeat(32),
      "--clock-uncertainty-seconds", "1"] : phase === "requeue"
      ? ["--phase", "requeue", "--run-id", original.runId] : [])],
    { env: { ...process.env, NODE_EXTRA_CA_CERTS: cert }, stdio: ["ignore", "pipe", "pipe"] });
  let pumpError = null;
  const pumping = ["mixed-barrier", "mixed-saturation"].includes(mode) ? pumpMixed(output).catch(error => {
    pumpError = error; child.kill("SIGTERM");
  }) : Promise.resolve();
  let logs = ""; child.stdout.on("data", bytes => { logs += bytes; }); child.stderr.on("data", bytes => { logs += bytes; });
  const exit = await new Promise((done, reject) => { child.once("error", reject); child.once("exit", done); });
  await pumping;
  if (pumpError) throw pumpError;
  await writeFile(join(root, `${name}.log`), logs, { mode: 0o600 });
  return { output, exit, logs };
}
try {
  const sourceClock = await run("source-clock", "positive", "clock"); assert.equal(sourceClock.exit, 0);
  assert.deepEqual(calls, ["clock"]); assert.equal(uploaded, 0);
  const sourceIdentity = JSON.parse(await readFile(join(sourceClock.output, "source-identity.json")));
  assert.deepEqual(sourceIdentity, { sourceDigest: "ab".repeat(32), scriptVersion: "script-1" });
  const sourceObservation = JSON.parse(await readFile(join(sourceClock.output, "source-clock-observation.json")));
  assert.equal(sourceObservation.scope, "authenticated_source_clock_only");
  const clockRequest = await readFile(join(sourceClock.output, "00001-clock-request.json"));
  assert.equal(JSON.parse(clockRequest).action.kind, "clock");
  assert.equal((await readdir(sourceClock.output)).includes("original.json"), false);
  const wrongClock = await run("source-clock-wrong-runtime", "wrong-runtime", "clock");
  assert.notEqual(wrongClock.exit, 0); assert.deepEqual(calls, ["clock"]);
  assert.equal((await readdir(wrongClock.output)).includes("source-identity.json"), false);
  const wrongUncertainty = await run("source-clock-wrong-uncertainty", "clock-wrong-uncertainty", "clock");
  assert.notEqual(wrongUncertainty.exit, 0); assert.deepEqual(calls, ["clock"]);
  assert.equal((await readdir(wrongUncertainty.output)).includes("source-identity.json"), false);
  const positive = await run("positive", "positive"); assert.equal(positive.exit, 0);
  assert.ok(calls.includes("expired_mutation"));
  const evidenceNames = await readdir(positive.output);
  assert.ok(evidenceNames.includes("00010-expired-mutation-pending.json"));
  assert.ok(evidenceNames.includes("00010-expired-mutation-capture.json"));
  assert.ok(evidenceNames.every(name => /^[a-z0-9][a-z0-9-]{0,127}\.json$/.test(name)));

  // Execute the existing collector's actual emitted guest programs against the
  // real driver output. Only the guest transport is local to this regression.
  const retention = join(root, "retention"); await mkdir(retention, { mode: 0o700 });
  const collectorProgram = `
import importlib.util, json, subprocess, sys, textwrap
from pathlib import Path

spec = importlib.util.spec_from_file_location('qualification_collector', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def local_guest_command(_worker, command, timeout=60):
    command = command.strip()
    header, remainder = command.split('\\n', 1)
    marker = header.split("<<'", 1)[1].split("'", 1)[0]
    program = remainder.rsplit('\\n' + marker, 1)[0]
    result = subprocess.run([sys.executable, '-B', '-c', program],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return result.stdout.decode()

def local_guest_python(_worker, python, body, selected, timeout=60):
    program = "import json\\nselected = json.loads(input())\\n" + textwrap.dedent(body)
    result = subprocess.run([python, '-B', '-c', program],
        input=json.dumps(selected).encode(), check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return result.stdout.decode()

module.private_guest_command = local_guest_command
module.direct_guest_python = local_guest_python
original = json.loads((Path(sys.argv[2]) / 'original.json').read_text())
retained = module.retain_direct_qualification_files(None, sys.executable, sys.argv[2], original['runId'])
assert any(item['name'] == '00010-expired-mutation-pending.json' for item in retained['files'])
assert retained['driverManifestPresent'] is True
pending = Path(sys.argv[2]) / '00010-expired-mutation-pending.json'
pending.rename(pending.with_name('00010-expired_mutation-pending.json'))
try:
    module.retain_direct_qualification_files(None, sys.executable, sys.argv[2], original['runId'],
        host_directory=retained['directory'])
except subprocess.CalledProcessError as error:
    assert b'qualification evidence filename refused' in error.stderr
else:
    raise AssertionError('collector accepted an underscore evidence filename')
finally:
    pending.with_name('00010-expired_mutation-pending.json').rename(pending)
print('PASS actual driver evidence accepted; old underscore filename refused by existing collector')
`;
  const collected = spawnSync(python, ["-B", "-c", collectorProgram, collector, positive.output],
    { cwd: retention, encoding: "utf8" });
  assert.equal(collected.status, 0, collected.stderr);
  assert.equal(uploaded, payload.length); assert.notEqual(partOrder[0], 1);
  const runtime = JSON.parse(await readFile(join(positive.output, "runtime-raw.json")));
  assert.equal(runtime.observations.samples[0].byteSize, String(payload.length));
  assert.equal(runtime.observations.samples[0].sha256, digest(payload));
  assert.equal(calls.filter(kind => kind === "inspect").length, 2);
  for (const name of await readdir(positive.output)) {
    const content = await readFile(join(positive.output, name), "utf8");
    assert.equal(content.includes(secret), false); assert.equal(content.includes("/part/"), false);
  }
  for (const mode of ["requeue-refused", "requeue-refused-recovery"]) {
    const selectedOriginal = structuredClone(original);
    const refused = await run(mode, mode, "requeue");
    assert.notEqual(refused.exit, 0);
    assert.deepEqual(calls, ["status", "enqueue"]);
    assert.equal(uploaded, 0);
    const capture = JSON.parse(await readFile(join(refused.output, "00002-enqueue-capture.json")));
    assert.deepEqual(capture.result, mode === "requeue-refused-recovery"
      ? { state: "refused_or_unknown", failurePhase: "fallback_begin", recoveryFailurePhase: "read_lease" }
      : { state: "refused_or_unknown", failurePhase: "fallback_begin" });
    const authentication = JSON.parse(await readFile(join(refused.output, "00002-enqueue-authentication.json")));
    assert.equal(authentication.status, 409);
    assert.equal(authentication.responseSha256,
      digest(await readFile(join(refused.output, "00002-enqueue-capture.json"))));
    assert.deepEqual(JSON.parse(await readFile(join(refused.output, "original.json"))), selectedOriginal);
    const unknown = JSON.parse(await readFile(join(refused.output, "00002-enqueue-unknown.json")));
    assert.equal(unknown.state, "unknown");
    assert.equal(unknown.cause, "dispatch_or_reply_unknown");
    const incomplete = JSON.parse(await readFile(join(refused.output, "incomplete-run-outcome.json")));
    assert.equal(incomplete.unknownEffects, "retained_without_replay");
    assert.equal((await readdir(refused.output)).includes("runtime-raw.json"), false);
    assert.equal(refused.logs.includes(secret), false);
    assert.equal(refused.logs.includes("read_lease"), false);
  }
  const replay = await run("terminal-replay", "replay"); assert.equal(replay.exit, 0);
  const replayRuntime = JSON.parse(await readFile(join(replay.output, "runtime-raw.json")));
  assert.equal(replayRuntime.observations.samples.length, 0);

  for (const mode of ["timeout-positive", "timeout-inspect-failure", "timeout-foreign-original",
    "timeout-stale-cursor", "timeout-page-bound"]) {
    const timeout = await run(mode, mode);
    assert.notEqual(timeout.exit, 0);
    assert.match(timeout.logs, /Queue observation deadline elapsed; closed originals remain recoverable\./);
    assert.equal(uploaded, payload.length);
    const afterEnqueue = calls.slice(calls.indexOf("enqueue") + 1);
    const inspectCount = mode === "timeout-page-bound" ? 32
      : mode === "timeout-positive" || mode === "timeout-inspect-failure" ? 2 : 1;
    assert.deepEqual(afterEnqueue, ["status", ...Array(inspectCount).fill("inspect")]);
    for (const kind of ["start", "begin", "grant", "report", "close", "enqueue"]) {
      assert.equal(calls.filter(call => call === kind).length, 1);
    }

    const diagnosis = JSON.parse(await readFile(join(timeout.output, "queue-deadline-inspection.json")));
    const savedOriginal = JSON.parse(await readFile(join(timeout.output, "original.json")));
    assert.deepEqual(savedOriginal, original);
    assert.deepEqual(diagnosis.objectIds, original.objects.map(object => object.objectId));
    assert.equal(diagnosis.state, "incomplete");
    assert.equal(diagnosis.inspection, mode === "timeout-positive" ? "complete" : "unknown");
    assert.equal(diagnosis.unknownEffects, "retained_without_replay");
    const names = await readdir(timeout.output);
    assert.equal(names.includes("runtime-raw.json"), false);
    assert.equal(JSON.parse(await readFile(join(timeout.output, "incomplete-run-outcome.json"))).state, "incomplete");
    const captures = [];
    for (const name of names.filter(name => name.endsWith("-inspect-capture.json"))) {
      captures.push(JSON.parse(await readFile(join(timeout.output, name))));
      assert.ok(names.includes(name.replace("-capture.json", "-authentication.json")));
    }
    assert.equal(captures.length, mode === "timeout-inspect-failure" ? 1 : inspectCount);
    if (mode === "timeout-positive") assert.deepEqual(captures[1].result.attempts[0].receipt, receipt);
    if (mode === "timeout-inspect-failure") assert.ok(names.some(name => name.endsWith("-inspect-unknown.json")));
    for (const name of names) {
      const content = await readFile(join(timeout.output, name), "utf8");
      assert.equal(content.includes(secret), false);
      assert.equal(content.includes("/part/"), false);
    }
  }

  for (const mode of ["missing-status", "duplicate-status"]) {
    const invalid = await run(mode, mode);
    assert.notEqual(invalid.exit, 0);
    assert.match(invalid.logs, /Queue status differs from selected original object coverage\./);
    assert.deepEqual(calls.slice(calls.indexOf("enqueue") + 1), ["status"]);
    assert.equal((await readdir(invalid.output)).includes("runtime-raw.json"), false);
    assert.equal(JSON.parse(await readFile(join(invalid.output, "incomplete-run-outcome.json"))).state, "incomplete");
  }

  const wrongRuntime = await run("wrong-runtime", "wrong-runtime"); assert.notEqual(wrongRuntime.exit, 0);
  assert.equal(calls.includes("begin"), false); assert.equal(calls.includes("grant"), false);
  const unknown = await run("unknown", "unknown"); assert.notEqual(unknown.exit, 0);
  assert.equal(calls.filter(kind => kind === "begin").length, 1);
  assert.equal(calls.includes("grant"), false);
  assert.ok((await readdir(unknown.output)).some(name => name.endsWith("-unknown.json")));
  const cancelled = await run("cancelled", "cancel"); assert.notEqual(cancelled.exit, 0);
  assert.equal(calls.includes("begin"), false); assert.equal(calls.includes("grant"), false);
  // Both runs use the actual producer and real loopback body streams.
  // The historical producer is an explicit immutable source input, never a
  // retagged qualification artifact. No rows are manually constructed.
  assert.ok(baselineDriver?.startsWith("/nix/store/"));
  const backend = createHttpServer((request, response) => {
    assert.ok(["/bulk-payload", "/bulk-second-payload", "/metadata-payload"].includes(request.url));
    assert.equal(request.method, "GET");
    assert.equal(request.headers["if-match"], '"actual-etag"');
    mixedFixture.gets.set(request.url, (mixedFixture.gets.get(request.url) ?? 0) + 1);
    const bytes = request.url === "/metadata-payload" ? metadataPayload
      : request.url === "/bulk-second-payload" ? secondPayload : payload;
    response.writeHead(200, { etag: '"actual-etag"', "content-length": String(bytes.length) });
    if (request.url === "/bulk-second-payload") {
      // Keep the second real stream active until metadata uses its reserved slot.
      mixedFixture.secondBulkResponse = response;
      return;
    }
    response.end(bytes);
    if (request.url === "/metadata-payload" && mixedFixture.secondBulkResponse) {
      mixedFixture.secondBulkResponse.end(secondPayload);
      mixedFixture.secondBulkResponse = null;
    }
  });
  await new Promise(done => backend.listen(0, "127.0.0.1", done));
  const holdRoot = join(root, "mixed-holder"); await mkdir(holdRoot, { mode: 0o700 });
  const listener = await createResponseHold(holdRoot, { listen: 0, upstream: backend.address().port });
  mixedFixture = { listener, listenerPort: Number(listener.ready.listenAddress.split(":")[1]), tasks: [], gets: new Map() };
  try {
    const before = await run("mixed-baseline", "mixed-baseline");
    assert.equal(before.exit, 0);
    assert.equal(JSON.parse(await readFile(join(before.output, "mixed-load-raw.json"))).observations.samples.length, 0);
    await Promise.all(mixedFixture.tasks);
    assert.deepEqual(Object.fromEntries(mixedFixture.gets), { "/metadata-payload": 1, "/bulk-payload": 1 });
    mixedFixture.tasks = [];
    const after = await run("mixed-barrier", "mixed-barrier");
    assert.equal(after.exit, 0);
    await Promise.all(mixedFixture.tasks);
    assert.deepEqual(Object.fromEntries(mixedFixture.gets), { "/bulk-payload": 1, "/metadata-payload": 1 });
    const actual = JSON.parse(await readFile(join(after.output, "mixed-load-raw.json")));
    assert.equal(actual.observations.samples.length, 1);
    assert.ok(Number(actual.observations.samples[0].bulkActive) > 0);
    assert.ok(Number(actual.observations.samples[0].metadataAdmissionsAfter) > Number(actual.observations.samples[0].metadataAdmissionsBefore));
    mixedFixture.tasks = [];
    const saturated = await run("mixed-saturation", "mixed-saturation");
    assert.equal(saturated.exit, 0, saturated.logs);
    await Promise.all(mixedFixture.tasks);
    assert.deepEqual(Object.fromEntries(mixedFixture.gets), {
      "/bulk-payload": 1, "/bulk-second-payload": 1, "/metadata-payload": 1 });
    const saturation = JSON.parse(await readFile(join(saturated.output, "mixed-load-raw.json")));
    assert.equal(saturation.observations.samples.length, 1);
    assert.equal(saturation.observations.samples[0].bulkActive, "2");
  } finally {
    await listener.close(); backend.closeAllConnections(); await new Promise(done => backend.close(done));
  }
  await chmod(keyFile, 0o644);
  const insecure = await run("insecure-key", "positive"); assert.notEqual(insecure.exit, 0); assert.equal(calls.length, 0);
  process.stdout.write(`PASS: actual HTTPS driver/stream/authentication/unknown/cancellation/private-file tests; retained ${root}\n`);
} finally { server.closeAllConnections(); await new Promise(done => server.close(done)); }
