// Exercises the operator driver against an authenticated HTTPS control peer.
// This is a protocol/stream/cancellation test, not provider qualification.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { createServer } from "node:https";
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
let scenario, child, origin, original, uploaded, receipt;
const calls = [], partOrder = [];
const server = createServer({ cert: await readFile(cert), key: await readFile(privateKey) }, async (request, response) => {
  try {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const bytes = Buffer.concat(chunks);
    if (request.url.startsWith("/part/")) {
      const number = Number(request.url.split("/").at(-1));
      assert.equal(request.headers["content-length"], String(bytes.length));
      assert.equal(request.headers["content-md5"], createHash("md5").update(bytes).digest("base64"));
      const offset = (number - 1) * 8 * 1024 * 1024;
      assert.equal(digest(bytes), digest(payload.subarray(offset, offset + bytes.length)));
      if (number === 1) await new Promise(done => setTimeout(done, 50));
      uploaded += bytes.length; partOrder.push(number);
      response.writeHead(200, { etag: `"part-${number}"` }); response.end(); return;
    }
    assert.equal(request.headers["x-aos-direct-qualification-signature"], mac("aos.direct-upload.qualification-request.v1\0", bytes));
    const control = JSON.parse(bytes), action = control.action; calls.push(action.kind);
    if (scenario === "unknown" && action.kind === "begin") { request.socket.destroy(); return; }
    if (scenario === "cancel" && action.kind === "clock") { child.kill("SIGTERM"); await new Promise(done => setTimeout(done, 30)); }
    let result = {};
    switch (action.kind) {
      case "start":
        original = { version: 1, runId: control.runId, sourceDigest: control.sourceDigest, scriptVersion: control.scriptVersion,
          deploymentId: "driver-test", publicOrigin: origin, executionKind: "hosted", objects: action.objects,
          bulkQueueName: "driver-bulk", metadataQueueName: "driver-metadata", material: { profile: { checksumAlgorithm: "md5" } } };
        result = { original }; break;
      case "clock": result = { kind: "clock", observedAtMillis: String(Date.now()),
        uncertaintySeconds: scenario === "clock-wrong-uncertainty" ? "2" : "1", nonce: control.nonce }; break;
      case "expired_mutation": result = { observedAt: String(Math.floor(Date.now() / 1000)),
        providerBefore: { isolateId: "driver-isolate", dispatches: 0 }, providerAfter: { isolateId: "driver-isolate", dispatches: 0 } }; break;
      case "begin": break;
      case "grant": result = { grants: action.parts.map(part => ({ sessionId: "session", logicalFingerprint: "aa".repeat(32),
        placement,
        grantId: "cc".repeat(32), grantRevision: "1", part, method: "PUT", url: `${origin}/part/${part.partNumber}`,
        requiredHeaders: [{ name: "content-md5", value: part.checksum.value }] })) }; break;
      case "report": {
        assert.equal(action.reports.length, 3);
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
      case "close": assert.equal(uploaded, payload.length); assert.equal(action.deferEnqueue, true); break;
      case "enqueue": {
        const started = Date.now() - 20, finished = Date.now();
        receipt = { attempt: { nonce: "dd".repeat(32), startedAtMillis: String(started),
          providerBefore: { isolateId: "driver-isolate", dispatches: 10, metadataAdmissionsDuringBulk: 0 } },
          finishedAtMillis: String(finished), messageId: "message", queueName: "driver-bulk",
          providerAfter: { isolateId: "driver-isolate", dispatches: 11, peakActive: 1, metadataAdmissionsDuringBulk: 0 },
          objects: { aggregateActive: 1, bulkActive: 1, metadataActive: 0 }, verificationReplayed: scenario === "replay",
          proof: { sha256: digest(payload), byte_size: String(payload.length) } };
        break;
      }
      case "status": result = { original, objects: original.objects.map(object => ({ objectId: object.objectId,
        closed: true, verified: Boolean(receipt), attemptCount: receipt ? 1 : 0 })) }; break;
      case "inspect": result = { original, objectId: action.objectId, closed: { settlementMillis: "5" },
        attempts: action.afterAttempt === 0 ? [{ attempt: { nonce: "ee".repeat(32) }, receipt: null }]
          : receipt ? [{ attempt: receipt.attempt, receipt }] : [],
        nextAttempt: action.afterAttempt === 0 ? 1 : null }; break;
      default: throw new Error("Unexpected control action.");
    }
    const reply = Buffer.from(JSON.stringify(sorted({ version: 1, requestSha256: digest(bytes), nonce: control.nonce,
      sourceDigest: control.sourceDigest, scriptVersion: scenario === "wrong-runtime" ? "different-script" : control.scriptVersion,
      observedAtMillis: String(Date.now()), result })));
    response.writeHead(200, { "content-type": "application/json",
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
  const output = join(root, name); await mkdir(output, { mode: 0o700 });
  child = spawn(process.execPath, [driver, "--origin", origin, "--control-key-file", keyFile,
    "--identity-file", identityFile, "--manifest-file", manifestFile, "--output-dir", output,
    "--wait-seconds", "0", ...(phase === "clock" ? ["--phase", "clock", "--run-id", "ef".repeat(32),
      "--clock-uncertainty-seconds", "1"] : [])], { env: { ...process.env, NODE_EXTRA_CA_CERTS: cert }, stdio: ["ignore", "pipe", "pipe"] });
  let logs = ""; child.stdout.on("data", bytes => { logs += bytes; }); child.stderr.on("data", bytes => { logs += bytes; });
  const exit = await new Promise((done, reject) => { child.once("error", reject); child.once("exit", done); });
  await writeFile(join(root, `${name}.log`), logs, { mode: 0o600 });
  return { output, exit };
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
import importlib.util, json, subprocess, sys
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

module.private_guest_command = local_guest_command
original = json.loads((Path(sys.argv[2]) / 'original.json').read_text())
retained = module.retain_direct_qualification_files(None, sys.executable, sys.argv[2], original['runId'])
assert any(item['name'] == '00010-expired-mutation-pending.json' for item in retained['files'])
assert retained['driverManifestPresent'] is True
pending = Path(sys.argv[2]) / '00010-expired-mutation-pending.json'
pending.rename(pending.with_name('00010-expired_mutation-pending.json'))
try:
    module.retain_direct_qualification_files(None, sys.executable, sys.argv[2], original['runId'])
except subprocess.CalledProcessError as error:
    assert b'qualification evidence inventory exceeds bounds' in error.stderr
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
  const replay = await run("terminal-replay", "replay"); assert.equal(replay.exit, 0);
  const replayRuntime = JSON.parse(await readFile(join(replay.output, "runtime-raw.json")));
  assert.equal(replayRuntime.observations.samples.length, 0);
  const wrongRuntime = await run("wrong-runtime", "wrong-runtime"); assert.notEqual(wrongRuntime.exit, 0);
  assert.equal(calls.includes("begin"), false); assert.equal(calls.includes("grant"), false);
  const unknown = await run("unknown", "unknown"); assert.notEqual(unknown.exit, 0);
  assert.equal(calls.filter(kind => kind === "begin").length, 1);
  assert.equal(calls.includes("grant"), false);
  assert.ok((await readdir(unknown.output)).some(name => name.endsWith("-unknown.json")));
  const cancelled = await run("cancelled", "cancel"); assert.notEqual(cancelled.exit, 0);
  assert.equal(calls.includes("begin"), false); assert.equal(calls.includes("grant"), false);
  await chmod(keyFile, 0o644);
  const insecure = await run("insecure-key", "positive"); assert.notEqual(insecure.exit, 0); assert.equal(calls.length, 0);
  process.stdout.write(`PASS: actual HTTPS driver/stream/authentication/unknown/cancellation/private-file tests; retained ${root}\n`);
} finally { server.closeAllConnections(); await new Promise(done => server.close(done)); }
