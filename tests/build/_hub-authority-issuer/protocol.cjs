// Runs the ordinary production Worker under local, test-only storage faults.
// Synthetic credentials and resource identities never qualify hosted dispatch.

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const { cpSync, mkdtempSync, readFileSync, writeFileSync } = require("node:fs");
const path = require("node:path");
const [toolingRoot, artifact, faultFixture, scratch, output] = process.argv.slice(2);
assert.equal(process.argv.length, 7, "Pass tooling, production artifact, fault fixture, scratch and output");
const load = createRequire(path.join(toolingRoot, "lib/node_modules/wrangler/node_modules/protocol.cjs"));
const { Miniflare } = load("miniflare");
const directory = mkdtempSync(path.join(scratch, "issuer-"));
cpSync(artifact, directory, { recursive: true });
cpSync(faultFixture, path.join(directory, "fixture.mjs"));
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const pubKey = "fixture-native-publisher-private-key-with-at-least-thirty-two-bytes";
const renewKey = "fixture-executor-renewal-private-key-distinct-from-publisher";
const seed = "7b".repeat(32);
const issuerKeyId = "independently-pinned-fixture-key";
const privateKey = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed, "hex")]),
  format: "der",
  type: "pkcs8"
});
const verifier = crypto.createPublicKey(privateKey);
const profile = {
  profile_id: "fixture-only-not-hosted-qualified",
  review_digest: "9".repeat(64),
  maximum_lifetime: "30",
  maximum_clock_uncertainty: "1"
};
const baseBindings = {
  HUB_RUNTIME_ROLE: "authority_issuer",
  HUB_AUTHORITY_CLOCK_ACCEPTANCE: "operator_qualified",
  HUB_AUTHORITY_TIMING_PROFILE: JSON.stringify(profile),
  HUB_AUTHORITY_CLOCK_UNCERTAINTY_SECS: "1",
  HUB_AUTHORITY_ISSUER_RESOURCE_ID: "permanent-fixture-issuer-resource",
  HUB_AUTHORITY_ISSUER_RUNTIME_ID: "fixture-dedicated-issuer",
  HUB_EXTERNAL_GUARD_NAMESPACE_ID: "fixture-object-guard-namespace",
  HUB_EXTERNAL_STORAGE_EXECUTOR_ID: "fixture-executor",
  HUB_AUTHORITY_ISSUER_KEY_ID: issuerKeyId,
  HUB_AUTHORITY_ISSUER_SEED: seed,
  HUB_AUTHORITY_PUBLISHER_KEY: pubKey,
  HUB_AUTHORITY_RENEWAL_KEY: renewKey
};
const common = {
  modules: true,
  modulesRoot: directory,
  modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
  compatibilityDate: "2024-09-23",
  cf: false
};
const options = {
  resourcePersistencePath: path.join(directory, "state"),
  workers: [
    {
      ...common,
      name: "authority-issuer",
      scriptPath: path.join(directory, "fixture.mjs"),
      bindings: { ...baseBindings },
      durableObjects: {
        HYBRID_AUTHORITY_STATE: { className: "HybridAuthorityState", useSQLite: true },
        HYBRID_AUTHORITY_ISSUERS: { className: "HybridAuthorityIssuer", useSQLite: true }
      }
    },
    {
      ...common,
      name: "executor",
      scriptPath: path.join(directory, "shim.mjs"),
      bindings: { HUB_RUNTIME_ROLE: "hub_executor" },
      serviceBindings: { HUB_AUTHORITY_ISSUER: "authority-issuer" }
    }
  ]
};
let runtime, issuers, registry, edge;
const verdicts = [];
const now = () => Math.floor(Date.now() / 1e3);

async function boot() {
  runtime = new Miniflare(options);
  await runtime.ready;
  issuers = await runtime.getDurableObjectNamespace("HYBRID_AUTHORITY_ISSUERS", "authority-issuer");
  registry = await runtime.getDurableObjectNamespace("HYBRID_AUTHORITY_STATE", "authority-issuer");
  options.workers[0].bindings.HUB_AUTHORITY_REGISTRY_OBJECT_ID = registry.idFromName("physical-authority-ledger-v1").toString();
  options.workers[0].bindings.HUB_AUTHORITY_ISSUER_NAMESPACE_PROBE_ID = issuers.idFromName("issuer-namespace-probe-v1").toString();
  await applyOptions();
}

async function applyOptions() {
  await runtime.setOptions(options);
  issuers = await runtime.getDurableObjectNamespace("HYBRID_AUTHORITY_ISSUERS", "authority-issuer");
  registry = await runtime.getDurableObjectNamespace("HYBRID_AUTHORITY_STATE", "authority-issuer");
  edge = await runtime.getWorker("executor");
}

async function restart() {
  console.log("STEP runtime dispose");
  await runtime.dispose();
  console.log("STEP runtime reboot");
  await boot();
}
const installation = (p) => ({
  format_version: 1,
  authority: p.authority,
  issuer_resource_id: baseBindings.HUB_AUTHORITY_ISSUER_RESOURCE_ID,
  runtime_identity: baseBindings.HUB_AUTHORITY_ISSUER_RUNTIME_ID,
  executor_identity: baseBindings.HUB_EXTERNAL_STORAGE_EXECUTOR_ID
});

function publication(id = crypto.randomUUID()) {
  const authority = {
    authority_id: id,
    guard_namespace_id: baseBindings.HUB_EXTERNAL_GUARD_NAMESPACE_ID,
    physical_resource_evidence_digest: sha(`physical-${id}`),
    qualification_digest: sha(`qualification-${id}`),
    qualified_managed_prefix: "managed"
  };
  const alias = {
    alias_id: `${id}-a000`,
    authority_id: id,
    spec: { host: { kind: "dns", value: "objects.example.invalid" }, port: 443, bucket: `fixture-${id}` },
    equivalence_evidence_digest: sha(`alias-${id}`)
  };
  const association = {
    association_id: `${id}-c000`,
    authority_id: id,
    alias_id: alias.alias_id,
    binding_id: 1,
    binding_stable_id: `${id}-binding`,
    binding_resource_version: 1,
    binding_write_revision: 1,
    binding_prefix: `managed/${id}`
  };
  const credentials = ["delete", "list", "read", "write"].map((purpose) => ({
    association_id: association.association_id,
    purpose,
    generation: 1,
    secret_version_ref: `secret://fixture/${id}/${purpose}`,
    credential_fingerprint: sha(`${id}-${purpose}`)
  }));
  const attestation = {
    attestation_id: `${id}-attest`,
    authority_id: id,
    managed_prefix: "managed",
    qualification_digest: authority.qualification_digest,
    provider_policy_evidence_digest: sha(`exclusive-${id}`),
    executor_identity: baseBindings.HUB_EXTERNAL_STORAGE_EXECUTOR_ID,
    credentials,
    valid_until: now() + 3600
  };
  const admission = {
    authority_id: id,
    expected_generation: 0,
    expected_digest: null,
    guard_namespace_id: authority.guard_namespace_id,
    state: "admitted",
    attestation_id: attestation.attestation_id,
    association_ids: [association.association_id]
  };
  return {
    authority,
    aliases: [alias],
    associations: [association],
    attestation,
    admission,
    generation: 1,
    digest: sha(JSON.stringify(admission))
  };
}

function denied(previous, state = "blocked") {
  const p = structuredClone(previous);
  p.aliases = [];
  p.associations = [];
  p.attestation = null;
  p.admission = {
    ...p.admission,
    expected_generation: previous.generation,
    expected_digest: previous.digest,
    state,
    attestation_id: null,
    association_ids: []
  };
  p.generation = previous.generation + 1;
  p.digest = sha(JSON.stringify(p.admission));
  return p;
}
const remote = (p) => ({
  authority_id: p.authority.authority_id,
  guard_namespace_id: p.authority.guard_namespace_id,
  generation: p.generation,
  digest: p.digest
});

function cohort(p) {
  const association = p.associations[0], credential = p.attestation.credentials.find((c) => c.association_id === association.association_id && c.purpose === "read");
  return {
    authority: p.authority,
    executor_identity: baseBindings.HUB_EXTERNAL_STORAGE_EXECUTOR_ID,
    admission_generation: String(p.generation),
    admission_digest: p.digest,
    publication_digest: sha(JSON.stringify(p)),
    alias: p.aliases.find((a) => a.alias_id === association.alias_id),
    association: {
      association_id: association.association_id,
      alias_id: association.alias_id,
      binding_id: String(association.binding_id),
      binding_stable_id: association.binding_stable_id,
      binding_resource_version: String(association.binding_resource_version),
      binding_write_revision: String(association.binding_write_revision),
      binding_prefix: association.binding_prefix
    },
    credential: {
      association_id: credential.association_id,
      purpose: "read",
      generation: String(credential.generation),
      secret_version_ref: credential.secret_version_ref,
      credential_fingerprint: credential.credential_fingerprint
    },
    attestation_id: p.attestation.attestation_id,
    attestation_prefix: p.attestation.managed_prefix,
    attestation_valid_until: String(p.attestation.valid_until),
    admitted_prefix: association.binding_prefix,
    allowed_effects: ["head"]
  };
}
const install = (p) => ({ kind: "install", input: p });
const issue = (p) => ({ kind: "issue", input: { cohort: cohort(p), requested_not_after: String(now() + 25) } });

function request(p, operation, lifetime = 30) {
  const time = now();
  return {
    protocol_version: 1,
    installation: installation(p),
    nonce: crypto.randomBytes(32).toString("hex"),
    issued_at: String(time),
    expires_at: String(time + lifetime),
    operation
  };
}

function verify(reply, r) {
  assert.equal(reply.payload.nonce, r.nonce);
  assert.equal(reply.payload.request_digest, sha(JSON.stringify(r)));
  const domain = r.operation.kind === "deny" ? "aos.external-authority-issuer-denial.v1\0" : "aos.external-authority-issuer-reply.v1\0";
  assert.equal(crypto.verify(null, Buffer.concat([Buffer.from(domain), Buffer.from(JSON.stringify(reply.payload))]), verifier, Buffer.from(reply.signature, "hex")), true);
  if (reply.payload.lease) {
    const token = JSON.parse(reply.payload.lease);
    assert.equal(crypto.verify(null, Buffer.concat([Buffer.from("aos.external-authority-epoch-lease.v1\0"), Buffer.from(JSON.stringify(token.payload))]), verifier, Buffer.from(token.signature, "hex")), true);
  }
}

async function invoke(p, operation, { key, throughEdge = false, lifetime = 30 } = {}) {
  console.log("STEP request " + operation.kind);
  const r = request(p, operation, lifetime), body = JSON.stringify(r);
  key ??= ["install", "publish", "deny"].includes(operation.kind) ? pubKey : renewKey;
  const signature = crypto.createHmac("sha256", key).update("aos-storage-work-v1\0").update("aos.external-authority-issuer-request.v1\0").update(body).digest("hex");
  const init = {
    method: "POST",
    headers: { "content-type": "application/json", "x-aos-storage-work-signature": signature },
    body
  };
  const response = throughEdge ? await edge.fetch("http://executor/_aos/storage-authority/issuer/v1", init) : await runtime.dispatchFetch("http://issuer/_aos/storage-authority/issuer/v1", init);
  const text = await response.text();
  console.log("STEP response " + operation.kind + " " + response.status);
  if (response.status !== 200) return { status: response.status, text };
  const reply = JSON.parse(text);
  verify(reply, r);
  return { status: 200, reply: reply.payload, bytes: Buffer.byteLength(text) };
}

async function ok(p, op, opts) {
  const result = await invoke(p, op, opts);
  assert.equal(result.status, 200, result.text);
  return result;
}

async function refused(p, op, opts) {
  const result = await invoke(p, op, opts);
  assert.ok(result.status >= 400, "unexpected live issuer success");
  return result;
}
const stub = (p) => issuers.get(issuers.idFromName(`authority-issuer-v1/${p.authority.authority_id}`));
const registryStub = () => registry.get(registry.idFromName("physical-authority-ledger-v1"));

async function fixture(target, route, body) {
  const response = await target.fetch(`http://fixture/fixture-${route}`, { method: "POST", body: JSON.stringify(body) });
  assert.equal(response.status, 200);
  return response.json().catch(() => null);
}
const read = (p, keys) => fixture(stub(p), "read", keys);
const write = (p, values) => fixture(stub(p), "write", values);
const count = async (p) => (await read(p, ["fixture:transactions"]))["fixture:transactions"] ?? 0;
const registryRead = (keys) => fixture(registryStub(), "read", keys);
const registryWrite = (values) => fixture(registryStub(), "write", values);
const registryCount = async () => (await registryRead(["fixture:transactions"]))["fixture:transactions"] ?? 0;
const record = (v) => JSON.stringify({ version: 1, value: v });

function pass(name) {
  verdicts.push(name);
  console.log("PASS " + name);
}

function largestPublication() {
  const p = publication();
  const id = p.authority.authority_id;
  const make = (fill) => {
    const q2 = structuredClone(p);
    q2.aliases = [];
    q2.associations = [];
    q2.attestation.credentials = [];
    q2.admission.association_ids = [];
    for (let i = 0; i < 256; i++) {
      const ix = String(i).padStart(3, "0"), aid = `${id}-a${ix}`, cid = `${id}-c${ix}`;
      q2.aliases.push({
        alias_id: aid,
        authority_id: id,
        spec: {
          host: { kind: "dns", value: "objects.example.invalid" },
          port: 443,
          bucket: `${id}-${ix}` + '"'.repeat(Math.min(fill, 215))
        },
        equivalence_evidence_digest: sha(`alias-${id}-${i}`)
      });
      q2.associations.push({
        association_id: cid,
        authority_id: id,
        alias_id: aid,
        binding_id: i + 1,
        binding_stable_id: `${id}-${ix}` + '"'.repeat(Math.min(fill, 215)),
        binding_resource_version: 1,
        binding_write_revision: 1,
        binding_prefix: `managed/${id}/${ix}` + '"'.repeat(Math.min(fill, 464))
      });
      q2.attestation.credentials.push({
        association_id: cid,
        purpose: "write",
        generation: 1,
        secret_version_ref: `secret://fixture/${id}/${ix}` + '"'.repeat(Math.min(fill, 197)),
        credential_fingerprint: sha(`${id}-${i}-read`)
      });
      q2.admission.association_ids.push(cid);
    }
    q2.digest = sha(JSON.stringify(q2.admission));
    return q2;
  };
  const base = '{"version":1,"deployment_id":"","guard_namespace_id":"","nonce":"","issued_at":9223372036854775807,"expires_at":9223372036854775807,"operation":{"kind":"publish","input":}}';
  const maximum = 768 * 1024 - (Buffer.byteLength(base) + 2 * 128 + 2 * 255 + 64);
  let lower = 0, upper = 464;
  while (lower < upper) {
    const mid = Math.ceil((lower + upper) / 2);
    if (Buffer.byteLength(JSON.stringify(make(mid))) <= maximum) lower = mid;
    else upper = mid - 1;
  }
  const q = make(lower);
  let remainder = maximum - Buffer.byteLength(JSON.stringify(q));
  for (const a of q.associations) {
    const addition = Math.min(Math.floor(remainder / 2), 512 - a.binding_prefix.length);
    a.binding_prefix += '"'.repeat(addition);
    remainder -= addition * 2;
    if (remainder === 1 && a.binding_prefix.length < 512) {
      a.binding_prefix += "x";
      remainder--;
    }
    if (remainder === 0) break;
  }
  assert.equal(Buffer.byteLength(JSON.stringify(q)), maximum, "fixture reaches exact public publication byte bound");
  return { p: q, maximum };
}

(async () => {
  try {
    await boot();
    const p = publication();
    await ok(p, install(p));
    const globalBefore = await registryCount();
    const token1 = await ok(p, issue(p), { throughEdge: true });
    assert.equal(token1.reply.current.journal.last_sequence, "1");
    assert.equal(await registryCount(), globalBefore);
    pass("dedicated issuer activated before real two-CAS issuance; ordinary edge forwards; no per-renew registry transaction");
    await refused(p, { kind: "publish", input: denied(p) }, { key: renewKey, throughEdge: true });
    await refused(p, issue(p), { key: pubKey });
    pass("executor renewal credential cannot publish control");
    const deadline = publication();
    await ok(deadline, install(deadline));
    const beforeDeadline = await count(deadline);
    await refused(deadline, { kind: "current" }, { lifetime: 1 });
    assert.equal(await count(deadline), beforeDeadline);
    await write(deadline, { "fixture:final-clock-delta-ms": 6e3 });
    const expired = await refused(deadline, issue(deadline), { lifetime: 5 });
    assert.equal(expired.status, 409);
    assert.equal((await read(deadline, ["fixture:clock-observations"]))["fixture:clock-observations"], 6);
    await fixture(stub(deadline), "clear", ["fixture:final-clock-delta-ms"]);
    await restart();
    const retainedDeadline = (await ok(deadline, { kind: "current" })).reply.current;
    assert.equal(retainedDeadline.journal.last_sequence, "1");
    assert.ok(BigInt(retainedDeadline.journal.largest_issued_expiry) > 0n);
    pass("uncertain request deadline refuses early and after final signing observation while committed sequence/expiry survive restart");
    const before = await count(p);
    await write(p, { "fixture:lost-ack": before + 1 });
    await refused(p, issue(p));
    let current = (await ok(p, { kind: "current" })).reply.current;
    assert.equal(current.journal.last_sequence, "2");
    assert.ok(BigInt(current.journal.largest_issued_expiry) > 0n);
    await restart();
    current = (await ok(p, { kind: "current" })).reply.current;
    assert.equal(current.journal.last_sequence, "2");
    pass("lost first durable acknowledgment returns no token; sequence/expiry persist across actual restart");
    await write(p, { "fixture:lost-ack": await count(p) + 2 });
    await refused(p, issue(p));
    await restart();
    current = (await ok(p, { kind: "current" })).reply.current;
    assert.equal(current.journal.last_sequence, "3");
    pass("lost second durable acknowledgment returns no token and retains committed history");
    const blocked2 = denied(p), blocked3 = denied(blocked2), blocked4 = denied(blocked3);
    const deny4 = { kind: "deny", input: { publication: blocked4, expected_remote: remote(p) } };
    const deniedReply = await ok(p, deny4);
    assert.equal(deniedReply.reply.current.journal.last_sequence, "3");
    const retired5 = denied(blocked4, "retired");
    await ok(p, { kind: "deny", input: { publication: retired5, expected_remote: remote(blocked4) } });
    const replay = await ok(p, deny4);
    assert.equal(replay.reply.applied.generation, "4");
    assert.equal(replay.reply.current.journal.generation, "5");
    assert.equal(replay.reply.current.journal.state, "retired");
    const altered = structuredClone(deny4);
    altered.input.expected_remote.digest = "f".repeat(64);
    await refused(p, altered);
    await refused(p, issue(p));
    const installReplay = await ok(p, install(p));
    assert.equal(installReplay.reply.current.journal.state, "retired");
    pass("denial gap preserves history; exact replay returns latest retired head; changed predecessor rejects; old install cannot readmit");
    const reset = publication();
    await ok(reset, install(reset));
    await ok(reset, issue(reset));
    await fixture(stub(reset), "reset", {});
    await restart();
    await refused(reset, install(reset));
    assert.equal((await read(reset, ["live-issuer-v1"]))["live-issuer-v1"], undefined);
    pass("erased issuer head/receipts with retained activated registry never recreates issuance history");
    const gap = publication();
    await registryWrite({ "fixture:lost-ack": await registryCount() + 1 });
    await refused(gap, install(gap));
    const unchanged = await registryCount();
    await refused(gap, { kind: "publish", input: denied(gap) });
    await refused(gap, { kind: "deny", input: { publication: denied(gap), expected_remote: remote(gap) } });
    await refused(gap, issue(gap));
    assert.equal(await registryCount(), unchanged);
    await ok(gap, install(gap));
    await ok(gap, issue(gap));
    pass("initial lost reservation acknowledgment remains pending; no other control/effect until exact activation retry");
    const advanced = publication();
    await registryWrite({ "fixture:lost-ack": await registryCount() + 1 });
    await refused(advanced, install(advanced));
    const blocked = denied(advanced);
    const receipt = {
      generation: blocked.generation,
      digest: blocked.digest,
      publication_digest: sha(JSON.stringify(blocked))
    };
    await registryWrite({
      [`authority/${advanced.authority.authority_id}/head`]: record(blocked),
      [`authority/${advanced.authority.authority_id}/watermark`]: record(remote(blocked)),
      [`authority/${advanced.authority.authority_id}/receipt/${blocked.generation}`]: record(receipt)
    });
    await refused(advanced, install(advanced));
    assert.equal((await read(advanced, ["live-issuer-v1"]))["live-issuer-v1"], undefined);
    const retired = denied(blocked, "retired");
    await registryWrite({
      [`authority/${advanced.authority.authority_id}/head`]: record(retired),
      [`authority/${advanced.authority.authority_id}/watermark`]: record(remote(retired)),
      [`authority/${advanced.authority.authority_id}/receipt/${retired.generation}`]: record({
        generation: retired.generation,
        digest: retired.digest,
        publication_digest: sha(JSON.stringify(retired))
      })
    });
    await refused(advanced, install(advanced));
    assert.equal((await read(advanced, ["live-issuer-v1"]))["live-issuer-v1"], undefined);
    pass("pending old Install cannot initialize behind later denied or retired registry head");
    for (const phase of [1, 2]) {
      const held = publication();
      await ok(held, install(held));
      const target = await count(held) + phase;
      await write(held, { "fixture:held-ack": target });
      let returned = false;
      const pending = invoke(held, issue(held)).then((value) => {
        returned = true;
        return value;
      }, () => null);
      const deadline2 = Date.now() + 15e3;
      while ((await read(held, ["fixture:held-entered"]))["fixture:held-entered"] !== target) {
        if (Date.now() > deadline2) throw new Error("held durable acknowledgment not observed");
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      assert.equal(returned, false, "no usable token before durable acknowledgment");
      await runtime.dispose();
      runtime = null;
      await pending;
      await boot();
      const retained = await ok(held, { kind: "current" });
      assert.equal(retained.reply.current.journal.last_sequence, "1");
      assert.ok(BigInt(retained.reply.current.journal.largest_issued_expiry) > 0n);
      pass(`actual runtime cancellation during durable acknowledgment ${phase} returns no token and retains sequence/expiry`);
    }
    const { p: large, maximum } = largestPublication();
    const installed = await ok(large, install(large));
    assert.ok(installed.bytes < 8192);
    assert.equal("publication" in installed.reply.current, false);
    const raw = (await read(large, ["live-issuer-v1"]))["live-issuer-v1"];
    const manifest = JSON.parse(raw);
    assert.equal(manifest.version, 2);
    assert.ok(manifest.chunks > 1 && manifest.chunks <= 16);
    await restart();
    const restarted = await ok(large, { kind: "current" });
    assert.ok(restarted.bytes < 8192);
    const chunkKeys = Array.from({ length: manifest.chunks }, (_, i) => `authority-record-chunk/${sha("live-issuer-v1")}/${i}`);
    const chunks = await read(large, chunkKeys);
    await fixture(stub(large), "clear", [chunkKeys[0]]);
    await refused(large, { kind: "current" });
    await write(large, { [chunkKeys[0]]: chunks[chunkKeys[0]] });
    await write(large, { [chunkKeys[0]]: chunks[chunkKeys[1]], [chunkKeys[1]]: chunks[chunkKeys[0]] });
    await refused(large, { kind: "current" });
    await write(large, { [chunkKeys[0]]: chunks[chunkKeys[0]], [chunkKeys[1]]: chunks[chunkKeys[1]] });
    await write(large, { [chunkKeys[0]]: "x".repeat(64 * 1024 + 1) });
    await refused(large, { kind: "current" });
    await write(large, { [chunkKeys[0]]: chunks[chunkKeys[0]] });
    await write(large, { "live-issuer-v1": raw.replace("{", '{"chunks":2,') });
    await refused(large, { kind: "current" });
    await write(large, { "live-issuer-v1": raw });
    await ok(large, { kind: "current" });
    pass("missing/reordered/oversized real chunks and duplicate manifest fields reject and exact restoration preserves the retained head");
    await ok(large, { kind: "deny", input: { publication: denied(large), expected_remote: remote(large) } });
    const obsolete = await read(large, Array.from({ length: manifest.chunks }, (_, i) => `authority-record-chunk/${sha("live-issuer-v1")}/${i}`));
    assert.equal(Object.keys(obsolete).length, 0);
    pass(`exact maximum ${maximum}-byte publication survives chunk transaction/restart; compact replies; obsolete chunks retire atomically`);
    const corrupt = publication();
    await ok(corrupt, install(corrupt));
    await write(corrupt, {
      "live-issuer-v1": JSON.stringify({ version: 2, chunks: 99, bytes: 999999, digest: "f".repeat(64) })
    });
    await refused(corrupt, { kind: "current" });
    await refused(corrupt, install(corrupt));
    pass("corrupt manifest fails closed, never absence or reinitialization");
    for (const [name, value] of [["missing-seed", undefined], ["seed-text", seed], ["uppercase-hex", seed.toUpperCase()], ["base64-seed", Buffer.from(seed, "hex").toString("base64")]]) {
      const saved2 = { ...options.workers[0].bindings };
      if (name === "missing-seed") delete options.workers[0].bindings.HUB_AUTHORITY_ISSUER_SEED;
      else options.workers[0].bindings.HUB_AUTHORITY_RENEWAL_KEY = value;
      await applyOptions();
      const fresh = publication();
      const before = await registryCount();
      const response = await invoke(fresh, install(fresh));
      assert.equal(response.status, 503);
      assert.equal(await registryCount(), before);
      options.workers[0].bindings = saved2;
      await applyOptions();
    }
    pass("missing signer and obvious seed/auth representations reject before installation");
    const saved = { ...options.workers[0].bindings };
    delete options.workers[0].bindings.HUB_AUTHORITY_CLOCK_ACCEPTANCE;
    await applyOptions();
    assert.equal((await invoke(publication(), { kind: "current" })).status, 503);
    options.workers[0].bindings = saved;
    await applyOptions();
    pass("explicit timing qualification absent => disabled; no default TTL/uncertainty qualification");
    assert.equal(verdicts.length, 16, "All qualified lifecycle groups must complete");
    const artifactHashes = Object.fromEntries(["shim.mjs", "index.wasm"].map((name) => [name, sha(readFileSync(path.join(artifact, name)))]));
    writeFileSync(output, JSON.stringify({
      pass: true,
      verdicts,
      maximumPublicationBytes: maximum,
      scope: "Actual optimized production Rust Worker under test-only JavaScript storage fault wrappers; local Miniflare/SQLite DO persistence only",
      providerBindings: [],
      productionArtifact: artifact,
      artifactHashes,
      faultFixtureSha256: sha(readFileSync(faultFixture)),
      excluded: ["hosted clock", "deployment key custody", "provider dispatch", "timing/performance", "Native interoperability"]
    }, null, 2) + "\n");
    console.log("RESULT " + output);
  } finally {
    if (runtime) await runtime.dispose();
  }
})().catch((error) => {
  writeFileSync(path.join(directory, "failure.txt"), String(error.stack) + "\n");
  console.error("FAIL " + String(error));
  process.exitCode = 1;
});
