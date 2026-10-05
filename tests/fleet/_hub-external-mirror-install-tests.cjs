// Controlled byte-storage tests; signatures and provider admission remain Rust-owned.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { mkdtempSync, chmodSync, rmSync } = require('node:fs');
const { connect } = require('node:net');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { installExternalMirrorFunctional } = require('./_hub-external-mirror-install.cjs');
const { acceptanceRegistryServer } = require('./_hub-worker-runner.cjs');

function fixture() {
  const run = 'a'.repeat(32), digest = 'b'.repeat(64);
  const profile = { profile: { issuerInstallation: { executor_identity: 'controlled-executor' } },
    runtimeQualification: { version: 1, qualificationDigest: 'c'.repeat(64) } };
  const installation = Object.fromEntries([
    'artifactManifestSha256', 'clockObservationSha256', 'configurationSha256',
    'namespaceObservationSha256', 'nativeExecutableSha256', 'prerequisiteArtifactSha256',
    'providerContractObservationSha256', 'scriptSha256', 'wasmSha256',
  ].map(name => [name, digest]));
  const artifact = { version: 1, purpose: 'full_and_pull_through_functional_probe_v1',
    execution: 'emulated_external', reviewerKeyId: 'mirror-reviewer', deploymentId: 'controlled-deployment',
    publicOrigin: 'https://localhost:4673', sourceDigest: digest, scriptVersion: 'emulated-' + digest,
    protectedProfile: profile, directEvidenceSha256: digest, externalDomainSha256: digest,
    upstreamBase: 'https://aos.andyl.org:4778/fleet-mirror/' + run,
    placementPrefix: '.aos-mirror-qualification/' + run + '/final', maximumObjectBytes: 1024,
    installation, issuedAt: Math.floor(Date.now() / 1000) - 1,
    validUntil: Math.floor(Date.now() / 1000) + 100, signature: 'd'.repeat(128) };
  const options = { name: 'selected-worker', resourcePersistencePath: '/selected/private/state',
    kvNamespaces: { HUB_EXTERNAL_MIRROR_FUNCTIONAL_ACCEPTANCE: 'distinct-mirror', DIRECT: 'distinct-direct' },
    bindings: { HUB_EXTERNAL_MIRROR_FUNCTIONAL_PROBE: '1',
      HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_PUBLIC_KEY: 'e'.repeat(64),
      HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_KEY_ID: 'mirror-reviewer',
      HUB_DEPLOYMENT_ID: artifact.deploymentId, HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN: artifact.publicOrigin,
      HUB_EXTERNAL_MIRROR_CONSUMER: JSON.stringify({ version: 1,
        domains: [{ profile, issuer_installation: profile.profile.issuerInstallation }] }) } };
  const namespace = { version: 1, observationScope: 'selected_external_copy_namespace_readback',
    runnerPid: process.pid, runnerStartTicks: '123', configurationSha256: digest, scriptSha256: digest,
    applicationWorkerName: options.name, sourceWorkerName: 'selected-source',
    persistenceRoot: options.resourcePersistencePath, namespaces: [{ bindingName: 'EXTERNAL_OBJECT_GUARD',
      className: 'ExternalObjectGuard', workerName: 'selected-source', namespaceKey: 'actual-key', objectIds: [] }],
    runnerSha256: digest, isolationModuleSha256: digest, miniflareModuleSha256: digest };
  const slots = new Map(), calls = [];
  const runtime = { getKVNamespace: async (...args) => {
    calls.push(['namespace', ...args]);
    return { get: async key => { calls.push(['get', key]); return slots.get(key) ?? null; },
      put: async (key, value) => { calls.push(['put', key]); slots.set(key, value); } };
  } };
  const request = value => {
    const bytes = Buffer.from(JSON.stringify(value));
    return { version: 1, kind: 'external-mirror-functional-install',
      key: 'controlled-external-mirror-v1:' + 'f'.repeat(64), artifactBase64: bytes.toString('base64'),
      artifactSha256: createHash('sha256').update(bytes).digest('hex') };
  };
  return { artifact, options, namespace, runtime, request, slots, calls };
}

test('actual selected KV stores exact bytes and same-slot replay performs no new put', async () => {
  const f = fixture(), original = f.request(f.artifact);
  const stored = await installExternalMirrorFunctional(f.runtime, f.options, original, async () => f.namespace);
  assert.deepEqual(Object.keys(stored).sort(), ['artifactBase64', 'artifactSha256', 'byteSize', 'key',
    'runnerPid', 'runnerStartTicks', 'status', 'version'].sort());
  assert.equal(stored.status, 'stored');
  assert.equal(stored.artifactBase64, original.artifactBase64);
  assert.deepEqual(f.calls[0], ['namespace', 'HUB_EXTERNAL_MIRROR_FUNCTIONAL_ACCEPTANCE', 'selected-worker']);
  await installExternalMirrorFunctional(f.runtime, f.options, original, async () => f.namespace);
  assert.equal(f.calls.filter(call => call[0] === 'put').length, 1);
});

test('unknown fields, substituted bytes and foreign slot refuse before storage', async () => {
  for (const mutate of [request => { request.pass = true; },
    request => { request.key = 'oci-sdk-emulator-v1-' + 'f'.repeat(64); },
    request => { request.artifactSha256 = '0'.repeat(64); },
    request => { request.artifactBase64 += '='; }]) {
    const f = fixture(), request = f.request(f.artifact);
    mutate(request);
    await assert.rejects(installExternalMirrorFunctional(f.runtime, f.options, request, async () => f.namespace));
    assert.equal(f.calls.length, 0);
  }
});

test('aliases, disabled flag and wrong reviewer refuse before storage', async () => {
  for (const mutate of [options => { options.kvNamespaces.DIRECT = 'distinct-mirror'; },
    options => { options.bindings.HUB_EXTERNAL_MIRROR_FUNCTIONAL_PROBE = '0'; },
    options => { options.bindings.HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_KEY_ID = 'other'; }]) {
    const f = fixture();
    mutate(f.options);
    await assert.rejects(installExternalMirrorFunctional(f.runtime, f.options, f.request(f.artifact), async () => f.namespace));
    assert.equal(f.calls.length, 0);
  }
});

test('foreign purpose, installed profile, source scope and expired original refuse', async () => {
  for (const mutate of [artifact => { artifact.execution = 'hosted'; },
    artifact => { artifact.purpose = 'oci_documents'; },
    artifact => { artifact.protectedProfile.runtimeQualification.qualificationDigest = '0'.repeat(64); },
    artifact => { artifact.placementPrefix += '/full'; },
    artifact => { artifact.upstreamBase += '/other'; },
    artifact => { artifact.scriptVersion = 'configured-label'; },
    artifact => { artifact.validUntil = artifact.issuedAt; }]) {
    const f = fixture();
    mutate(f.artifact);
    await assert.rejects(installExternalMirrorFunctional(f.runtime, f.options, f.request(f.artifact), async () => f.namespace));
    assert.equal(f.calls.length, 0);
  }
});

test('actual namespace and current configured bytes must match before storage', async () => {
  for (const mutate of [namespace => { namespace.observationScope = 'oci_sdk_emulator_namespace_readback'; },
    namespace => { namespace.runnerPid += 1; },
    namespace => { namespace.configurationSha256 = '0'.repeat(64); },
    namespace => { namespace.scriptSha256 = '0'.repeat(64); },
    namespace => { namespace.namespaces[0].className = 'OtherGuard'; }]) {
    const f = fixture();
    mutate(f.namespace);
    await assert.rejects(installExternalMirrorFunctional(f.runtime, f.options, f.request(f.artifact), async () => f.namespace));
    assert.equal(f.calls.length, 0);
  }
});

test('conflict and altered readback refuse without overwriting an original slot', async () => {
  const f = fixture(), request = f.request(f.artifact);
  f.slots.set(request.key, 'different retained bytes');
  await assert.rejects(installExternalMirrorFunctional(f.runtime, f.options, request, async () => f.namespace));
  assert.equal(f.calls.filter(call => call[0] === 'put').length, 0);
  f.runtime.getKVNamespace = async () => ({ get: async () => null, put: async () => {} });
  await assert.rejects(installExternalMirrorFunctional(f.runtime, f.options, request, async () => f.namespace));
});

test('changed runner lifetime or namespace during readback refuses stored-result claim', async () => {
  for (const mutate of [namespace => { namespace.runnerStartTicks = '124'; },
    namespace => { namespace.namespaces[0].namespaceKey = 'changed-key'; }]) {
    const f = fixture();
    let reads = 0;
    await assert.rejects(installExternalMirrorFunctional(f.runtime, f.options, f.request(f.artifact), async () => {
      const observed = structuredClone(f.namespace);
      if (reads++) mutate(observed);
      return observed;
    }));
    assert.equal(f.calls.filter(call => call[0] === 'put').length, 1);
  }
});

test('runner dispatches the exact dedicated kind and refuses an unavailable installer', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'aos-mirror-storage-'));
  chmodSync(root, 0o700);
  let server;
  const send = (file, request) => new Promise((resolve, reject) => {
    const socket = connect(file), blocks = [];
    socket.setTimeout(2000, () => socket.destroy(new Error('Controlled socket timed out')));
    socket.once('error', reject);
    socket.on('data', bytes => blocks.push(bytes));
    socket.once('end', () => resolve(JSON.parse(Buffer.concat(blocks).toString())));
    socket.once('connect', () => socket.end(JSON.stringify(request)));
  });
  try {
    const f = fixture(), request = f.request(f.artifact), file = path.join(root, 'control.sock');
    server = acceptanceRegistryServer(f.runtime, file, f.options.bindings, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      selected => installExternalMirrorFunctional(f.runtime, f.options, selected, async () => f.namespace));
    await server.ready;
    assert.equal((await send(file, request)).status, 'stored');
    assert.equal((await send(file, { ...request, pass: true })).status, 'refused');
    await server.close();
    server = acceptanceRegistryServer(f.runtime, path.join(root, 'unavailable.sock'), f.options.bindings);
    await server.ready;
    assert.equal((await send(path.join(root, 'unavailable.sock'), request)).status, 'refused');
  } finally {
    if (server) await server.close();
    rmSync(root, { recursive: true, force: true });
  }
});
