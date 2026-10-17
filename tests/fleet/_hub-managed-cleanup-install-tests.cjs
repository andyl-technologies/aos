// Controlled KV/namespace boundaries only; no Miniflare or provider is started.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');
const { installManagedCleanupFixture, decodeRecord, FIXTURE_KEY } = require('./_hub-managed-cleanup-install.cjs');

function fixture() {
  const now = Math.floor(Date.now() / 1000);
  const digest = 'a'.repeat(64);
  const profile = { deploymentId: 'fixture', publicOrigin: 'https://localhost:4643',
    nativeOrigin: 'https://localhost:4644', workerSourceDigest: digest,
    workerScriptVersion: `emulated-${digest}`, workerName: 'fixture-worker',
    bindingName: 'REGISTRY_BUCKET', namespaceId: `oci-sdk-qualification-${'b'.repeat(32)}`,
    namespaceObjectId: 'c'.repeat(64), namespaceUniqueKey: 'miniflare-R2BucketObject',
    clockPolicy: { version: 1, mode: 'bounded_utc', uncertaintySeconds: '1' },
    maximumProviderRequests: 2, privateStagePolicy: { policyId: 'fixture-policy',
      policyDigest: 'd'.repeat(64), namespace: `oci-sdk-qualification-${'b'.repeat(32)}` },
    anchor: { object: { key: 'qualification/anchor/source', size: 32,
      etag: '"actual-fixture-anchor"', provider_version: 'actual-fixture-version' }, sha256: 'e'.repeat(64) } };
  const record = { version: 1, profile, selection: { deploymentId: profile.deploymentId,
    placementPrefix: 'qualification/oci-terminal-cleanup/fresh',
    protectedProfileDigest: 'f'.repeat(64), sourceDigest: digest,
    scriptVersion: profile.workerScriptVersion, uncertaintySeconds: 1,
    issuedAt: now - 1, expiresAt: now + 120 } };
  const options = { kvNamespaces: { HUB_OCI_SDK_EMULATOR_ACCEPTANCE: 'fixture-kv' }, bindings: {
    HUB_MANAGED_OCI_CLEANUP_FIXTURE_PREFIX: record.selection.placementPrefix,
    HUB_MANAGED_OCI_CLEANUP_FIXTURE_NAMESPACE: profile.namespaceId,
    HUB_DEPLOYMENT_ID: profile.deploymentId, HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN: profile.publicOrigin,
    HUB_HYBRID_ORIGIN_URL: profile.nativeOrigin, HUB_DIRECT_UPLOAD_CLOCK_MODE: 'bounded_utc',
    HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS: '1', HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS: '2',
  } };
  const observation = { observationScope: 'oci_sdk_emulator_namespace_readback', runnerPid: process.pid,
    runnerStartTicks: '123', workerdPid: 456, workerdStartTicks: '789', configurationSha256: '1'.repeat(64),
    wasmSha256: '2'.repeat(64), shimSha256: '3'.repeat(64), workerName: profile.workerName,
    bindingName: profile.bindingName, namespaceId: profile.namespaceId,
    namespaceObjectId: profile.namespaceObjectId, namespaceUniqueKey: profile.namespaceUniqueKey,
    buildDerivedSourceDigest: digest, buildDerivedScriptVersion: profile.workerScriptVersion };
  const values = new Map();
  const calls = [];
  const runtime = { async getKVNamespace(name, worker) {
    calls.push(['namespace', name, worker]);
    return { async get(key) { calls.push(['get', key]); return values.get(key) ?? null; },
      async put(key, value) { calls.push(['put', key]); values.set(key, value); } };
  }, getR2Bucket() { throw new Error('Installer must not use any R2 SDK method'); } };
  const request = () => {
    const bytes = Buffer.from(JSON.stringify(record));
    return { version: 1, kind: 'managed-oci-cleanup-fixture-install', recordBase64: bytes.toString('base64'),
      recordSha256: createHash('sha256').update(bytes).digest('hex') };
  };
  return { record, options, observation, values, calls, runtime, request };
}

test('closed bounded record is stored byte-identically at the fixed KV key', async () => {
  const f = fixture();
  const request = f.request();
  const result = await installManagedCleanupFixture(f.runtime, f.options, request, async () => f.observation);
  assert.equal(result.recordBase64, request.recordBase64);
  assert.equal(result.recordSha256, request.recordSha256);
  assert.equal(result.byteSize, String(Buffer.from(request.recordBase64, 'base64').length));
  assert.equal(result.key, FIXTURE_KEY);
  assert.deepEqual(f.calls.map(row => row[0]), ['namespace', 'get', 'put', 'get']);
});

test('same retained identity performs no fresh KV write', async () => {
  const f = fixture();
  const request = f.request();
  f.values.set(FIXTURE_KEY, Buffer.from(request.recordBase64, 'base64').toString());
  await installManagedCleanupFixture(f.runtime, f.options, request, async () => f.observation);
  assert.equal(f.calls.filter(row => row[0] === 'put').length, 0);
});

test('different retained bytes are never overwritten', async () => {
  const f = fixture();
  f.values.set(FIXTURE_KEY, 'different');
  await assert.rejects(installManagedCleanupFixture(f.runtime, f.options, f.request(), async () => f.observation), /different bytes/);
  assert.equal(f.calls.filter(row => row[0] === 'put').length, 0);
});

test('foreign prefix or actual namespace refuses before KV selection', async () => {
  for (const change of [f => { f.record.selection.placementPrefix = 'other/source'; },
    f => { f.observation.namespaceObjectId = '9'.repeat(64); }]) {
    const f = fixture(); change(f);
    await assert.rejects(installManagedCleanupFixture(f.runtime, f.options, f.request(), async () => f.observation));
    assert.equal(f.calls.length, 0);
  }
});

test('expired, future or oversized window refuses before KV selection', async () => {
  for (const change of [f => { f.record.selection.expiresAt = f.record.selection.issuedAt; },
    f => { f.record.selection.issuedAt += 600; },
    f => { f.record.selection.expiresAt += 600; }]) {
    const f = fixture(); change(f);
    await assert.rejects(installManagedCleanupFixture(f.runtime, f.options, f.request(), async () => f.observation));
    assert.equal(f.calls.length, 0);
  }
});

test('unknown fields and the actual serialized record byte cap refuse', () => {
  const unknown = fixture(); unknown.record.grantsDelete = true;
  assert.throws(() => decodeRecord(unknown.request()), /not closed/);
  const large = fixture(); large.record.profile.anchor.object.key = 'x'.repeat(4096);
  assert.throws(() => decodeRecord(large.request()), /shape differs|bytes differ/);
});

test('changed hash or noncanonical base64 refuses', () => {
  const f = fixture();
  assert.throws(() => decodeRecord({ ...f.request(), recordSha256: '0'.repeat(64) }), /bytes differ/);
  assert.throws(() => decodeRecord({ ...f.request(), recordBase64: f.request().recordBase64 + '\n' }), /bytes differ/);
});

test('aliased registry and changed current clock policy refuse', async () => {
  for (const change of [f => { f.options.kvNamespaces.OTHER = 'fixture-kv'; },
    f => { f.options.bindings.HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS = '2'; }]) {
    const f = fixture(); change(f);
    await assert.rejects(installManagedCleanupFixture(f.runtime, f.options, f.request(), async () => f.observation));
    assert.equal(f.calls.length, 0);
  }
});

test('actual post-store runtime drift refuses despite retained KV bytes', async () => {
  const f = fixture(); let count = 0;
  await assert.rejects(installManagedCleanupFixture(f.runtime, f.options, f.request(), async () =>
    count++ ? { ...f.observation, workerdStartTicks: 'changed' } : f.observation), /runtime changed/);
  assert.equal(f.calls.filter(row => row[0] === 'put').length, 1);
});
