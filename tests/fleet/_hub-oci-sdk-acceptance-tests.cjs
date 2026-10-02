// Controlled typed KV tests. No artifact signature, Miniflare or provider effects.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { chmodSync, mkdtempSync, rmSync } = require('node:fs');
const { connect } = require('node:net');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { acceptanceRegistryServer, storeOciSdkAcceptance } = require('./_hub-worker-runner.cjs');

const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function fixture() {
  const digest = 'a'.repeat(64);
  const namespace = {
    observationScope: 'oci_sdk_emulator_namespace_readback', runnerPid: process.pid,
    runnerStartTicks: '1', workerdPid: 123, workerdStartTicks: '2',
    workerName: 'controlled-worker', bindingName: 'REGISTRY_BUCKET',
    namespaceId: 'oci-sdk-qualification-' + 'b'.repeat(32),
    namespaceObjectId: 'c'.repeat(64), namespaceUniqueKey: 'miniflare-R2BucketObject',
    buildDerivedSourceDigest: digest, buildDerivedScriptVersion: 'emulated-' + digest,
    wasmByteSize: '100',
  };
  const files = ['configurationSha256', 'runnerSha256', 'miniflareModuleSha256',
    'miniflareEntryWorkerSha256', 'miniflareBucketWorkerSha256', 'wasmSha256',
    'shimSha256', 'workerdExecutableSha256'];
  for (const field of files) namespace[field] = digest;
  const mapping = {
    workerName: namespace.workerName, bindingName: namespace.bindingName,
    namespaceId: namespace.namespaceId, namespaceObjectId: namespace.namespaceObjectId,
    namespaceUniqueKey: namespace.namespaceUniqueKey, workerSourceDigest: digest,
    workerScriptVersion: namespace.buildDerivedScriptVersion,
  };
  const clockPolicy = { version: 1, mode: 'bounded_utc', uncertaintySeconds: '1' };
  const anchor = { object: { key: '.aos-oci-sdk-qualification/' + 'd'.repeat(32) + '/anchor',
    provider_version: 'controlled-version', etag: '"controlled-etag"', size: 256 }, sha256: digest };
  const now = Math.floor(Date.now() / 1000);
  const installation = { ...mapping, observedAt: now, wasmByteSize: 100 };
  for (const field of [...files, 'namespaceObservationSha256', 'nativeObservationSha256',
    'nativeExecutableSha256', 'nativeConfigurationSha256', 'sourceNarSha256',
    'distributionNarSha256']) installation[field] = digest;
  // Deliberately unsigned mock bytes: successful storage must not claim acceptance.
  const artifact = {
    version: 1, purpose: 'oci_documents', executionKind: 'emulated_managed_sdk',
    reviewerKeyId: 'controlled-reviewer', issuedAt: now - 1, expiresAt: now + 120,
    signature: '0'.repeat(128), evidenceSha256: digest,
    profile: { ...mapping, deploymentId: 'controlled-deployment', publicOrigin: 'https://worker.test',
      nativeOrigin: 'https://native.test', clockPolicy, maximumProviderRequests: 2,
      privateStagePolicy: { policyId: 'controlled-policy', policyDigest: digest,
        namespace: namespace.namespaceId }, anchor },
    evidence: { sdkObservationScope: 'anchor_create_and_conditional_read', installation,
      clock: {}, sdkObservationSha256: digest, anchor, expiredEffects: 0 },
  };
  const key = 'oci-sdk-emulator-v1-' + 'e'.repeat(64);
  const options = { ociSdkAcceptanceRegistryKey: key, kvNamespaces: {
    HUB_OCI_SDK_EMULATOR_ACCEPTANCE: 'controlled-oci-registry',
    HUB_DIRECT_UPLOAD_ACCEPTANCE: 'controlled-direct-registry',
  }, bindings: {
    HUB_DEPLOYMENT_ID: artifact.profile.deploymentId,
    HUB_OCI_SDK_EMULATOR_ENABLED: 'true',
    HUB_OCI_SDK_EMULATOR_REVIEWER_KEY_ID: artifact.reviewerKeyId,
    HUB_OCI_SDK_EMULATOR_REVIEWER_PUBLIC_KEY: 'f'.repeat(64),
    HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN: artifact.profile.publicOrigin,
    HUB_HYBRID_ORIGIN_URL: artifact.profile.nativeOrigin,
    HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS: '2',
    HUB_DIRECT_UPLOAD_CLOCK_MODE: 'bounded_utc',
    HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS: '1',
  } };
  const calls = [];
  let stored = null;
  const registry = {
    async get(selectedKey) { calls.push(['get', selectedKey]); return stored; },
    async put(selectedKey, bytes) { calls.push(['put', selectedKey]); stored = bytes; },
  };
  const runtime = { async getKVNamespace(binding, workerName) {
    calls.push(['select', binding, workerName]); return registry;
  } };
  return {
    artifact, namespace, options, calls, registry, runtime, key,
    request(value = artifact) {
      const bytes = Buffer.from(JSON.stringify(value));
      return { version: 1, kind: 'oci-sdk-acceptance-install', key,
        artifactBase64: bytes.toString('base64'), artifactSha256: hash(bytes) };
    },
    observe: async () => ({ ...namespace }),
    run(request = this.request()) {
      return storeOciSdkAcceptance(runtime, options, request, this.observe);
    },
    retained() { return stored; },
    setRetained(value) { stored = value; },
  };
}

test('typed staging returns exact eight stored fields and actual dedicated KV bytes', async () => {
  const value = fixture();
  const request = value.request();
  const result = await value.run(request);

  assert.deepEqual(result, { version: 1, status: 'stored', key: request.key,
    artifactSha256: request.artifactSha256,
    byteSize: String(Buffer.from(request.artifactBase64, 'base64').length),
    runnerPid: process.pid, runnerStartTicks: '1', artifactBase64: request.artifactBase64 });
  assert.equal(value.retained(), Buffer.from(request.artifactBase64, 'base64').toString());
  assert.deepEqual(value.calls, [['select', 'HUB_OCI_SDK_EMULATOR_ACCEPTANCE', 'controlled-worker'],
    ['get', value.key], ['put', value.key], ['get', value.key]]);
});

test('same retained bytes read back without another put; conflicting bytes never overwrite', async () => {
  const value = fixture();
  value.setRetained(Buffer.from(value.request().artifactBase64, 'base64').toString());
  await value.run();
  assert.equal(value.calls.some(([kind]) => kind === 'put'), false);

  value.setRetained('retained-conflict');
  await assert.rejects(value.run());
  assert.equal(value.retained(), 'retained-conflict');
  assert.equal(value.calls.some(([kind]) => kind === 'put'), false);
});

test('closed request, hash, canonical base64, UTF-8 and artifact size refuse before KV', async () => {
  for (const mode of ['extra', 'version', 'kind', 'key', 'hash', 'base64', 'utf8', 'size']) {
    const value = fixture();
    const request = value.request();
    if (mode === 'extra') request.extra = true;
    if (mode === 'version') request.version = true;
    if (mode === 'kind') request.kind = 'other';
    if (mode === 'key') request.key += 'a';
    if (mode === 'hash') request.artifactSha256 = '0'.repeat(64);
    if (mode === 'base64') request.artifactBase64 += '\n';
    if (mode === 'utf8' || mode === 'size') {
      const bytes = mode === 'utf8' ? Buffer.from([255]) : Buffer.alloc(32769);
      request.artifactBase64 = bytes.toString('base64');
      request.artifactSha256 = hash(bytes);
    }
    await assert.rejects(value.run(request), mode);
    assert.deepEqual(value.calls, [], mode);
  }
});

test('closed artifact, profile, evidence and installation field sets refuse before KV', async () => {
  for (const selected of ['artifact', 'profile', 'evidence', 'installation']) {
    for (const change of ['extra', 'missing']) {
      const value = fixture();
      const target = selected === 'artifact' ? value.artifact : selected === 'installation'
        ? value.artifact.evidence.installation : value.artifact[selected];
      if (change === 'extra') target.extra = true;
      else delete target[Object.keys(target)[0]];
      await assert.rejects(value.run(), `${selected}/${change}`);
      assert.deepEqual(value.calls, []);
    }
  }
  const value = fixture();
  await assert.rejects(value.run(value.request(null)));
  assert.deepEqual(value.calls, []);
});

test('purpose, scope, execution, reviewer and explicit configuration refuse before KV', async () => {
  const mutations = [
    value => { value.artifact.purpose = 'direct_upload'; },
    value => { value.artifact.executionKind = 'hosted'; },
    value => { value.artifact.reviewerKeyId = 'other'; },
    value => { value.artifact.evidence.sdkObservationScope = 'business_effects'; },
    value => { value.artifact.signature = 'invalid'; },
    value => { value.artifact.evidenceSha256 = 'invalid'; },
    value => { delete value.options.ociSdkAcceptanceRegistryKey; },
    value => { delete value.options.kvNamespaces; },
    value => { value.options.kvNamespaces = ['HUB_OCI_SDK_EMULATOR_ACCEPTANCE']; },
    value => { value.options.kvNamespaces.HUB_OCI_SDK_EMULATOR_ACCEPTANCE = {
      id: 'controlled-oci-registry', remoteProxyConnectionString: 'unsupported' }; },
    value => { value.options.kvNamespaces.HUB_DIRECT_UPLOAD_ACCEPTANCE = 'controlled-oci-registry'; },
    value => { value.options.kvNamespaces.HUB_DIRECT_UPLOAD_ACCEPTANCE = { id: 'controlled-oci-registry' }; },
    value => { value.options.bindings.HUB_OCI_SDK_EMULATOR_ENABLED = false; },
    value => { value.options.bindings.HUB_OCI_SDK_EMULATOR_REVIEWER_PUBLIC_KEY = 'invalid'; },
    value => { value.options.bindings.HUB_DEPLOYMENT_ID = 'other'; },
    value => { value.options.bindings.HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN = 'https://other.test'; },
    value => { value.options.bindings.HUB_HYBRID_ORIGIN_URL = 'https://other.test'; },
    value => { value.options.bindings.HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS = '02'; },
    value => { value.artifact.profile.maximumProviderRequests = 33; },
    value => { value.artifact.profile.clockPolicy.uncertaintySeconds = '2'; },
    value => { value.artifact.profile.clockPolicy.extra = true; },
  ];
  for (const mutate of mutations) {
    const value = fixture();
    mutate(value);
    await assert.rejects(value.run());
    assert.deepEqual(value.calls, []);
  }
});

test('UTC integer and original interval bounds refuse before KV', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const change of [{ issuedAt: String(now) }, { issuedAt: now + 10 },
    { expiresAt: now - 1 }, { expiresAt: now + 29, issuedAt: now - 1 },
    { expiresAt: now + 3601, issuedAt: now - 1 }, { expiresAt: Number.MAX_SAFE_INTEGER + 1 }]) {
    const value = fixture();
    Object.assign(value.artifact, change);
    await assert.rejects(value.run());
    assert.deepEqual(value.calls, []);
  }
});

test('every live mapping and measured installation field must match before KV', async () => {
  const mapping = ['workerName', 'bindingName', 'namespaceId', 'namespaceObjectId',
    'namespaceUniqueKey', 'workerSourceDigest', 'workerScriptVersion'];
  const files = ['configurationSha256', 'runnerSha256', 'miniflareModuleSha256',
    'miniflareEntryWorkerSha256', 'miniflareBucketWorkerSha256', 'wasmSha256',
    'wasmByteSize', 'shimSha256', 'workerdExecutableSha256'];
  for (const field of [...mapping, ...files]) {
    const value = fixture();
    value.artifact.evidence.installation[field] = 'different';
    await assert.rejects(value.run(), field);
    assert.deepEqual(value.calls, [], field);
  }
  for (const field of mapping) {
    const value = fixture();
    value.artifact.profile[field] = 'different';
    await assert.rejects(value.run(), field);
    assert.deepEqual(value.calls, []);
  }
  for (const change of [{ runnerPid: process.pid + 1 }, { observationScope: 'other' }]) {
    const value = fixture();
    Object.assign(value.namespace, change);
    await assert.rejects(value.run());
    assert.deepEqual(value.calls, []);
  }
});

test('changed KV readback refuses and preserves actual stored bytes', async () => {
  const value = fixture();
  let reads = 0;
  value.registry.get = async () => ++reads === 1 ? null : 'changed-readback';
  await assert.rejects(value.run());
  assert.equal(value.retained(), Buffer.from(value.request().artifactBase64, 'base64').toString());
});

test('post-storage mapping or process change refuses without deleting bytes', async () => {
  for (const field of ['runnerStartTicks', 'workerdPid', 'workerdStartTicks', 'namespaceObjectId']) {
    const value = fixture();
    let observations = 0;
    value.observe = async () => observations++ === 0 ? { ...value.namespace }
      : { ...value.namespace, [field]: 'changed' };
    await assert.rejects(value.run(), field);
    assert.notEqual(value.retained(), null, field);
    assert.equal(value.calls.some(([kind]) => kind === 'delete'), false);
  }
});

test('expiry after an awaited read refuses before put; post-write expiry retains bytes', async () => {
  const actualNow = Date.now;
  try {
    for (const stage of ['get', 'put']) {
      const value = fixture();
      const original = value.registry[stage];
      value.registry[stage] = async (...args) => {
        const result = await original(...args);
        Date.now = () => value.artifact.expiresAt * 1000;
        return result;
      };
      await assert.rejects(value.run(), stage);
      assert.equal(value.calls.some(([kind]) => kind === 'put'), stage === 'put');
      assert.equal(value.retained() !== null, stage === 'put');
      Date.now = actualNow;
    }
  } finally { Date.now = actualNow; }
});

function socketRequest(socketPath, value) {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const chunks = [];
    socket.on('error', reject);
    socket.on('data', bytes => chunks.push(bytes));
    socket.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString())));
    socket.on('connect', () => socket.end(JSON.stringify(value)));
  });
}

test('real private socket routes OCI independently and refuses concurrent staging', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'aos-oci-staging-controlled-'));
  chmodSync(root, 0o700);
  const value = fixture();
  let enter;
  let release;
  const entered = new Promise(resolve => { enter = resolve; });
  const held = new Promise(resolve => { release = resolve; });
  const socketPath = path.join(root, 'control.sock');
  const server = acceptanceRegistryServer(value.runtime, socketPath, value.options.bindings,
    async () => ({ scope: 'guard' }), async () => ({ scope: 'oci' }), undefined,
    async request => { enter(); await held; return value.run(request); });
  try {
    await server.ready;
    assert.deepEqual(await socketRequest(socketPath, { version: 1, kind: 'namespace-readback' }),
      { scope: 'guard' });
    assert.deepEqual(await socketRequest(socketPath, { version: 1, kind: 'oci-sdk-namespace-readback' }),
      { scope: 'oci' });
    const first = socketRequest(socketPath, value.request());
    await entered;
    assert.deepEqual(await socketRequest(socketPath, value.request()), { version: 1, status: 'refused' });
    release();
    assert.equal((await first).status, 'stored');
    assert.deepEqual(await socketRequest(socketPath, { ...value.request(), extra: true }),
      { version: 1, status: 'refused' });
    assert.equal(value.calls.filter(([kind]) => kind === 'put').length, 1);
  } finally {
    release();
    await server.close();
    rmSync(root, { recursive: true });
  }
});
