// Controlled producer and custody tests. No Miniflare runtime or R2 SDK effects.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync } = require('node:fs');
const path = require('node:path');
const { tmpdir } = require('node:os');
const { test } = require('node:test');
const runner = require('./_hub-worker-runner.cjs');

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const originalBytes = value => Buffer.from(JSON.stringify(Object.fromEntries(
  Object.keys(value).sort().map(field => [field, value[field]]))) + '\n');

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), 'aos-oci-anchor-controlled-'));
  chmodSync(root, 0o700);
  const namespace = { observationScope: 'oci_sdk_emulator_namespace_readback',
    namespaceId: 'oci-sdk-qualification-' + 'a'.repeat(32),
    observedAt: new Date().toISOString(), bindingName: 'REGISTRY_BUCKET',
    workerName: 'controlled-worker', runnerPid: process.pid, runnerStartTicks: '1',
    configurationSha256: 'a'.repeat(64) };
  const namespaceBytes = Buffer.from(JSON.stringify(namespace));
  const payload = Buffer.from('controlled bounded anchor bytes');
  const now = Math.floor(Date.now() / 1000);
  const original = { version: 1, runId: 'b'.repeat(32), issuedAt: String(now),
    expiresAt: String(now + 30), namespaceObservationBase64: namespaceBytes.toString('base64'),
    namespaceObservationSha256: hash(namespaceBytes), payloadBase64: payload.toString('base64'),
    payloadSha256: hash(payload), payloadByteSize: String(payload.length) };
  const calls = [];
  const key = `.aos-oci-sdk-qualification/${original.runId}/anchor`;
  const identity = { key, size: payload.length, version: 'c'.repeat(32),
    httpEtag: '"' + 'd'.repeat(32) + '"' };
  const bucket = {
    async put(actualKey, bytes, options) {
      assert.equal(readFileSync(path.join(root, 'oci-sdk-anchor-journal', original.runId,
        'original.json')).toString(), originalBytes(original).toString());
      calls.push(['put', actualKey, Buffer.from(bytes), options]);
      return { ...identity };
    },
    async get(actualKey, options) {
      calls.push(['get', actualKey, options]);
      return { ...identity, body: new ReadableStream({ start(controller) {
        controller.enqueue(payload.subarray(0, 3));
        controller.enqueue(payload.subarray(3));
        controller.close();
      } }) };
    },
  };
  const runtime = { async getR2Bucket(binding, worker) {
    calls.push(['select', binding, worker]);
    return bucket;
  } };
  return { root, namespace, payload, original, calls, bucket, runtime, identity,
    options: { ociAnchorEnabled: true, resourcePersistencePath: root },
    request() {
      const bytes = Buffer.from(originalBytes(original).toString());
      return { version: 1, kind: 'oci-sdk-anchor-create', originalBase64: bytes.toString('base64'),
        originalSha256: hash(bytes) };
    },
    run() { return runner.createOciSdkAnchor(runtime, this.options, this.request(),
      async () => ({ ...namespace, observedAt: new Date().toISOString() })); },
    close() { rmSync(root, { recursive: true }); } };
}

test('positive original precedes create-only Put and conditional full identity read', async () => {
  const value = fixture();
  try {
    const result = await value.run();
    assert.equal(result.status, 'observed');
    assert.deepEqual(result.sdkInvocations, { put: 1, get: 1 });
    assert.deepEqual(result.anchor, { object: { key: value.identity.key,
      provider_version: value.identity.version, etag: value.identity.httpEtag,
      size: value.payload.length }, sha256: hash(value.payload) });
    assert.deepEqual(value.calls, [ ['select', 'REGISTRY_BUCKET', 'controlled-worker'],
      ['put', value.identity.key, value.payload, { onlyIf: { etagDoesNotMatch: '*' },
        sha256: hash(value.payload) }],
      ['get', value.identity.key, { onlyIf: { etagMatches: value.identity.httpEtag.slice(1, -1) } }] ]);
    assert.deepEqual(JSON.parse(readFileSync(path.join(value.root, 'oci-sdk-anchor-journal',
      value.original.runId, 'receipt.json'))), result);
    await assert.rejects(value.run());
    assert.equal(value.calls.length, 3);
  } finally { value.close(); }
});

test('closed original refuses malformed bounds, UTC types and embedded hashes', () => {
  const value = fixture();
  try {
    const changes = [{ extra: true }, { version: true }, { runId: 'not-a-run' },
      { issuedAt: Number(value.original.issuedAt) }, { expiresAt: value.original.issuedAt },
      { expiresAt: String(Number(value.original.issuedAt) + 31) }, { payloadByteSize: '01' },
      { payloadSha256: '0'.repeat(64) }, { namespaceObservationSha256: '0'.repeat(64) },
      { payloadBase64: '', payloadSha256: hash(Buffer.alloc(0)), payloadByteSize: '0' },
      { payloadBase64: Buffer.alloc(1025).toString('base64'),
        payloadSha256: hash(Buffer.alloc(1025)), payloadByteSize: '1025' }];
    for (const change of changes) assert.throws(() => runner.ociAnchorOriginal(
      originalBytes({ ...value.original, ...change })));
    assert.throws(() => runner.ociAnchorOriginal(Buffer.from([0xff])));
    assert.throws(() => runner.ociAnchorOriginal(Buffer.from(
      originalBytes(value.original).toString().replace('{', '{\"version\":1,'))));
    assert.equal(value.calls.length, 0);
  } finally { value.close(); }
});

test('opt-in, immutable namespace, dedicated scope and expired originals refuse before SDK', async () => {
  for (const mode of ['disabled', 'extra-request', 'namespace', 'ordinary', 'expired', 'rollback']) {
    const value = fixture();
    try {
      let request = value.request();
      if (mode === 'disabled') value.options.ociAnchorEnabled = false;
      if (mode === 'extra-request') request.extra = true;
      if (mode === 'namespace') value.namespace.workerName = 'changed-after-original';
      if (mode === 'ordinary') value.namespace.namespaceId = 'ordinary-bucket';
      if (mode === 'expired') {
        value.original.issuedAt = String(Math.floor(Date.now() / 1000) - 31);
        value.original.expiresAt = String(Number(value.original.issuedAt) + 30);
        request = value.request();
      }
      if (mode === 'rollback') {
        value.original.issuedAt = String(Math.floor(Date.now() / 1000) + 30);
        value.original.expiresAt = String(Number(value.original.issuedAt) + 30);
        request = value.request();
      }
      await assert.rejects(runner.createOciSdkAnchor(value.runtime, value.options, request,
        async () => value.namespace));
      assert.equal(value.calls.length, 0, mode);
      assert.equal(existsSync(path.join(value.root, 'oci-sdk-anchor-journal')), false, mode);
    } finally { value.close(); }
  }
});

test('lost Put reply stays permanent unknown and cannot repeat the mutation', async () => {
  const value = fixture();
  try {
    value.bucket.put = async () => { value.calls.push(['put-with-lost-reply']); throw new Error('controlled'); };
    const result = await value.run();
    assert.equal(result.status, 'unknown');
    assert.deepEqual(result.sdkInvocations, { put: 1, get: 0 });
    assert.equal(result.anchor, undefined);
    assert.deepEqual(JSON.parse(readFileSync(path.join(value.root, 'oci-sdk-anchor-journal',
      value.original.runId, 'diagnostic.json'))),
      { version: 1, stage: 'conditional_create', code: 'sdk_call_failed' });
    await assert.rejects(value.run());
    assert.equal(value.calls.length, 2);
    assert.equal(JSON.parse(readFileSync(path.join(value.root, 'oci-sdk-anchor-journal',
      value.original.runId, 'receipt.json'))).status, 'unknown');
  } finally { value.close(); }
});

test('conditional create refusal cannot dispatch a GET or replace an original', async () => {
  const value = fixture();
  try {
    value.bucket.put = async () => null;
    const result = await value.run();
    assert.equal(result.status, 'refused');
    assert.deepEqual(result.sdkInvocations, { put: 1, get: 0 });
    assert.deepEqual(JSON.parse(readFileSync(path.join(value.root, 'oci-sdk-anchor-journal',
      value.original.runId, 'diagnostic.json'))),
      { version: 1, stage: 'conditional_create', code: 'conditional_create_refused' });
    await assert.rejects(value.run());
    assert.equal(value.calls.length, 1);
  } finally { value.close(); }
});

test('different versions, ETags, keys, sizes and incomplete bodies remain unknown', async () => {
  for (const change of [{ version: 'e'.repeat(32) }, { httpEtag: '"' + 'e'.repeat(32) + '"' },
      { key: 'another-key' }, { size: 0 }, { body: null },
      { body: new ReadableStream({ start(controller) { controller.enqueue(Buffer.from('wrong')); controller.close(); } }) }]) {
    const value = fixture();
    try {
      const originalGet = value.bucket.get;
      value.bucket.get = async (...args) => ({ ...await originalGet(...args), ...change });
      const result = await value.run();
      assert.equal(result.status, 'unknown');
      assert.equal(result.anchor, undefined);
    } finally { value.close(); }
  }
});

test('stream limits and UTC expiry after await preserve unknown without positive receipt', async () => {
  for (const mode of ['oversized', 'empty', 'expired-put', 'expired-read']) {
    const value = fixture();
    const actualNow = Date.now;
    let clock = actualNow();
    Date.now = () => clock;
    try {
      if (mode === 'expired-put') {
        const originalPut = value.bucket.put;
        value.bucket.put = async (...args) => {
          const reply = await originalPut(...args);
          clock = Number(value.original.expiresAt) * 1000;
          return reply;
        };
      } else {
        value.bucket.get = async () => ({ ...value.identity,
          body: new ReadableStream({ pull(controller) {
            if (mode === 'expired-read') clock = Number(value.original.expiresAt) * 1000;
            controller.enqueue(Buffer.alloc(mode === 'oversized' ? 1025 : mode === 'empty' ? 0 : 1));
            controller.close();
          } }) });
      }
      const result = await value.run();
      assert.equal(result.status, 'unknown', mode);
      assert.equal(result.anchor, undefined, mode);
      assert.equal(result.sdkInvocations.get, mode === 'expired-put' ? 0 : 1);
    } finally { Date.now = actualNow; value.close(); }
  }
});


test('conditional read uses the SDK raw ETag while the positive identity remains quoted', async () => {
  const value = fixture();
  try {
    const originalGet = value.bucket.get;
    value.bucket.get = async (key, options) => {
      assert.match(options.onlyIf.etagMatches, /^[0-9a-f]{32}$/);
      assert.equal(options.onlyIf.etagMatches, value.identity.httpEtag.slice(1, -1));
      return originalGet(key, options);
    };
    const result = await value.run();
    assert.equal(result.status, 'observed');
    assert.equal(result.anchor.object.etag, value.identity.httpEtag);
    assert.equal(existsSync(path.join(value.root, 'oci-sdk-anchor-journal',
      value.original.runId, 'diagnostic.json')), false);
  } finally { value.close(); }
});


test('conditional read failure retains only bounded private diagnostic labels', async () => {
  const value = fixture();
  try {
    value.bucket.get = async () => { throw new Error('private SDK detail must not be retained'); };
    const result = await value.run();
    assert.equal(result.status, 'unknown');
    assert.equal(result.anchor, undefined);
    assert.deepEqual(result.sdkInvocations, { put: 1, get: 1 });
    const diagnostic = JSON.parse(readFileSync(path.join(value.root, 'oci-sdk-anchor-journal',
      value.original.runId, 'diagnostic.json')));
    assert.deepEqual(diagnostic, { version: 1, stage: 'conditional_read', code: 'sdk_call_failed' });
    assert.equal(JSON.stringify(result).includes('private SDK detail'), false);
    await assert.rejects(value.run());
    assert.equal(value.calls.length, 2);
  } finally { value.close(); }
});
