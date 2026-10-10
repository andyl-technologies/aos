// Controlled source/API tests only; no Worker, R2 object or acceptance dispatch.
const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, chmodSync, readFileSync, writeFileSync, symlinkSync, rmSync } = require('node:fs');
const { createRequire } = require('node:module');
const { connect } = require('node:net');
const path = require('node:path');
const { tmpdir } = require('node:os');
const { test } = require('node:test');
const observer = require('./_hub-worker-runner.cjs');
const toolingRoot = process.env.AOS_OCI_OBSERVER_MINIFLARE;
if (!toolingRoot) throw new Error('Pass the selected installed AOS Miniflare root');
const load = createRequire(path.join(toolingRoot,
  'lib/node_modules/wrangler/node_modules/fleet-runner.cjs'));
const api = load('miniflare');

function options() {
  return { name: 'selected-worker', r2Buckets: { REGISTRY_BUCKET: 'namespace-one' },
    resourcePersistencePath: '/selected/private-state' };
}

function queueCaptureFixture(change = {}) {
  const runDigest = 'a'.repeat(64), sourceDigest = 'b'.repeat(64), jobDigest = 'c'.repeat(64);
  const selection = { version: 1, binding: 'REGISTRY_BUCKET', runDigest, sourceDigest,
    prefix: `.aos-queue-fault-capture/${runDigest}/`, cutoffUnixMs: Date.now() + 10_000 };
  const configured = { ...options(), bindings: {
    HUB_PROVIDER_CAPACITY_POLICY: JSON.stringify({ source_digest: sourceDigest }),
  } };
  const body = Buffer.from('{"actual":"private job"}');
  const key = selection.prefix + jobDigest + '.json';
  const calls = [];
  const bucket = { async get(actual) {
    assert.equal(this, bucket);
    calls.push(['get', actual]);
    return { key, size: body.length, etag: 'controlled-etag', version: 'controlled-version',
      body: new ReadableStream({ start(controller) { controller.enqueue(body); controller.close(); } }),
      ...change };
  } };
  const runtime = { async getR2Bucket(binding, worker) {
    assert.equal(this, runtime);
    calls.push(['select', binding, worker]);
    return bucket;
  } };
  return { configured, selection, body, calls, runtime,
    request: { version: 1, kind: 'queue-fault-job-read', runDigest, sourceDigest, jobDigest } };
}

test('selected queue image export reads only actual bucket stream and binds original metadata', async () => {
  const peer = queueCaptureFixture();
  const read = observer.createQueueFaultJobReader(peer.runtime, peer.configured, api,
    Buffer.from('actual configuration'), peer.selection);
  const receipt = await read(peer.request);
  assert.equal(Buffer.from(receipt.base64, 'base64').toString(), peer.body.toString());
  assert.equal(receipt.byteSize, String(peer.body.length));
  assert.equal(receipt.eof, true);
  assert.equal(receipt.queueServerAcceptance, null);
  assert.deepEqual(peer.calls, [['select', 'REGISTRY_BUCKET', 'selected-worker'],
    ['get', peer.selection.prefix + peer.request.jobDigest + '.json']]);
  const calls = peer.calls.length;
  for (const change of [{ extra: true }, { sourceDigest: 'd'.repeat(64) },
    { runDigest: 'e'.repeat(64) }, { jobDigest: '../foreign' }]) {
    await assert.rejects(read({ ...peer.request, ...change }));
  }
  assert.equal(peer.calls.length, calls);
});

test('queue raw export refuses partial, oversized, missing and cancelled body with bounded reads', async () => {
  for (const change of [{ size: 999 }, { size: 65537 }, { body: null }, {
    size: 1, body: new ReadableStream({ start(controller) { controller.error(new Error('private failure')); } }),
  }]) {
    const peer = queueCaptureFixture(change);
    const read = observer.createQueueFaultJobReader(peer.runtime, peer.configured, api,
      Buffer.from('configuration'), peer.selection);
    await assert.rejects(read(peer.request));
  }
  let cancelled = false;
  const peer = queueCaptureFixture({ size: 65536, body: new ReadableStream({
    start(controller) { controller.enqueue(Buffer.alloc(65537)); },
    cancel() { cancelled = true; },
  }) });
  const read = observer.createQueueFaultJobReader(peer.runtime, peer.configured, api,
    Buffer.from('configuration'), peer.selection);
  await assert.rejects(read(peer.request), /bound/);
  assert.equal(cancelled, true);
});

test('queue capture is default disabled and malformed selection refuses before SDK reads', () => {
  const peer = queueCaptureFixture();
  assert.equal(observer.createQueueFaultJobReader(peer.runtime, peer.configured, api,
    Buffer.from('configuration'), undefined), undefined);
  for (const change of [{ binding: 'OTHER' }, { prefix: '.foreign/' }, { extra: true },
    { cutoffUnixMs: Date.now() - 1 }, { sourceDigest: 'd'.repeat(64) }]) {
    assert.throws(() => observer.createQueueFaultJobReader(peer.runtime, peer.configured, api,
      Buffer.from('configuration'), { ...peer.selection, ...change }));
  }
  assert.equal(peer.calls.length, 0);
});

function socketRequest(filename, request) {
  return new Promise((resolve, reject) => {
    const socket = connect(filename);
    const chunks = [];
    socket.setTimeout(2000, () => socket.destroy(new Error('Controlled socket timed out')));
    socket.once('error', reject);
    socket.on('data', block => chunks.push(block));
    socket.once('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString())));
    socket.once('connect', () => socket.end(JSON.stringify(request)));
  });
}

test('actual installed implementation matches all three reviewed source hashes', () => {
  const implementation = observer.ociMiniflareImplementation(load);
  assert.equal(implementation.version, observer.OCI_MINIFLARE_PIN.version);
  assert.equal(implementation.moduleFile.sha256, observer.OCI_MINIFLARE_PIN.moduleSha256);
  assert.equal(implementation.entryFile.sha256, observer.OCI_MINIFLARE_PIN.entryWorkerSha256);
  assert.equal(implementation.bucketFile.sha256, observer.OCI_MINIFLARE_PIN.bucketWorkerSha256);
});

test('changed installed API bytes refuse before runtime selection', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'oci-source-api-'));
  try {
    const moduleRoot = path.join(root, 'module');
    const sourceRoot = path.dirname(load.resolve('miniflare'));
    const selectedRoot = path.join(moduleRoot, 'dist/src');
    mkdirSync(path.join(selectedRoot, 'workers/shared'), { recursive: true });
    mkdirSync(path.join(selectedRoot, 'workers/r2'), { recursive: true });
    writeFileSync(path.join(moduleRoot, 'package.json'),
      readFileSync(path.join(sourceRoot, '../../package.json')));
    for (const name of ['workers/shared/object-entry.worker.js', 'workers/r2/bucket.worker.js']) {
      writeFileSync(path.join(selectedRoot, name), readFileSync(path.join(sourceRoot, name)));
    }
    writeFileSync(path.join(selectedRoot, 'index.js'), 'changed');
    const selected = Object.assign(() => { throw new Error('Load must remain untouched'); },
      { resolve: () => path.join(selectedRoot, 'index.js') });
    assert.throws(() => observer.ociMiniflareImplementation(selected));
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('actual schema and plugin bind normalized id to the local entry service', () => {
  const selection = observer.ociLocalR2Selection(api, options());
  assert.deepEqual(selection, { workerName: 'selected-worker', bindingName: 'REGISTRY_BUCKET',
    namespaceId: 'namespace-one', namespaceUniqueKey: 'miniflare-R2BucketObject',
    persistenceRoot: '/selected/private-state/r2' });
  const bindings = api.R2_PLUGIN.getBindings(api.R2OptionsSchema.parse(options()));
  assert.equal(bindings[0].r2Bucket.name, 'r2:bucket:entry');
  assert.deepEqual(JSON.parse(bindings[0].r2Bucket.props.json),
    { MINIFLARE_NAMESPACE: selection.namespaceId });
});

test('object-form id normalizes identically; different ids stay different', () => {
  const selected = options();
  selected.r2Buckets.REGISTRY_BUCKET = { id: 'namespace-two' };
  assert.equal(observer.ociLocalR2Selection(api, selected).namespaceId, 'namespace-two');
});

test('remote, missing, aliased and unbounded namespace selections refuse', () => {
  const cases = [
    { ...options(), r2Buckets: {} },
    { ...options(), r2Buckets: { OTHER: 'namespace-one' } },
    { ...options(), r2Buckets: { REGISTRY_BUCKET: { id: 'namespace-one',
      remoteProxyConnectionString: new URL('https://example.invalid') } } },
    { ...options(), r2Buckets: { REGISTRY_BUCKET: { id: 'namespace-one',
      s3Credentials: { accessKeyId: 'controlled', secretAccessKey: 'controlled' } } } },
    { ...options(), r2Buckets: { REGISTRY_BUCKET: 'namespace-one', OTHER: 'namespace-one' } },
    { ...options(), r2Buckets: { REGISTRY_BUCKET: 'x'.repeat(129) } },
    { ...options(), name: 'x'.repeat(129) },
    { ...options(), resourcePersistencePath: 'relative' },
  ];
  for (const selected of cases) assert.throws(() => observer.ociLocalR2Selection(api, selected));
});

test('live namespace API selection never calls an SDK object operation', async () => {
  const calls = [];
  const runtime = {
    getR2Bucket: async (...args) => {
      calls.push(['getR2Bucket', ...args]);
      return new Proxy({}, { get(_target, name) {
        if (name === 'then') return undefined;
        throw new Error('Object SDK access is forbidden');
      } });
    },
    _getInternalDurableObjectNamespace: async (...args) => {
      calls.push(['namespace', ...args]);
      return { idFromName(name) {
        calls.push(['idFromName', name]);
        return { toString: () => 'a'.repeat(64) };
      } };
    },
  };
  assert.equal(await observer.ociNamespaceObjectId(runtime,
    observer.ociLocalR2Selection(api, options())), 'a'.repeat(64));
  assert.deepEqual(calls, [ ['getR2Bucket', 'REGISTRY_BUCKET', 'selected-worker'],
    ['namespace', 'r2', 'r2:bucket', 'R2BucketObject'], ['idFromName', 'namespace-one'] ]);
});

test('unsupported namespace API and malformed actual object id refuse', async () => {
  const mapping = observer.ociLocalR2Selection(api, options());
  await assert.rejects(observer.ociNamespaceObjectId({ getR2Bucket: async () => ({}) }, mapping));
  await assert.rejects(observer.ociNamespaceObjectId({ getR2Bucket: async () => ({}),
    _getInternalDurableObjectNamespace: async () => ({
      idFromName: () => ({ toString: () => 'not-an-object-id' }) }) }, mapping));
});

test('streamed file hashing refuses bounds and symlink substitution', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'oci-source-files-'));
  try {
    writeFileSync(path.join(root, 'file'), 'controlled');
    assert.equal(observer.ociHashFile(path.join(root, 'file'), 10).byteSize, '10');
    assert.throws(() => observer.ociHashFile(path.join(root, 'file'), 9));
    symlinkSync(path.join(root, 'file'), path.join(root, 'alias'));
    assert.throws(() => observer.ociHashFile(path.join(root, 'alias'), 10));
    assert.throws(() => observer.ociHashFile(root, 10));
    assert.equal(observer.ociProcessIdentity(process.pid).pid, process.pid);
    assert.throws(() => observer.ociWorkerdIdentity('/not/the/runtime'));
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('owner-private socket keeps old variant and External verifier; new request is closed', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'oci-source-socket-'));
  chmodSync(root, 0o700);
  let sdkDispatches = 0;
  let refuse = false;
  const server = observer.acceptanceRegistryServer({ getKVNamespace() { sdkDispatches++; } },
    path.join(root, 'control.sock'), {}, async () => ({ version: 1, kind: 'old-guard' }),
    async () => {
      if (refuse) throw new Error('private namespace diagnostic canary');
      return { version: 1, observationScope: 'controlled-callback' };
    });
  try {
    await server.ready;
    assert.deepEqual(await socketRequest(path.join(root, 'control.sock'),
      { version: 1, kind: 'namespace-readback' }), { version: 1, kind: 'old-guard' });
    assert.deepEqual(await socketRequest(path.join(root, 'control.sock'),
      { version: 1, kind: 'oci-sdk-namespace-readback' }),
    { version: 1, observationScope: 'controlled-callback' });
    for (const request of [{ version: 2, kind: 'oci-sdk-namespace-readback' },
      { version: 1, kind: 'oci-sdk-namespace-readback', extra: true },
      { version: 1, kind: 'unknown' },
      { version: 1, artifactBase64: '', artifactSha256: '0'.repeat(64), key: 'managed' }]) {
      assert.deepEqual(await socketRequest(path.join(root, 'control.sock'), request),
        { version: 1, status: 'refused' });
    }
    assert.equal(sdkDispatches, 0);
    refuse = true;
    const diagnostics = [], originalError = console.error;
    console.error = message => diagnostics.push(message);
    try {
      assert.deepEqual(await socketRequest(path.join(root, 'control.sock'),
        { version: 1, kind: 'oci-sdk-namespace-readback' }), { version: 1, status: 'refused' });
      assert.equal(diagnostics.length, 1);
      assert.match(diagnostics[0], /^Local OCI namespace observation refused at runner line [0-9]+$/);
    } finally {
      console.error = originalError;
    }
  } finally {
    await server.close();
    rmSync(root, { recursive: true });
  }
});

test('queue read owns and cancels the returned stream before metadata validation', async () => {
  let cancelled = 0;
  const peer = queueCaptureFixture({ size: 65537, body: new ReadableStream({
    cancel() { cancelled++; },
  }) });
  const read = observer.createQueueFaultJobReader(peer.runtime, peer.configured, api,
    Buffer.from('configuration'), peer.selection);
  await assert.rejects(read(peer.request), /unbounded/);
  assert.equal(cancelled, 1);
});

test('stalled queue stream and a caller-closed pending get have bounded local ownership', async () => {
  let cancelled = 0;
  const stream = new ReadableStream({ cancel() { cancelled++; } });
  const peer = queueCaptureFixture({ size: 1, body: stream });
  peer.selection.cutoffUnixMs = Date.now() + 40;
  const read = observer.createQueueFaultJobReader(peer.runtime, peer.configured, api,
    Buffer.from('configuration'), peer.selection);
  await assert.rejects(read(peer.request), /lifetime expired/);
  assert.equal(cancelled, 1);
  assert.equal(stream.locked, false);

  const delayed = queueCaptureFixture();
  const caller = new AbortController();
  let resolveGet, selected;
  const waiting = new Promise(resolve => { selected = resolve; });
  delayed.runtime.getR2Bucket = async () => ({ get() {
    selected();
    return new Promise(resolve => { resolveGet = resolve; });
  } });
  const next = observer.createQueueFaultJobReader(delayed.runtime, delayed.configured, api,
    Buffer.from('configuration'), delayed.selection);
  const pending = next(delayed.request, caller.signal);
  await waiting;
  caller.abort();
  await assert.rejects(pending, /caller closed/);
  let lateCancelled = false;
  resolveGet({ body: new ReadableStream({ cancel() { lateCancelled = true; } }) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(lateCancelled, true);
});
