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
  const server = observer.acceptanceRegistryServer({ getKVNamespace() { sdkDispatches++; } },
    path.join(root, 'control.sock'), {}, async () => ({ version: 1, kind: 'old-guard' }),
    async () => ({ version: 1, observationScope: 'controlled-callback' }));
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
  } finally {
    await server.close();
    rmSync(root, { recursive: true });
  }
});
