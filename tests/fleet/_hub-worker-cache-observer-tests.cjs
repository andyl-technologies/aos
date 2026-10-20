// Controlled cache doubles test the observer; only the API pin reads real files.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { chmodSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const { connect } = require('node:net');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { publicDocumentCacheKey, installedCacheApi, observePublicDocumentCache } = require('./_hub-worker-cache-observer.cjs');
const { acceptanceRegistryServer } = require('./_hub-worker-runner.cjs');

const tooling = '/nix/store/87zc7fx4hmg9xhczciq60liawanzaqqk-miniflare-wrangler-4.119.0+miniflare-3.20240909.0';
const load = createRequire(path.join(tooling, 'lib/node_modules/wrangler/node_modules/fleet-runner.cjs'));
const body = Buffer.from('{"schema":"controlled-documentation-fixture"}');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const selection = { registrySlug: 'fleet/read-parity', documentSha256: hash(body),
  assetVersion: '76f2f84c', bodyBytes: body.length };
const bindings = { HUB_EXTERNAL_URL: 'https://worker.test', HUB_DEPLOYMENT_ID: 'read-parity-001' };

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), 'aos-cache-observer-controlled-'));
  const scriptPath = path.join(root, 'shim.mjs');
  writeFileSync(scriptPath, '// controlled shim\n');
  let current = null;
  const calls = [];
  const cache = {
    match: async key => { calls.push(['match', key]); return current?.clone(); },
    delete: async key => { calls.push(['delete', key]); const present = current !== null; current = null; return present; },
  };
  return {
    calls, options: { name: 'selected-worker', scriptPath, bindings },
    runtime: { getCaches: async () => ({ default: cache }) },
    fill: (bytes = body, expiry = String(Math.floor(Date.now() / 1000) + 60)) => {
      current = new Response(bytes, { headers: { 'x-aos-front-cache-expires': expiry } });
    },
  };
}

function observe(selected, kind = 'public-document-cache-readback', configured = selection) {
  return observePublicDocumentCache(selected.runtime, load, selected.options,
    Buffer.from('{"controlled":true}'), configured, { version: 1, kind }, 'a'.repeat(64));
}

test('actual installed Miniflare API source matches the reviewed implementation', () => {
  const actual = installedCacheApi(load);
  assert.equal(actual.version, '5.20260801.0-alpha');
  assert.equal(actual.moduleSha256, '973b3563e0e4ac82531642131ebff32b77edfced4ba7f56123a2b09d37c15d01');
});

test('fixed key binds deployment, assets, full sha256-prefixed documentation URL and variants', () => {
  const original = publicDocumentCacheKey(bindings, selection);
  assert.equal(original.url, `https://worker.test/fleet/read-parity/-/api/v1/documentation/sha256:${hash(body)}`);
  const digest = createHash('sha256');
  for (const value of ['aos-hybrid-public-cache-v1', 'read-parity-001', '76f2f84c', original.url,
    '*/*', null, 'identity', null, null]) {
    const bytes = value === null ? Buffer.alloc(0) : Buffer.from(value);
    const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(bytes.length));
    digest.update(length).update(bytes);
  }
  assert.equal(original.key, 'https://worker.test/_internal/hybrid-public-cache/' + digest.digest('hex'));
  assert.notEqual(publicDocumentCacheKey(bindings, { ...selection, assetVersion: '00000000' }).key, original.key);
  assert.notEqual(publicDocumentCacheKey({ ...bindings, HUB_DEPLOYMENT_ID: 'other' }, selection).key, original.key);
});

test('readback observes cold state without a put or deletion', async () => {
  const selected = fixture();
  const result = await observe(selected);
  assert.equal(result.before, null);
  assert.equal(result.deleted, null);
  assert.deepEqual(selected.calls.map(call => call[0]), ['match']);
});

test('one exact existing document is read, deleted and independently absent on readback', async () => {
  const selected = fixture(); selected.fill();
  const result = await observe(selected, 'public-document-cache-evict');
  assert.equal(result.before.bodySha256, hash(body));
  assert.equal(result.deleted, true);
  assert.equal(result.after, null);
  assert.deepEqual(selected.calls.map(call => call[0]), ['match', 'delete', 'match']);
  assert.equal(new Set(selected.calls.map(call => call[1])).size, 1);
});

test('wrong body, oversized body, invalid expiry and absent eviction refuse before delete', async () => {
  for (const value of [Buffer.from('wrong'), Buffer.concat([body, Buffer.from('x')])]) {
    const selected = fixture(); selected.fill(value);
    await assert.rejects(observe(selected, 'public-document-cache-evict'));
    assert.equal(selected.calls.some(call => call[0] === 'delete'), false);
  }
  const selected = fixture(); selected.fill(body, 'unknown');
  await assert.rejects(observe(selected, 'public-document-cache-evict'));
  await assert.rejects(observe(fixture(), 'public-document-cache-evict'));
});

test('caller supplied key, unsupported operation and ambiguous worker refuse without cache access', async () => {
  const selected = fixture();
  assert.throws(() => publicDocumentCacheKey(bindings, { ...selection, key: 'other' }));
  await assert.rejects(observe(selected, 'purge-all'));
  selected.options.workers = [{ name: 'other-worker' }];
  await assert.rejects(observe(selected));
  assert.equal(selected.calls.length, 0);
});

test('actual private runner socket dispatches only the closed selected cache operation', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'aos-cache-socket-controlled-'));
  chmodSync(root, 0o700);
  const socketPath = path.join(root, 'control.sock');
  const selected = fixture(); selected.fill();
  const observed = [];
  const server = acceptanceRegistryServer({}, socketPath, {}, undefined, undefined, undefined, undefined,
    async request => { observed.push(request.kind); return observe(selected, request.kind); });
  await server.ready;

  function request(value) {
    return new Promise((resolve, reject) => {
      const connection = connect(socketPath);
      const chunks = [];
      connection.once('connect', () => connection.end(JSON.stringify(value)));
      connection.on('data', chunk => chunks.push(chunk));
      connection.once('end', () => resolve(JSON.parse(Buffer.concat(chunks))));
      connection.once('error', reject);
    });
  }

  try {
    const result = await request({ version: 1, kind: 'public-document-cache-readback' });
    assert.equal(result.runnerPid, process.pid);
    assert.equal(result.before.bodySha256, hash(body));
    assert.equal(typeof result.runnerStartTicks, 'string');
    assert.equal(Object.keys(result).length, 19);
    assert.deepEqual(await request({ version: 1, kind: 'public-document-cache-evict', key: 'caller-key' }),
      { version: 1, status: 'refused' });
    assert.deepEqual(observed, ['public-document-cache-readback']);
    assert.equal(selected.calls.some(([kind]) => kind === 'delete'), false);
  } finally {
    await server.close();
    rmSync(root, { recursive: true });
  }
});
