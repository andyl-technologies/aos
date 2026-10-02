// Actual loopback HTTP tests of the confined provider adapter, without workerd.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { queueFaultProvider } from './_hub-direct-queue-fault-provider.mjs';

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

function setup() {
  const runDigest = 'a'.repeat(64);
  const key = `.aos-direct-qualification/${runDigest}/queue-fault/source/payload`;
  const object = { bytes: Buffer.from('actual closed fixture bytes'),
    version: 'actual-version-1', etag: '"actual-etag-1"' };
  const objects = new Map([[key, object]]);
  const selection = { version: 1, runDigest, bucket: 'fixture-bucket', key,
    expected: { version: object.version, etag: object.etag,
      sha256: digest(object.bytes), byteSize: object.bytes.length } };
  return { object, objects, selection, adapter: queueFaultProvider(objects, selection) };
}

async function listen(handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, close: () => new Promise((resolve) => server.close(resolve)) };
}

test('actual conditional GET succeeds, then exact replacement retires the old incarnation', async () => {
  const { adapter, selection, object } = setup();
  const provider = await listen((request, response) => {
    if (!adapter.read(request, response)) response.writeHead(404).end();
  });
  const admin = await listen((request, response) => {
    adapter.administer(request, response).then((handled) => {
      if (!handled) response.writeHead(404).end();
    });
  });
  try {
    const path = `/${selection.bucket}/${selection.key}`;
    const url = `${provider.origin}${path}?versionId=${object.version}`;
    const before = await fetch(url, { headers: { 'If-Match': object.etag } });
    assert.equal(before.status, 200);
    assert.deepEqual(Buffer.from(await before.arrayBuffer()), object.bytes);

    const replacement = await fetch(`${admin.origin}/fixture/queue-fault/replace-source`, {
      method: 'POST', body: JSON.stringify(adapter.trigger),
    });
    assert.equal(replacement.status, 200);
    const observed = await replacement.json();
    assert.notEqual(observed.old.identityDigest, observed.current.identityDigest);
    assert.notEqual(observed.old.sha256, observed.current.sha256);
    const stale = await fetch(url, { headers: { 'If-Match': object.etag } });
    assert.equal(stale.status, 404);
    assert.equal((await stale.arrayBuffer()).byteLength, 0);

    const current = adapter.privateIdentities().current;
    const wrongEtag = await fetch(`${provider.origin}${path}?versionId=${current.version}`, {
      headers: { 'If-Match': object.etag },
    });
    assert.equal(wrongEtag.status, 412);
    const versionless = await fetch(`${provider.origin}${path}`, {
      headers: { 'If-Match': object.etag },
    });
    assert.equal(versionless.status, 412);
    const correct = await fetch(`${provider.origin}${path}?versionId=${current.version}`, {
      headers: { 'If-Match': current.etag },
    });
    assert.equal(correct.status, 200);
    assert.equal(digest(Buffer.from(await correct.arrayBuffer())), current.sha256);
    const snapshot = adapter.snapshot();
    assert.deepEqual(snapshot.counters, { replacements: 1, reads: 5, refusedReads: 3,
      responseOfferedBytes: 2 * object.bytes.length });
    assert.equal(snapshot.observations[2].requestedVersionDigest, digest(object.version));
    assert.ok(!JSON.stringify(snapshot).includes(selection.key));
    assert.ok(!JSON.stringify(snapshot).includes(object.etag));
  } finally {
    await Promise.all([provider.close(), admin.close()]);
  }
});

test('wrong namespace, original or trigger cannot alter the actual store', () => {
  const { objects, selection, adapter, object } = setup();
  assert.throws(() => queueFaultProvider(objects, { ...selection, key: 'ordinary/source' }));
  assert.throws(() => queueFaultProvider(objects, { ...selection,
    expected: { ...selection.expected, sha256: 'b'.repeat(64) } }));
  for (const trigger of [{ ...adapter.trigger, keyDigest: 'b'.repeat(64) },
    { ...adapter.trigger, expectedIdentityDigest: 'b'.repeat(64) },
    { ...adapter.trigger, extra: true }]) {
    assert.throws(() => adapter.replace(trigger));
    assert.equal(objects.get(selection.key), object);
    assert.equal(adapter.snapshot().counters.replacements, 0);
  }
  adapter.replace(adapter.trigger);
  const replacement = objects.get(selection.key);
  assert.throws(() => adapter.replace(adapter.trigger));
  assert.equal(objects.get(selection.key), replacement);
  assert.equal(adapter.snapshot().counters.replacements, 1);
});

test('actual source drift refuses replacement before any write', () => {
  const { objects, selection, adapter } = setup();
  const changed = { bytes: Buffer.from('different actual bytes'), version: 'other', etag: '"other"' };
  objects.set(selection.key, changed);
  assert.throws(() => adapter.replace(adapter.trigger));
  assert.equal(objects.get(selection.key), changed);
  assert.equal(adapter.snapshot().counters.replacements, 0);
});

test('an explicit arm changes only the first selected actual read without a scheduling hold', async () => {
  const { adapter, selection, object } = setup();
  const server = await listen((request, response) => {
    if (!adapter.read(request, response)) response.writeHead(418).end();
  });
  try {
    adapter.arm(adapter.trigger);
    assert.throws(() => adapter.arm(adapter.trigger));
    assert.equal(adapter.snapshot().counters.replacements, 0);
    const foreign = await fetch(`${server.origin}/fixture-bucket/other`);
    assert.equal(foreign.status, 418);
    assert.equal(adapter.snapshot().counters.replacements, 0);
    const first = await fetch(`${server.origin}/${selection.bucket}/${selection.key}`, {
      headers: { 'If-Match': object.etag },
    });
    assert.equal(first.status, 412);
    assert.equal(adapter.snapshot().counters.replacements, 1);
    const second = await fetch(`${server.origin}/${selection.bucket}/${selection.key}`, {
      headers: { 'If-Match': object.etag },
    });
    assert.equal(second.status, 412);
    assert.equal(adapter.snapshot().counters.replacements, 1);
  } finally {
    await server.close();
  }
});

test('unguarded reads expose actual changed bytes; extra versions refuse and foreign objects remain untouched', async () => {
  const { adapter, selection, object } = setup();
  const server = await listen((request, response) => {
    if (!adapter.read(request, response)) response.writeHead(418).end();
  });
  try {
    const path = `${server.origin}/${selection.bucket}/${selection.key}`;
    adapter.replace(adapter.trigger);
    const unconditional = await fetch(path);
    assert.equal(unconditional.status, 200);
    assert.notEqual(digest(Buffer.from(await unconditional.arrayBuffer())), digest(object.bytes));
    assert.equal(adapter.snapshot().observations[1].kind, 'unconditional_read');
    const duplicate = await fetch(`${path}?versionId=${object.version}&versionId=${object.version}`, {
      headers: { 'If-Match': object.etag },
    });
    assert.equal(duplicate.status, 400);
    assert.equal((await duplicate.arrayBuffer()).byteLength, 0);
    const foreign = await fetch(`${server.origin}/fixture-bucket/other?versionId=v`);
    assert.equal(foreign.status, 418);
    assert.equal(adapter.snapshot().counters.reads, 2);
  } finally {
    await server.close();
  }
});
