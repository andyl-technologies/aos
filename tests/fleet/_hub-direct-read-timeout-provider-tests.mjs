// Actual loopback socket tests of the source adapter, without TLS/auth claims.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, request } from 'node:http';
import { test } from 'node:test';
import { readTimeoutProvider } from './_hub-direct-read-timeout-provider.mjs';

function fixture() {
  const runDigest = 'a'.repeat(64);
  const key = `.aos-direct-read-qualification/${runDigest}/timeout/object`;
  const bytes = Buffer.from('controlled completed read timeout source');
  const object = { bytes, version: 'actual-controlled-version', etag: '"actual-controlled-etag"' };
  const objects = new Map([[key, object]]);
  const selection = { version: 1, bucket: 'read-fixture', runDigest, key,
    expected: { version: object.version, etag: object.etag, byteSize: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex') } };
  const events = [];
  return { objects, selection, events, adapter: readTimeoutProvider(objects, selection, event => events.push(event)) };
}

test('one actual conditional GET receives no response bytes and records actual peer closure', async () => {
  const selected = fixture();
  let closed;
  const actualClose = new Promise(resolve => { closed = resolve; });
  const server = createServer((incoming, response) => {
    // This controlled test deliberately supplies no authentication assertion.
    assert.equal(selected.adapter.read(incoming, response), true);
    response.once('close', closed);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    let bytes = 0;
    await new Promise((resolve, reject) => {
      const client = request({ hostname: '127.0.0.1', port: server.address().port,
        path: '/read-fixture/' + selected.selection.key + '?versionId=actual-controlled-version',
        headers: { 'if-match': '"actual-controlled-etag"' } }, response => {
        response.on('data', chunk => { bytes += chunk.length; });
        response.once('end', () => reject(new Error('Unexpected completed response')));
      });
      client.once('socket', connection => connection.once('connect', () => {
        setTimeout(() => client.destroy(new Error('controlled peer timeout')), 20);
      }));
      client.once('error', resolve); client.end();
    });
    await actualClose;
    assert.equal(bytes, 0);
    assert.deepEqual(selected.events.map(event => event.kind), ['read_started', 'peer_closed']);
    assert.ok(BigInt(selected.events[1].elapsedNanoseconds) > 0n);
    assert.equal(selected.adapter.snapshot().reads, 1);
    assert.equal(selected.objects.get(selected.selection.key).version, selected.selection.expected.version);
    assert.throws(() => selected.adapter.read({ method: 'GET',
      url: '/read-fixture/' + selected.selection.key + '?versionId=actual-controlled-version',
      headers: { 'if-match': '"actual-controlled-etag"' } }, {}));
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('wrong namespace, replacement, conditional identity and replay cannot arm the timeout', () => {
  const selected = fixture();
  assert.throws(() => readTimeoutProvider(selected.objects, { ...selected.selection, key: 'ordinary/key' }, () => {}));
  const incoming = { method: 'GET', url: '/read-fixture/' + selected.selection.key + '?versionId=wrong',
    headers: { 'if-match': selected.selection.expected.etag } };
  assert.throws(() => selected.adapter.read(incoming, {}));
  assert.equal(selected.adapter.snapshot().reads, 0);
  assert.equal(selected.adapter.read({ ...incoming, method: 'PUT' }, {}), false);
  selected.objects.get(selected.selection.key).bytes[0] ^= 1;
  incoming.url = '/read-fixture/' + selected.selection.key + '?versionId=actual-controlled-version';
  assert.throws(() => selected.adapter.read(incoming, {}));
  assert.equal(selected.adapter.snapshot().reads, 0);
});
