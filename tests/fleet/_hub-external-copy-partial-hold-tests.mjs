// Controlled HTTP transport test; no Garage/Copy/qualification evidence.
import assert from 'node:assert/strict';
import { mkdtemp, chmod, readFile, rm } from 'node:fs/promises';
import { createServer, request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createCopyPartialHold } from './_hub-external-copy-partial-hold.mjs';

const root = await mkdtemp(join(tmpdir(), 'aos-copy-partial-'));
console.log('Controlled attempt root:', root);
await chmod(root, 0o700);
const prefix = '/fleet-s3/.aos-direct-qualification/external-oci/' + 'a'.repeat(32) + '/registry/';
const other = '/fleet-s3/.aos-direct-qualification/external-oci/' + 'b'.repeat(32) + '/registry/';
const bytes = Buffer.alloc(256 * 1024, 71);
const provider = createServer((incoming, response) => {
  response.writeHead(206, { 'etag': '"actual-tag"', 'content-length': String(bytes.length),
    'content-range': `bytes 0-${bytes.length - 1}/${bytes.length}` });
  response.end(bytes);
});
await new Promise(resolve_ => provider.listen(0, '127.0.0.1', resolve_));
let listener, succeeded = false;
try {
  listener = await createCopyPartialHold({ version: 1, root, host: 's3.fleet.test',
    targetPrefixes: [prefix, other] }, { listen: 0, upstream: provider.address().port }, 'c'.repeat(64));
  const port = Number(listener.ready.listenAddress.split(':').at(-1));
  assert.match(listener.ready.executableSha256, /^[0-9a-f]{64}$/);
  await listener.command({ version: 1, kind: 'arm', targetPrefix: prefix, holdUntilUnixMillis: Date.now() + 10000 });
  await assert.rejects(listener.command({ version: 1, kind: 'arm', targetPrefix: prefix,
    holdUntilUnixMillis: Date.now() + 10000 }));
  const headers = { host: 's3.fleet.test', 'if-match': '"actual-tag"', range: `bytes=0-${bytes.length - 1}`,
    authorization: 'AWS4-HMAC-SHA256 Credential=controlled/20261002/region/s3/aws4_request, SignedHeaders=host;if-match;range, Signature=' + 'd'.repeat(64) };
  let received = 0;
  const blocks = [];
  let resolvePrefix, rejectPrefix;
  const prefixConsumed = new Promise((resolve_, reject) => { resolvePrefix = resolve_; rejectPrefix = reject; });
  const completed = new Promise((resolve_, reject) => {
    const sent = request({ hostname: '127.0.0.1', port, path: prefix + 'nar/actual', headers }, response => {
      assert.equal(response.statusCode, 206);
      assert.equal(response.headers.etag, '"actual-tag"');
      assert.equal(response.headers['content-length'], String(bytes.length));
      response.on('data', block => {
        received += block.length; blocks.push(block);
        if (received === 65536) resolvePrefix();
      });
      response.once('error', reject);
      response.once('end', resolve_);
    });
    sent.once('error', error => { rejectPrefix(error); reject(error); }); sent.end();
  });
  completed.catch(() => {});
  await prefixConsumed;
  // A separate pass-through request must not release the selected owner.
  await new Promise((resolve_, reject) => {
    const sent = request({ hostname: '127.0.0.1', port, path: '/ordinary' }, response => {
      response.resume(); response.once('end', resolve_);
    });
    sent.once('error', reject); sent.end();
  });
  let state;
  for (let count = 0; count < 100; count += 1) {
    state = await listener.command({ version: 1, kind: 'state', targetPrefix: prefix });
    if (state.pendingLocalHold) break;
    await new Promise(resolve_ => setTimeout(resolve_, 10));
  }
  assert.equal(received, 65536);
  assert.equal(state.pendingLocalHold, true);
  const retained = JSON.parse(await readFile(state.prefixReceipt.path));
  assert.equal(retained.workerConsumedBytes, null);
  assert.equal(retained.downstreamOfferedBytes, '65536');
  assert.equal(retained.prefixFile.sha256,
    createHash('sha256').update(bytes.subarray(0, 65536)).digest('hex'));
  await assert.rejects(listener.command({ version: 1, kind: 'release', targetPrefix: other }));
  await listener.command({ version: 1, kind: 'release', targetPrefix: prefix });
  await completed;
  assert.deepEqual(Buffer.concat(blocks), bytes);
  assert.equal((await listener.command({ version: 1, kind: 'state', targetPrefix: other })).selected, false);
  console.log('PASS controlled partial prefix/release/exact body and unrelated-owner isolation; no provider authority proof');
  succeeded = true;
} finally {
  await listener?.close();
  await new Promise(resolve_ => provider.close(resolve_));
  if (succeeded) await rm(root, { recursive: true });
  else console.error('Failed controlled attempt retained:', root);
}
