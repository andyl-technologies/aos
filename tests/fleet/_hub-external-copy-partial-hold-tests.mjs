// Controlled HTTP transport test; no Garage/Copy/qualification evidence.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, chmod, readFile, rm } from 'node:fs/promises';
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
const inventoryBytes = Buffer.alloc(8388608 + bytes.length, 83);
const provider = createServer((incoming, response) => {
  const inventory = incoming.url.includes('/oci/blobs/sha256/');
  const range = /^bytes=([0-9]+)-([0-9]+)$/.exec(incoming.headers.range ?? '');
  const start = inventory && range ? Number(range[1]) : 0;
  const end = inventory && range ? Number(range[2]) : bytes.length - 1;
  const body = inventory ? inventoryBytes.subarray(start, end + 1) : bytes;
  response.writeHead(206, { 'etag': '"actual-tag"', 'content-length': String(body.length),
    'content-range': `bytes ${start}-${end}/${inventory ? inventoryBytes.length : bytes.length}` });
  response.end(body);
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
  // The continuation selector shares the immutable prefix but has its own
  // one-use state. A real first interval completes before the later hold.
  const sourceKey = prefix + 'oci/blobs/sha256/' + 'e'.repeat(64);
  await assert.rejects(listener.command({ version: 1, kind: 'arm_inventory', targetPrefix: prefix,
    sourceKey, rangeStart: 0, holdUntilUnixMillis: Date.now() + 10000 }));
  await assert.rejects(listener.command({ version: 1, kind: 'arm_inventory_after_first_range', targetPrefix: prefix,
    sourceKey, rangeStart: 8388608, fixtureCutoffUnixMillis: Date.now() - 1 }));
  const fixtureCutoff = Date.now() + 10000;
  await listener.command({ version: 1, kind: 'arm_inventory_after_first_range', targetPrefix: prefix,
    sourceKey, rangeStart: 8388608, fixtureCutoffUnixMillis: fixtureCutoff });

  function fetchRange(path, start, end, onBlock = null, selectedPort = port) {
    return new Promise((resolve_, reject) => {
      const selectedHeaders = { ...headers, range: `bytes=${start}-${end}` };
      const sent = request({ hostname: '127.0.0.1', port: selectedPort, path, headers: selectedHeaders }, response => {
        const chunks = [];
        response.on('data', block => { chunks.push(block); onBlock?.(block); });
        response.once('error', reject);
        response.once('end', () => resolve_({ body: Buffer.concat(chunks), headers: response.headers }));
      });
      sent.once('error', reject); sent.end();
    });
  }
  // An unobserved first interval, stale range or different key cannot activate
  // the deferred selector. The second range remains unchanged in each case.
  await fetchRange(sourceKey, 8388608, inventoryBytes.length - 1);
  await fetchRange(sourceKey, 65536, 8388607);
  await fetchRange(prefix + 'oci/blobs/sha256/' + 'f'.repeat(64), 0, 8388607);
  const waiting = await listener.command({ version: 1, kind: 'state_inventory', targetPrefix: prefix });
  assert.equal(waiting.awaitingFirstRange, true);
  assert.equal(waiting.holdUntilUnixMillis, null);
  assert.equal(waiting.firstRangeReceipt, null);
  const first = await fetchRange(sourceKey, 0, 8388607);
  assert.deepEqual(first.body, inventoryBytes.subarray(0, 8388608));
  assert.equal((await listener.command({ version: 1, kind: 'state_inventory', targetPrefix: prefix })).selected, false);
  await fetchRange(prefix + 'oci/blobs/sha256/' + 'f'.repeat(64), 8388608, inventoryBytes.length - 1);
  assert.equal((await listener.command({ version: 1, kind: 'state_inventory', targetPrefix: prefix })).selected, false);

  let inventoryReceived = 0, inventoryPrefix;
  const inventoryPrefixConsumed = new Promise(resolve_ => { inventoryPrefix = resolve_; });
  const heldInventory = fetchRange(sourceKey, 8388608, inventoryBytes.length - 1, block => {
    inventoryReceived += block.length;
    if (inventoryReceived === 65536) inventoryPrefix();
  });
  heldInventory.catch(() => {});
  await inventoryPrefixConsumed;
  let inventoryState;
  for (let count = 0; count < 100; count += 1) {
    inventoryState = await listener.command({ version: 1, kind: 'state_inventory', targetPrefix: prefix });
    if (inventoryState.pendingLocalHold) break;
    await new Promise(resolve_ => setTimeout(resolve_, 10));
  }
  assert.equal(inventoryState.pendingLocalHold, true);
  assert.equal(inventoryState.awaitingFirstRange, false);
  assert.equal(inventoryState.fixtureCutoffUnixMillis, fixtureCutoff);
  assert.ok(inventoryState.holdUntilUnixMillis <= fixtureCutoff);
  const firstRange = JSON.parse(await readFile(inventoryState.firstRangeReceipt.path));
  assert.equal(firstRange.identity.range, 'bytes=0-8388607');
  assert.equal(firstRange.responseBytes, '8388608');
  assert.equal(firstRange.responseSha256, createHash('sha256').update(inventoryBytes.subarray(0, 8388608)).digest('hex'));
  assert.equal(firstRange.upstreamComplete, true);
  assert.equal(inventoryReceived, 65536);
  const inventoryReceipt = JSON.parse(await readFile(inventoryState.prefixReceipt.path));
  const requestReceipt = JSON.parse(await readFile(inventoryReceipt.requestReceipt.path));
  assert.equal(requestReceipt.range, `bytes=8388608-${inventoryBytes.length - 1}`);
  assert.equal(requestReceipt.ifMatch, '"actual-tag"');
  assert.deepEqual(Object.keys(requestReceipt).sort(), ['host', 'ifMatch', 'method', 'range', 'targetSha256']);
  assert.equal(JSON.stringify(requestReceipt).includes('Credential='), false);
  await assert.rejects(listener.command({ version: 1, kind: 'arm_inventory', targetPrefix: prefix,
    sourceKey, rangeStart: 8388608, holdUntilUnixMillis: Date.now() + 10000 }));
  await listener.command({ version: 1, kind: 'release_inventory', targetPrefix: prefix });
  const delivered = await heldInventory;
  assert.deepEqual(delivered.body, inventoryBytes.subarray(8388608));
  assert.equal(delivered.headers['content-range'], `bytes 8388608-${inventoryBytes.length - 1}/${inventoryBytes.length}`);
  const resumed = await fetchRange(sourceKey, 8388608, inventoryBytes.length - 1);
  assert.deepEqual(resumed.body, inventoryBytes.subarray(8388608));
  for (let count = 0; count < 100; count += 1) {
    inventoryState = await listener.command({ version: 1, kind: 'state_inventory', targetPrefix: prefix });
    if (inventoryState.continuationReceipts.length === 1) break;
    await new Promise(resolve_ => setTimeout(resolve_, 10));
  }
  const continuation = JSON.parse(await readFile(inventoryState.continuationReceipts[0].path));
  assert.equal(continuation.responseBytes, String(inventoryBytes.length - 8388608));
  assert.equal(continuation.identity.range, requestReceipt.range);
  assert.equal(continuation.contentRange, delivered.headers['content-range']);
  assert.equal(continuation.responseSha256,
    createHash('sha256').update(inventoryBytes.subarray(8388608)).digest('hex'));
  assert.equal(continuation.upstreamComplete, true);
  assert.equal(continuation.workerConsumedBytes, null);
  assert.equal(continuation.remoteDrain, null);
  console.log('PASS exact inventory continuation selector, full first interval, bounded hold, private header projection and real resumed response');

  const expiryRoot = join(root, 'expiry');
  await mkdir(expiryRoot, { mode: 0o700 });
  const expired = await createCopyPartialHold({ version: 1, root: expiryRoot, host: 's3.fleet.test',
    targetPrefixes: [prefix] }, { listen: 0, upstream: provider.address().port }, 'c'.repeat(64));
  try {
    await expired.command({ version: 1, kind: 'arm_inventory_after_first_range', targetPrefix: prefix,
      sourceKey, rangeStart: 8388608, fixtureCutoffUnixMillis: Date.now() + 50 });
    await assert.rejects(expired.command({ version: 1, kind: 'arm_inventory_after_first_range', targetPrefix: prefix,
      sourceKey, rangeStart: 8388608, fixtureCutoffUnixMillis: Date.now() + 1000 }));
    await new Promise(resolve_ => setTimeout(resolve_, 60));
    const expiredPort = Number(expired.ready.listenAddress.split(':').at(-1));
    await fetchRange(sourceKey, 0, 8388607, null, expiredPort);
    const observedExpiry = await expired.command({ version: 1, kind: 'state_inventory', targetPrefix: prefix });
    assert.equal(observedExpiry.holdUntilUnixMillis, null);
    assert.equal(observedExpiry.firstRangeReceipt, null);
    assert.equal(observedExpiry.selected, false);
  } finally { await expired.close(); }
  console.log('PASS deferred arm requires its observed first range before original cutoff; no rearm or cutoff extension');

  // Closing the owned listener must terminate a selected local hold without
  // waiting for its ceiling or implying that the provider settled the read.
  const closingKey = other + 'oci/blobs/sha256/' + 'e'.repeat(64);
  await listener.command({ version: 1, kind: 'arm_inventory', targetPrefix: other,
    sourceKey: closingKey, rangeStart: 8388608, holdUntilUnixMillis: Date.now() + 10000 });
  let closingBytes = 0, resolveClosingPrefix;
  const closingPrefix = new Promise(resolve_ => { resolveClosingPrefix = resolve_; });
  const closingRequest = fetchRange(closingKey, 8388608, inventoryBytes.length - 1, block => {
    closingBytes += block.length;
    if (closingBytes === 65536) resolveClosingPrefix();
  });
  closingRequest.catch(() => {});
  await closingPrefix;
  for (let count = 0; count < 100; count += 1) {
    state = await listener.command({ version: 1, kind: 'state_inventory', targetPrefix: other });
    if (state.pendingLocalHold) break;
    await new Promise(resolve_ => setTimeout(resolve_, 10));
  }
  assert.equal(state.pendingLocalHold, true);
  assert.equal(state.providerSettlement, null);
  let closeDeadline;
  try {
    await Promise.race([listener.close(), new Promise((_, reject) => {
      closeDeadline = setTimeout(() => reject(new Error('Owned hold cleanup exceeded bound')), 2000);
    })]);
  } finally {
    clearTimeout(closeDeadline);
  }
  listener = null;
  await assert.rejects(closingRequest);
  assert.equal(closingBytes, 65536);
  console.log('PASS owned listener close terminates its partial inventory hold; remote settlement remains unknown');
  console.log('PASS controlled partial prefix/release/exact body and unrelated-owner isolation; no provider authority proof');
  succeeded = true;
} finally {
  await listener?.close();
  await new Promise(resolve_ => provider.close(resolve_));
  if (succeeded) await rm(root, { recursive: true });
  else console.error('Failed controlled attempt retained:', root);
}
