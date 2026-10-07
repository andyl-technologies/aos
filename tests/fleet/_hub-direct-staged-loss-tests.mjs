// Controlled transport tests only; they confer no provider qualification.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, chmod, open, readFile, writeFile, rm } from 'node:fs/promises';
import { createServer, request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { providerPositive, createStagedLoss, readBoundedStagedStream } from './_hub-direct-staged-loss.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const expected = { bucket: 'fixture', key: 'actual/key', uploadId: 'actual-upload' };
const complete = Buffer.from('<CompleteMultipartUploadResult><Location>https://fixture/actual/key</Location>'
  + '<Bucket>fixture</Bucket><Key>actual/key</Key><ETag>&quot;actual-etag&quot;</ETag></CompleteMultipartUploadResult>');

test('complete requires closed actual XML identity, not HTTP200', () => {
  assert.equal(providerPositive('source_complete', 200, complete, expected).ETag, '"actual-etag"');
  for (const body of [Buffer.from('<Error><Code>InternalError</Code></Error>'),
    Buffer.from(complete.toString().replace('actual/key</Key>', 'other/key</Key>')),
    Buffer.from(complete.toString().replace('</Bucket>', '</Bucket><Bucket>fixture</Bucket>')),
    Buffer.concat([complete, complete]), Buffer.from([0xff])]) {
    assert.throws(() => providerPositive('source_complete', 200, body, expected));
  }
  assert.throws(() => providerPositive('source_complete', 500, complete, expected));
  assert.throws(() => providerPositive('source_complete', 200, Buffer.alloc(65537), expected));
});

test('Create records real UploadId and Abort requires204 empty body', () => {
  const created = Buffer.from('<InitiateMultipartUploadResult><Bucket>fixture</Bucket>'
    + '<Key>actual/key</Key><UploadId>provider-issued</UploadId></InitiateMultipartUploadResult>');
  assert.equal(providerPositive('create', 200, created, { ...expected, uploadId: null }).UploadId, 'provider-issued');
  assert.deepEqual(providerPositive('abort', 204, Buffer.alloc(0), expected), { kind: 'abort', uploadId: 'actual-upload' });
  assert.throws(() => providerPositive('abort', 404, Buffer.alloc(0), expected));
  assert.throws(() => providerPositive('abort', 204, Buffer.from('body'), expected));
});

test('empty EOF observed after the original cutoff is not accepted', async () => {
  const stream = Readable.from([]);
  stream.complete = true;
  let samples = 0;
  const remaining = () => ++samples === 1 ? 1000 : 0;
  await assert.rejects(readBoundedStagedStream(stream, remaining), /eligible complete HTTP EOF/);
  assert.equal(samples, 2);
});

test('an original growing after its initial stat exceeds a fixed read bound', async () => {
  const root = await mkdtemp(join(tmpdir(), 'staged-loss-growth-'));
  await chmod(root, 0o700);
  const original = Buffer.from('{"controlled":"initial"}');
  const file = join(root, 'input-original.private.json');
  await writeFile(file, original, { flag: 'wx', mode: 0o600 });
  const probe = await open(file, 'r');
  const prototype = Object.getPrototypeOf(probe);
  const originalRead = prototype.read;
  await probe.close();
  let grew = false;
  try {
    prototype.read = async function growingOriginalRead(...arguments_) {
      if (!grew) {
        grew = true;
        await writeFile(file, Buffer.alloc(65537));
      }
      return originalRead.apply(this, arguments_);
    };
    await assert.rejects(createStagedLoss({ version: 1, kind: 'source_complete', originalSha256: sha(original),
      originalReference: { file, sha256: sha(original), byteSize: String(original.length) },
      method: 'POST', target: '/fixture/actual/key?uploadId=actual-upload', host: 'localhost',
      requestSha256: sha(Buffer.alloc(0)), requestBytes: '0', rawHeadersSha256: sha(Buffer.from('[]')),
      cutoffUnixMs: Date.now() + 5000, expected }, root, 3900), /original exceeds its retained bound/);
    assert.equal(grew, true);
  } finally {
    prototype.read = originalRead;
    await rm(root, { recursive: true, force: true });
  }
});

test('expiry during actual private retention refuses before upstream end', async () => {
  const root = await mkdtemp(join(tmpdir(), 'staged-loss-retention-'));
  await chmod(root, 0o700);
  const probe = await open(join(root, 'sync-probe'), 'wx', 0o600);
  const prototype = Object.getPrototypeOf(probe);
  const originalSync = prototype.sync;
  await probe.close();
  let slowNextSync = false;
  let localRequests = 0;
  let handlerError;
  let finished;
  const handlerFinished = new Promise(resolve => { finished = resolve; });
  const upstream = createServer((incoming, response) => {
    localRequests += 1;
    incoming.resume();
    response.writeHead(200, { 'content-length': complete.length });
    response.end(complete);
  });
  const listener = createServer();

  try {
    const original = Buffer.from('{"controlled":"retention cutoff"}');
    const originalFile = join(root, 'input-original.private.json');
    await writeFile(originalFile, original, { flag: 'wx', mode: 0o600 });
    await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
    await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
    const host = `127.0.0.1:${listener.address().port}`;
    const headers = ['Host', host, 'Content-Length', '0', 'Connection', 'close'];
    const loss = await createStagedLoss({ version: 1, kind: 'source_complete', originalSha256: sha(original),
      originalReference: { file: originalFile, sha256: sha(original), byteSize: String(original.length) },
      method: 'POST', target: '/fixture/actual/key?uploadId=actual-upload', host,
      requestSha256: sha(Buffer.alloc(0)), requestBytes: '0', rawHeadersSha256: sha(Buffer.from(JSON.stringify(headers))),
      cutoffUnixMs: Date.now() + 500, expected }, root, upstream.address().port);

    // This changes only the disposable test process's FileHandle method. It
    // delays a real private fsync after EOF, rather than fabricating a reply.
    prototype.sync = async function delayedPrivateSync() {
      if (slowNextSync) {
        slowNextSync = false;
        await new Promise(resolve => setTimeout(resolve, 700));
      }
      return originalSync.call(this);
    };
    slowNextSync = true;
    listener.on('request', async (incoming, response) => {
      try { await loss(incoming, response); } catch (error) { handlerError = error; response.destroy(); }
      finally { finished(); }
    });
    await new Promise(resolve => {
      const outgoing = request({ hostname: '127.0.0.1', port: listener.address().port,
        method: 'POST', path: '/fixture/actual/key?uploadId=actual-upload', headers });
      outgoing.on('error', resolve);
      outgoing.on('response', () => assert.fail('expired request must not be forwarded'));
      outgoing.end();
    });
    await handlerFinished;
    assert.match(handlerError.message, /expired before upstream dispatch/);
    const terminal = JSON.parse(await readFile(join(root, 'terminal.private.json')));
    assert.equal(terminal.upstreamEndInvocations, 0);
    assert.equal(localRequests, 0);
    assert.equal(terminal.providerDispatches, null);
    assert.equal(terminal.providerSettlement, null);
    assert.equal(terminal.outcome, 'unknown');
  } finally {
    prototype.sync = originalSync;
    listener.closeAllConnections();
    upstream.closeAllConnections();
    await Promise.all([new Promise(resolve => listener.close(resolve)), new Promise(resolve => upstream.close(resolve))]);
    await rm(root, { recursive: true, force: true });
  }
});

test('actual local response EOF is retained before one downstream loss; second arm refuses', async () => {
  const root = await mkdtemp(join(tmpdir(), 'staged-loss-'));
  await chmod(root, 0o700);
  let dispatches = 0;
  const upstream = createServer((incoming, response) => {
    dispatches += 1;
    incoming.resume();
    incoming.on('end', () => { response.writeHead(200, { 'content-length': complete.length }); response.end(complete); });
  });
  const listener = createServer();
  let observed;
  let failure;
  try {
    const original = Buffer.from('{"controlled":"original"}');
    const originalFile = join(root, 'input-original.private.json');
    await writeFile(originalFile, original, { flag: 'wx', mode: 0o600 });
    await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
    await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
    const host = `127.0.0.1:${listener.address().port}`;
    const headers = ['Host', host, 'Content-Length', '0', 'Connection', 'close'];
    const loss = await createStagedLoss({ version: 1, kind: 'source_complete', originalSha256: sha(original),
      originalReference: { file: originalFile, sha256: sha(original), byteSize: String(original.length) },
      method: 'POST', target: '/fixture/actual/key?uploadId=actual-upload', host,
      requestSha256: sha(Buffer.alloc(0)), requestBytes: '0', rawHeadersSha256: sha(Buffer.from(JSON.stringify(headers))),
      cutoffUnixMs: Date.now() + 2000, expected }, root, upstream.address().port);
    listener.on('request', async (incoming, response) => {
      try { observed = await loss(incoming, response); } catch (error) { failure = error; response.destroy(); }
    });
    await new Promise(resolve => {
      const outgoing = request({ hostname: '127.0.0.1', port: listener.address().port,
        method: 'POST', path: '/fixture/actual/key?uploadId=actual-upload', headers });
      outgoing.on('error', resolve);
      outgoing.on('response', () => assert.fail('selected positive must not reach caller'));
      outgoing.end();
    });
    // Terminal retention can complete after the socket loss. Wait only for the
    // actual handler; no provider or mutation is reissued by this test.
    const until = Date.now() + 1000;
    while (!observed && !failure && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 5));
    assert.ifError(failure);
    assert.equal(observed.upstreamEndInvocations, 1);
    assert.equal(observed.providerDispatches, null);
    assert.equal(dispatches, 1);
    assert.equal(observed.downstreamDestroyInvoked, true);
    assert.equal(observed.providerSettlement, null);
    assert.equal((await readFile(join(root, 'reply.private.bin'))).equals(complete), true);
    assert.equal(JSON.parse(await readFile(join(root, 'terminal.private.json'))).outcome, 'provider_positive_caller_reply_lost');
    await assert.rejects(loss({}, {}), /already consumed/);
  } finally {
    listener.closeAllConnections();
    upstream.closeAllConnections();
    await Promise.all([new Promise(resolve => listener.close(resolve)), new Promise(resolve => upstream.close(resolve))]);
    await rm(root, { recursive: true, force: true });
  }
});
