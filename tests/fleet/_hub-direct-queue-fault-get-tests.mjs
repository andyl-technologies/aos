// Controlled local peers test exact forwarding and lifecycle, not provider auth.
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createGetOwner, selectedGet } from './_hub-direct-queue-fault-get.mjs';

const signature = `AWS4-HMAC-SHA256 Credential=synthetic/20261006/garage/s3/aws4_request, SignedHeaders=host;if-match;x-amz-content-sha256;x-amz-date, Signature=${'a'.repeat(64)}`;
const headers = ['Host', 's3.fleet.test', 'If-Match', '"old"', 'Authorization', signature,
  'X-Amz-Date', '20261006T000000Z', 'X-Amz-Content-Sha256', 'b'.repeat(64), 'Connection', 'close'];
const selection = deadline => ({ version: 1, runDigest: 'c'.repeat(64), host: 's3.fleet.test',
  path: '/fleet-s3/fixture/payload', sourceSha256: 'd'.repeat(64),
  fullObjectBytes: '8388608', cutoffUnixMs: deadline });
const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function fixture(action) {
  const root = await fs.mkdtemp(join(tmpdir(), 'queue-get-'));
  await fs.chmod(root, 0o700);
  const seen = [];
  const peer = createServer((incoming, reply) => {
    seen.push({ method: incoming.method, url: incoming.url, rawHeaders: incoming.rawHeaders });
    reply.writeHead(412, { 'content-type': 'application/xml' });
    reply.end('<Error><Code>PreconditionFailed</Code></Error>');
  });
  await new Promise(resolve => peer.listen(0, '127.0.0.1', resolve));
  let owner;
  try {
    owner = await createGetOwner(root, { listen: 0, upstream: peer.address().port });
    await action(owner, seen);
  } finally {
    await owner?.close();
    peer.closeAllConnections();
    await new Promise(resolve => peer.close(resolve));
    await fs.rm(root, { recursive: true, force: true });
  }
}

function send(owner, path = '/fleet-s3/fixture/payload') {
  let socket;
  const result = new Promise((resolve, reject) => {
    socket = request({ hostname: '127.0.0.1', port: Number(owner.ready.listenAddress.split(':')[1]),
      method: 'GET', path, headers }, response => {
      const pieces = [];
      response.on('data', piece => pieces.push(piece));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(pieces) }));
      response.on('error', reject);
    });
    socket.on('error', reject);
    socket.end();
  });
  // Attach immediately: expected disconnect must never become an unhandled rejection.
  result.catch(() => {});
  return { socket, result };
}

async function held(owner) {
  const stop = Date.now() + 1000;
  while (!owner.observe().events.some(row => row.kind === 'get_held_before_forward')) {
    if (Date.now() >= stop) throw new Error('controlled peer did not reach held boundary');
    await wait(5);
  }
}

test('selected GET is owned before forwarding; exact signature/Host/URI and real reply survive', async () => {
  await fixture(async (owner, seen) => {
    owner.arm(selection(Date.now() + 1000));
    const call = send(owner);
    try {
      await held(owner);
      assert.equal(seen.length, 0);
      assert.equal(owner.observe().events[0].upstreamOpened, false);
      owner.release('explicit');
      const reply = await call.result;
      assert.equal(reply.status, 412);
      assert.match(reply.body.toString(), /PreconditionFailed/);
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0], { method: 'GET', url: '/fleet-s3/fixture/payload', rawHeaders: headers });
    } finally { owner.release('test_cleanup'); call.socket.destroy(); }
  });
});

test('unselected path forwards once; expired or disconnected hold never opens upstream', async () => {
  await fixture(async (owner, seen) => {
    owner.arm(selection(Date.now() + 60));
    assert.equal((await send(owner, '/fleet-s3/unselected').result).status, 412);
    const call = send(owner);
    try {
      await held(owner);
      call.socket.destroy();
      await assert.rejects(call.result);
      await wait(70);
      assert.equal(seen.length, 1);
      assert.equal(owner.observe().held.reason, 'downstream_closed');
      assert.throws(() => owner.arm(selection(Date.now() + 1000)));
    } finally { owner.release('test_cleanup'); call.socket.destroy(); }
  });
});

test('wrong condition/version/framing refuses selected interception', () => {
  const selected = selection(Date.now() + 1000);
  for (const raw of [headers.filter((_, index) => index < 2 || index > 3),
    [...headers, 'If-Match', '"other"'], [...headers, 'Range', 'bytes=0-1'],
    headers.map(value => value === signature ? signature.replace('host;if-match;', 'host;') : value)]) {
    assert.throws(() => selectedGet({ method: 'GET', url: selected.path, rawHeaders: raw }, selected));
  }
  const observed = selectedGet({ method: 'GET', url: `${selected.path}?versionId=actual-version`, rawHeaders: headers }, selected);
  assert.equal(observed.providerVersion, 'actual-version');
  assert.equal(observed.ifMatch, '"old"');
  for (const query of ['versionId=null', 'versionId=', 'versionId=a&versionId=b', 'X-Amz-Signature=secret']) {
    assert.throws(() => selectedGet({ method: 'GET', url: `${selected.path}?${query}`, rawHeaders: headers }, selected));
  }
  assert.equal(selectedGet({ method: 'PUT', url: selected.path, rawHeaders: headers }, selected), null);
});

test('original cutoff closes held transport without forwarding or synthesizing a denial', async () => {
  await fixture(async (owner, seen) => {
    owner.arm(selection(Date.now() + 60));
    const call = send(owner);
    try {
      await held(owner);
      await assert.rejects(call.result);
      assert.equal(seen.length, 0);
      assert.equal(owner.observe().held.reason, 'deadline');
    } finally { owner.release('test_cleanup'); call.socket.destroy(); }
  });
});

test('ready record remains absent during actual delayed fsync and publishes one stable private inode', { timeout: 5000 }, async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'queue-ready-'));
  await fs.chmod(root, 0o700);
  const originalOpen = fs.open;
  let releaseSync;
  let enteredSync;
  const blocked = new Promise(resolve => { releaseSync = resolve; });
  const reached = new Promise(resolve => { enteredSync = resolve; });
  fs.open = async (...arguments_) => {
    const file = await originalOpen(...arguments_);
    if (arguments_[0] === `${root}/ready.pending`) {
      const synchronize = file.sync.bind(file);
      file.sync = async () => { enteredSync(); await blocked; return synchronize(); };
    }
    return file;
  };
  let owner;
  const starting = createGetOwner(root, { listen: 0, upstream: 3903 });
  try {
    await reached;
    await assert.rejects(fs.lstat(`${root}/ready.json`), { code: 'ENOENT' });
    assert.equal((await fs.lstat(`${root}/ready.pending`)).mode & 0o777, 0o600);
    releaseSync();
    owner = await starting;
    const final = await fs.lstat(`${root}/ready.json`);
    assert.equal(final.nlink, 1);
    assert.equal(final.mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await fs.readFile(`${root}/ready.json`, 'utf8')), owner.ready);
    await assert.rejects(fs.lstat(`${root}/ready.pending`), { code: 'ENOENT' });
  } finally {
    releaseSync();
    fs.open = originalOpen;
    owner ??= await starting;
    await owner.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});
