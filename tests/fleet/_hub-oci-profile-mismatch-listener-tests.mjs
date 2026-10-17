// Controlled loopback transports only; no Worker/R2 or authentication claim.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { startListener, ROUTE } from './_hub-oci-profile-mismatch-listener.mjs';

function command(file, value) {
  return new Promise((resolve, reject) => {
    const peer = net.connect(file); let data = '';
    peer.on('connect', () => peer.end(JSON.stringify(value) + '\n'));
    peer.on('data', chunk => { data += chunk; });
    peer.on('end', () => { try { resolve(JSON.parse(data)); } catch (error) { reject(error); } });
    peer.on('error', reject);
  });
}

function post(port, body, extra = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port, path: ROUTE, method: 'POST',
      headers: { host: 'localhost:4643', 'content-length': String(body.length),
        'x-aos-oci-projection-signature': 'f'.repeat(64), 'x-aos-storage-call-id': 'preserved-call', ...extra } }, response => {
      let data = ''; response.on('data', chunk => { data += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body: data }));
    });
    request.on('error', reject); request.end(body);
  });
}

async function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oci-profile-source-'));
  fs.chmodSync(root, 0o700);
  const calls = { a: [], b: [] };
  async function upstream(mode) {
    const server = http.createServer(async (request, response) => {
      const chunks = []; for await (const chunk of request) chunks.push(chunk);
      calls[mode].push({ body: Buffer.concat(chunks), rawHeaders: request.rawHeaders });
      response.writeHead(mode === 'b' ? 409 : 200, { 'content-type': 'application/json' }).end('{}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return server;
  }
  const a = await upstream('a'), b = await upstream('b');
  const listener = await startListener({ version: 1, root, listenPort: 0,
    upstreamAPort: a.address().port, upstreamBPort: b.address().port, originHost: 'localhost:4643' });
  const selection = { version: 1, capture_id: 'a'.repeat(32), placement_prefix: 'real/prefix',
    document_digest: 'sha256:' + 'b'.repeat(64), protected_profile_digest: 'c'.repeat(64),
    source_digest: 'd'.repeat(64), script_version: 'source-bound-script' };
  const now = Math.floor(Date.now() / 1000);
  const original = { version: 1, key: 'real/prefix/oci/uploads/actual/chunks/0',
    admission: { placement_prefix: 'real/prefix', staging_object_key: 'oci/uploads/actual/chunks/0' },
    descriptor: { digest: selection.document_digest }, nonce: 'e'.repeat(64),
    protected_profile_digest: selection.protected_profile_digest,
    issuer: { source_digest: selection.source_digest, script_version: selection.script_version },
    issued_at: now, expires_at: now + 30, clock_uncertainty_seconds: 1 };
  const control = value => command(path.join(root, 'control.sock'), value);
  const close = async () => {
    await listener.close();
    await Promise.all([new Promise(resolve => a.close(resolve)), new Promise(resolve => b.close(resolve))]);
    fs.rmSync(root, { recursive: true });
  };
  return { root, calls, listener, selection, original, control, close };
}

async function held(f) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const status = await f.control({ version: 1, kind: 'status' });
    if (status.state === 'held') return status;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error('controlled rendezvous missing');
}

test('unarmed ordinary path retains exact body, MAC and call headers', async () => {
  const f = await fixture();
  try {
    const body = Buffer.from(JSON.stringify(f.original));
    assert.equal((await post(f.listener.server.address().port, body)).status, 200);
    assert.deepEqual(f.calls.a[0].body, body);
    assert.ok(f.calls.a[0].rawHeaders.includes('preserved-call'));
    assert.equal(f.calls.b.length, 0);
  } finally { await f.close(); }
});

test('one actual retained original releases identical bytes once to B', async () => {
  const f = await fixture();
  try {
    await f.control({ version: 1, kind: 'arm', selection: f.selection });
    const body = Buffer.from(JSON.stringify(f.original));
    const reply = post(f.listener.server.address().port, body);
    const status = await held(f);
    assert.equal(f.calls.a.length + f.calls.b.length, 0);
    assert.deepEqual(fs.readFileSync(status.original.originalFile), body);
    assert.equal(status.original.requestSha256, crypto.createHash('sha256').update(body).digest('hex'));
    assert.equal((await f.control({ version: 1, kind: 'release', requestSha256: status.original.requestSha256,
      nonce: status.original.nonce })).state, 'released');
    assert.equal((await reply).status, 409);
    assert.deepEqual(f.calls.b[0].body, body);
    const terminalStatus = await f.control({ version: 1, kind: 'status' });
    assert.equal(terminalStatus.response.status, 409);
    const rawReply = fs.readFileSync(terminalStatus.response.bodyFile);
    assert.equal(rawReply.toString(), '{}');
    assert.equal(crypto.createHash('sha256').update(rawReply).digest('hex'), terminalStatus.response.bodySha256);
    assert.equal((await f.control({ version: 1, kind: 'release', requestSha256: status.original.requestSha256,
      nonce: status.original.nonce })).state, 'control_refused');
  } finally { await f.close(); }
});

test('expired original is not held, renewed or forwarded', async () => {
  const f = await fixture();
  try {
    await f.control({ version: 1, kind: 'arm', selection: f.selection });
    f.original.expires_at = f.original.issued_at;
    assert.equal((await post(f.listener.server.address().port, Buffer.from(JSON.stringify(f.original)))).status, 502);
    assert.equal(f.calls.a.length + f.calls.b.length, 0);
  } finally { await f.close(); }
});

test('wrong actual descriptor keeps A routing and does not fabricate a hold', async () => {
  const f = await fixture();
  try {
    await f.control({ version: 1, kind: 'arm', selection: f.selection });
    f.original.descriptor.digest = 'sha256:' + '1'.repeat(64);
    assert.equal((await post(f.listener.server.address().port, Buffer.from(JSON.stringify(f.original)))).status, 200);
    assert.equal((await f.control({ version: 1, kind: 'status' })).state, 'armed');
    assert.equal(f.calls.b.length, 0);
  } finally { await f.close(); }
});

test('caller cancellation leaves the original unknown without B forwarding', async () => {
  const f = await fixture();
  try {
    await f.control({ version: 1, kind: 'arm', selection: f.selection });
    const body = Buffer.from(JSON.stringify(f.original));
    const request = http.request({ host: '127.0.0.1', port: f.listener.server.address().port,
      path: ROUTE, method: 'POST', headers: { host: 'localhost:4643',
        'content-length': String(body.length), 'x-aos-oci-projection-signature': 'f'.repeat(64) } });
    request.on('error', () => {}); request.end(body);
    await held(f); request.destroy();
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal((await f.control({ version: 1, kind: 'status' })).state, 'unknown');
    assert.equal(f.calls.a.length + f.calls.b.length, 0);
    assert.ok(fs.existsSync(path.join(f.root, 'hold-unknown.json')));
  } finally { await f.close(); }
});
