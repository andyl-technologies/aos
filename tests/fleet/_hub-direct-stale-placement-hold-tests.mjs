// Controlled transport gates, not real Native/Worker/provider acceptance.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { stalePlacementHold } from './_hub-direct-stale-placement-hold.mjs';

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aos-stale-hold-controlled-'));
  fs.chmodSync(directory, 0o700);
  const now = Math.floor(Date.now() / 1000);
  const context = {
    deployment_id: 'controlled-deployment', placement_id: 3, placement_resource_version: 4,
    binding_id: 5, binding_resource_version: 6, binding_kind: 'deployment_r2',
    placement_prefix: 'controlled/registry/',
  };
  const body = Buffer.from(JSON.stringify({
    version: 1, plan_id: 'controlled-original', issued_at: now, expires_at: now + 30,
    ...context, operation: { kind: 'inspect_metadata', path: 'info/refs' },
  }));
  const request = { method: 'POST', url: '/_internal/storage/v1/execute', headers: {
    host: 'worker.test', 'content-type': 'application/json',
    'content-length': String(body.length), 'x-aos-storage-work-signature': 'a'.repeat(64),
  } };
  return { directory, body, request,
    selection: { version: 1, originHost: 'worker.test', ...context } };
}

test('one actual loopback request waits, then preserves exact body/signature once', async () => {
  const current = fixture();
  const hold = stalePlacementHold(current.selection, current.directory);
  let dispatches = 0;
  let seen = null;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    try {
      assert.equal(await hold.beforeDispatch(request, body), true);
      dispatches += 1;
      seen = { body, signature: request.headers['x-aos-storage-work-signature'] };
      response.end('controlled upstream');
    } catch {
      response.destroy();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const terminal = new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port: server.address().port,
      path: current.request.url, method: 'POST', headers: current.request.headers }, response => {
      response.resume();
      response.on('end', resolve);
    });
    request.on('error', reject);
    request.end(current.body);
  });
  try {
    const deadline = Date.now() + 1000;
    while (hold.status().state !== 'held' && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 2));
    }
    const observed = hold.status();
    assert.equal(observed.state, 'held');
    assert.equal(dispatches, 0);
    assert.deepEqual(fs.readFileSync(path.join(current.directory, 'original-request.json')), current.body);
    assert.equal(fs.statSync(path.join(current.directory, 'original-request.json')).mode & 0o777, 0o600);
    assert.throws(() => hold.release('b'.repeat(64)), /original_mismatch/);
    hold.release(observed.requestSha256);
    await terminal;
    assert.equal(dispatches, 1);
    assert.deepEqual(seen.body, current.body);
    assert.equal(seen.signature, current.request.headers['x-aos-storage-work-signature']);
    assert.throws(() => hold.release(observed.requestSha256), /original_mismatch/);
  } finally {
    hold.close();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(current.directory, { recursive: true });
  }
});

test('unselected routes/context and oversized plans do not enter the barrier', async () => {
  const current = fixture();
  const hold = stalePlacementHold(current.selection, current.directory);
  try {
    assert.equal(await hold.beforeDispatch({ ...current.request, method: 'GET' }, current.body), false);
    const other = JSON.parse(current.body);
    other.placement_id += 1;
    assert.equal(await hold.beforeDispatch(current.request, Buffer.from(JSON.stringify(other))), false);
    assert.equal(await hold.beforeDispatch(current.request, Buffer.alloc(65537)), false);
    assert.equal(hold.status().state, 'unused');
    assert.equal(fs.existsSync(path.join(current.directory, 'original-request.json')), false);
  } finally {
    fs.rmSync(current.directory, { recursive: true });
  }
});

test('changed representation, signature or expired actual authorization refuses', async () => {
  for (const kind of ['duplicate', 'signature', 'expired']) {
    const current = fixture();
    const hold = stalePlacementHold(current.selection, current.directory);
    try {
      let body = current.body;
      if (kind === 'duplicate') body = Buffer.from(current.body.toString().replace('"version":1', '"version":1,"version":1'));
      if (kind === 'signature') current.request.headers['x-aos-storage-work-signature'] = 'not-a-signature';
      if (kind === 'expired') {
        const original = JSON.parse(body);
        original.issued_at -= 31;
        original.expires_at -= 31;
        body = Buffer.from(JSON.stringify(original));
      }
      current.request.headers['content-length'] = String(body.length);
      await assert.rejects(hold.beforeDispatch(current.request, body), /shape|time/);
      assert.equal(hold.status().state, 'unused');
    } finally {
      fs.rmSync(current.directory, { recursive: true });
    }
  }
});

test('changed held Buffer cannot dispatch after release', async () => {
  const current = fixture();
  const hold = stalePlacementHold(current.selection, current.directory);
  const waiting = hold.beforeDispatch(current.request, current.body);
  try {
    const observed = hold.status();
    current.body[0] = 0;
    hold.release(observed.requestSha256);
    await assert.rejects(waiting, /original_changed/);
    const retained = fs.readFileSync(path.join(current.directory, 'original-request.json'));
    assert.equal(crypto.createHash('sha256').update(retained).digest('hex'), observed.requestSha256);
  } finally {
    hold.close();
    fs.rmSync(current.directory, { recursive: true });
  }
});

test('actual expiry and owner close retain an original without automatic dispatch', async () => {
  for (const kind of ['expiry', 'close']) {
    const current = fixture();
    if (kind === 'expiry') {
      const original = JSON.parse(current.body);
      original.issued_at = Math.floor(Date.now() / 1000) - 29;
      original.expires_at = original.issued_at + 30;
      current.body = Buffer.from(JSON.stringify(original));
      current.request.headers['content-length'] = String(current.body.length);
    }
    const hold = stalePlacementHold(current.selection, current.directory);
    const waiting = hold.beforeDispatch(current.request, current.body);
    const refused = assert.rejects(waiting, /original_expired|closed_without_dispatch/);
    if (kind === 'close') hold.close();
    await refused;
    assert.equal(hold.status().state, kind === 'close' ? 'closed_unknown' : 'expired');
    assert.equal(fs.existsSync(path.join(current.directory, 'original-request.json')), true);
    assert.throws(() => hold.release(hold.status().requestSha256), /original_mismatch/);
    fs.rmSync(current.directory, { recursive: true });
  }
});
