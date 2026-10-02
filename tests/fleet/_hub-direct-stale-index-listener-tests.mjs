// Actual loopback TLS/socket gates with a controlled upstream, not Worker evidence.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startListener } from './_hub-direct-stale-index-listener.mjs';

const actualRequest = https.request.bind(https);
const directory = path.dirname(fileURLToPath(import.meta.url));
const openssl = process.argv[2];
assert.ok(openssl?.startsWith('/nix/store/'), 'select the source-built OpenSSL executable');

async function fixture({ delayUpstream = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aos-stale-index-tls-'));
  fs.chmodSync(root, 0o700);
  const certificateFile = path.join(root, 'certificate.pem');
  const privateKeyFile = path.join(root, 'key.pem');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', privateKeyFile, '-out', certificateFile], { stdio: 'ignore' });
  const configuration = { version: 1, root, listenPort: 0, upstreamHost: 'worker',
    upstreamPort: 443, originHost: 'aos.andyl.org', certificateFile, privateKeyFile,
    caFile: certificateFile, holdModuleFile: path.join(directory, '_hub-direct-stale-placement-hold.mjs') };
  const running = await startListener(configuration);
  const calls = [];
  const previous = https.request;
  https.request = (options, receive) => {
    const request = new EventEmitter();
    request.setTimeout = () => request;
    request.destroy = () => request;
    request.end = body => {
      const response = new PassThrough();
      calls.push({ options, body: Buffer.from(body), response });
      response.statusCode = 200;
      response.rawHeaders = ['Content-Type', 'application/json', 'Content-Length', '2'];
      receive(response);
      if (!delayUpstream) response.end('{}');
    };
    return request;
  };
  const context = { deployment_id: 'controlled-deployment', placement_id: 3,
    placement_resource_version: 4, binding_id: 5, binding_resource_version: 6,
    binding_kind: 'deployment_r2', placement_prefix: 'controlled/registry/' };
  const selection = { version: 1, originHost: configuration.originHost, ...context };
  const now = Math.floor(Date.now() / 1000);
  const original = { version: 1, plan_id: 'controlled-original', issued_at: now,
    expires_at: now + 30, ...context, operation: { kind: 'inspect_metadata', path: 'info/refs' } };
  function send(body, headers = {}, route = '/_internal/storage/v1/execute') {
    return new Promise((resolve, reject) => {
      const request = actualRequest({ hostname: '127.0.0.1', servername: 'localhost',
        port: running.server.address().port, ca: fs.readFileSync(certificateFile),
        path: route, method: 'POST', headers: { host: configuration.originHost,
          'content-type': 'application/json', 'content-length': String(body.length),
          'x-aos-storage-work-signature': 'a'.repeat(64),
          'x-aos-storage-call-id': 'controlled-call', 'x-aos-fleet-request-id': 'controlled-capture',
          ...headers } }, response => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      });
      request.on('error', reject);
      request.end(body);
    });
  }
  function control(request) {
    return new Promise((resolve, reject) => {
      const socket = net.connect(path.join(root, 'control.sock'));
      const bytes = [];
      socket.on('connect', () => socket.write(JSON.stringify(request) + '\n'));
      socket.on('data', chunk => bytes.push(chunk));
      socket.on('error', reject);
      socket.on('end', () => resolve(JSON.parse(Buffer.concat(bytes))));
    });
  }
  async function close() {
    running.close();
    https.request = previous;
    await new Promise(resolve => setImmediate(resolve));
    fs.rmSync(root, { recursive: true });
  }
  return { root, original, selection, calls, send, control, close };
}

async function waitHeld(current) {
  const deadline = Date.now() + 2000;
  while (Date.now() < deadline) {
    const observed = await current.control({ version: 1, kind: 'status' });
    if (observed.result.state === 'held') return observed.result;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error('controlled rendezvous was not observed');
}

test('TLS hold preserves exact body/signature/correlations and forwards only after release', async () => {
  const current = await fixture();
  try {
    await current.control({ version: 1, kind: 'arm', selection: current.selection });
    const body = Buffer.from(JSON.stringify(current.original));
    const terminal = current.send(body);
    const held = await waitHeld(current);
    assert.equal(current.calls.length, 0);
    assert.deepEqual(fs.readFileSync(path.join(current.root, 'hold/original-request.json')), body);
    assert.equal(held.requestSha256, crypto.createHash('sha256').update(body).digest('hex'));
    assert.equal((await current.control({ version: 1, kind: 'release', requestSha256: 'b'.repeat(64) })).status, 'refused');
    await current.control({ version: 1, kind: 'release', requestSha256: held.requestSha256 });
    assert.equal(await terminal, 200);
    assert.equal(current.calls.length, 1);
    assert.deepEqual(current.calls[0].body, body);
    const headers = current.calls[0].options.headers;
    for (const [name, value] of [['x-aos-storage-work-signature', 'a'.repeat(64)],
      ['x-aos-storage-call-id', 'controlled-call'], ['x-aos-fleet-request-id', 'controlled-capture']]) {
      assert.equal(headers[headers.indexOf(name) + 1], value);
    }
    assert.equal(current.calls[0].options.rejectUnauthorized, true);
    assert.equal((await current.control({ version: 1, kind: 'release', requestSha256: held.requestSha256 })).status, 'refused');
  } finally { await current.close(); }
});

test('unarmed and nonmatching plans preserve transport without an invented hold', async () => {
  const current = await fixture();
  try {
    const body = Buffer.from(JSON.stringify(current.original));
    assert.equal(await current.send(body), 200);
    await current.control({ version: 1, kind: 'arm', selection: current.selection });
    const other = Buffer.from(JSON.stringify({ ...current.original, placement_id: 99 }));
    assert.equal(await current.send(other), 200);
    assert.equal((await current.control({ version: 1, kind: 'status' })).result.state, 'unused');
    assert.deepEqual(current.calls.map(call => call.body), [body, other]);
  } finally { await current.close(); }
});

test('wrong route/origin and oversized framing never reach the upstream', async () => {
  const current = await fixture();
  try {
    assert.equal(await current.send(Buffer.from('{}'), {}, '/other'), 404);
    assert.equal(await current.send(Buffer.from('{}'), { host: 'other.test' }), 404);
    assert.equal(await current.send(Buffer.from('{}'), { 'content-length': String(1024 * 1024 + 1) }), 502);
    assert.equal(current.calls.length, 0);
  } finally { await current.close(); }
});

test('actual original expiry and explicit close retain unknown without forwarding', async () => {
  for (const kind of ['expiry', 'close']) {
    const current = await fixture();
    try {
      await current.control({ version: 1, kind: 'arm', selection: current.selection });
      if (kind === 'expiry') {
        current.original.issued_at = Math.floor(Date.now() / 1000) - 29;
        current.original.expires_at = current.original.issued_at + 30;
      }
      const terminal = current.send(Buffer.from(JSON.stringify(current.original)));
      const held = await waitHeld(current);
      if (kind === 'close') await current.control({ version: 1, kind: 'close' });
      assert.equal(await terminal, 502);
      assert.equal(current.calls.length, 0);
      assert.equal((await current.control({ version: 1, kind: 'status' })).result.state,
        kind === 'close' ? 'closed_unknown' : 'expired');
      assert.equal(fs.existsSync(path.join(current.root, 'hold/original-request.json')), true);
      assert.equal((await current.control({ version: 1, kind: 'release', requestSha256: held.requestSha256 })).status, 'refused');
    } finally { await current.close(); }
  }
});

test('128 concurrent execute transports cover overlap and retain the 129th refusal', async () => {
  const current = await fixture({ delayUpstream: true });
  try {
    const body = Buffer.from(JSON.stringify(current.original));
    const terminals = Array.from({ length: 129 }, () => current.send(body));
    const all = Promise.all(terminals);
    const deadline = Date.now() + 10000;
    let status;
    while (Date.now() < deadline) {
      status = (await current.control({ version: 1, kind: 'transport-status' })).result;
      if (status.active === 128 && status.capacityRefusals === 1) break;
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.equal(status.active, 128);
    assert.equal(current.calls.length, 128);
    assert.equal(status.requests, 129);
    assert.equal(status.capacityRefusals, 1);
    assert.equal(status.overflow, false);
    assert.equal(status.maximumRetainedRows, 204704);
    assert.equal(status.maximumRetainedBytes, 512 * 1024 * 1024);
    assert.equal(status.retainedRows, 129);
    const files = fs.readdirSync(current.root).filter(name => /^(dispatch|refused)-/.test(name));
    assert.equal(files.length, 129);
    assert.equal(status.retainedBytes,
      files.reduce((total, name) => total + fs.statSync(path.join(current.root, name)).size, 0));
    for (const call of current.calls) call.response.end('{}');
    const results = await all;
    assert.equal(results.filter(code => code === 200).length, 128);
    assert.equal(results.filter(code => code === 503).length, 1);
  } finally { await current.close(); }
});
