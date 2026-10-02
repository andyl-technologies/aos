// Exercise only bounded private socket dispatch with controlled callbacks.
// These cases do not observe genuine Worker SDK calls or provider effects.
const assert = require('node:assert/strict');
const { mkdtempSync, chmodSync, rmSync } = require('node:fs');
const { connect } = require('node:net');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { acceptanceRegistryServer } = require('./_hub-worker-runner.cjs');

async function fixture(callback, action, cleanupCallback) {
  const directory = mkdtempSync(path.join(tmpdir(), 'managed-runner-socket-'));
  chmodSync(directory, 0o700);
  const socketPath = path.join(directory, 'control.sock');
  const server = acceptanceRegistryServer({}, socketPath, {}, undefined, undefined,
    undefined, undefined, undefined, cleanupCallback, callback);
  await server.ready;
  const exchange = request => new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const chunks = [];
    socket.on('error', reject);
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch (error) { reject(error); }
    });
    socket.on('connect', () => socket.end(JSON.stringify(request)));
  });
  try {
    await action(exchange);
  } finally {
    await server.close();
    rmSync(directory, { recursive: true });
  }
}

test('GC and cleanup callbacks remain separate in the composed runner', async () => {
  let gcCalls = 0;
  let cleanupCalls = 0;
  await fixture(async request => {
    gcCalls += 1;
    return { version: 1, kind: request.kind };
  }, async exchange => {
    assert.deepEqual(await exchange({ version: 1, kind: 'managed-gc-snapshot' }),
      { version: 1, kind: 'managed-gc-snapshot' });
    assert.deepEqual(await exchange({ version: 1, kind: 'managed-oci-cleanup-fixture-install' }),
      { version: 1, status: 'stored' });
    assert.equal(gcCalls, 1);
    assert.equal(cleanupCalls, 1);
  }, async request => {
    cleanupCalls += 1;
    assert.equal(request.kind, 'managed-oci-cleanup-fixture-install');
    return { version: 1, status: 'stored' };
  });
});

test('optional absence refuses Managed routes', async () => {
  await fixture(undefined, async exchange => {
    assert.deepEqual(await exchange({ version: 1, kind: 'managed-gc-snapshot' }),
      { version: 1, status: 'refused' });
  });
});

test('selected callback receives exact request and actual bounded response bytes', async () => {
  const request = { version: 1, kind: 'managed-gc-snapshot', keys: ['selected/key'], claimIds: ['claim'] };
  const reply = { version: 1, kind: request.kind, guardReads: { 'selected/key': { sha256: 'b'.repeat(64) } } };
  await fixture(async actual => {
    assert.deepEqual(actual, request);
    return reply;
  }, async exchange => {
    assert.deepEqual(await exchange(request), reply);
  });
});

test('callback refusal is sanitized and response overflow refuses', async () => {
  for (const callback of [async () => { throw new Error('private diagnostic'); },
    async () => ({ body: 'x'.repeat(1024 * 1024) })]) {
    await fixture(callback, async exchange => {
      assert.deepEqual(await exchange({ version: 1, kind: 'managed-gc-positive-replay' }),
        { version: 1, status: 'refused' });
    });
  }
});

test('concurrent requests cannot initialize or dispatch a second observer', async () => {
  let entered;
  const began = new Promise(resolve => { entered = resolve; });
  let release;
  const held = new Promise(resolve => { release = resolve; });
  let calls = 0;
  await fixture(async () => {
    calls += 1;
    entered();
    await held;
    return { version: 1, observed: 'controlled' };
  }, async exchange => {
    const first = exchange({ version: 1, kind: 'managed-gc-snapshot' });
    await began;
    assert.deepEqual(await exchange({ version: 1, kind: 'managed-gc-positive-replay' }),
      { version: 1, status: 'refused' });
    release();
    assert.deepEqual(await first, { version: 1, observed: 'controlled' });
    assert.equal(calls, 1);
  });
});
