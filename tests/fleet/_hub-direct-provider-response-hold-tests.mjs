// Actual loopback transport tests; the fixture backend is not Garage authority.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { createServer, request } from 'node:http';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { createResponseHold } from './_hub-direct-provider-response-hold.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const TARGET = '/fresh-fixture/selected%2Fobject?versionId=actual-version';
const selection = { version: 1, target: TARGET, host: 's3.fleet.test', range: null };
const authorization = 'AWS4-HMAC-SHA256 Credential=test/20261002/garage/s3/aws4_request, '
  + 'SignedHeaders=host;if-match;x-amz-content-sha256;x-amz-date, Signature=' + 'a'.repeat(64);
const headers = { Host: 's3.fleet.test', 'If-Match': '"actual-etag"', Authorization: authorization,
  'x-amz-date': '20261002T010000Z', 'x-amz-content-sha256': sha(Buffer.alloc(0)) };

async function fixture(action, run) {
  const root = await fs.mkdtemp(join(tmpdir(), 'aos-response-hold-test-'));
  await fs.chmod(root, 0o700);
  const received = [];
  const backend = createServer((incoming, outgoing) => {
    received.push({ method: incoming.method, target: incoming.url, headers: incoming.headers });
    action(incoming, outgoing, received.length);
  });
  await new Promise(resolve => backend.listen(0, '127.0.0.1', resolve));
  const listener = await createResponseHold(root, { listen: 0, upstream: backend.address().port });
  try { await run({ root, listener, received, port: Number(listener.ready.listenAddress.split(':')[1]) }); }
  finally {
    await listener.close();
    backend.closeAllConnections();
    await new Promise(resolve => backend.close(resolve));
    await fs.rm(root, { recursive: true });
  }
}

function read(port, options = {}) {
  return new Promise((resolve, reject) => {
    const outgoing = request({ hostname: '127.0.0.1', port, method: options.method ?? 'GET',
      path: options.target ?? TARGET, headers: options.headers ?? headers, agent: false }, incoming => {
      const blocks = [];
      incoming.on('data', block => blocks.push(block));
      incoming.once('error', reject);
      incoming.once('end', () => resolve({ status: incoming.statusCode, headers: incoming.headers,
        body: Buffer.concat(blocks) }));
    });
    outgoing.once('error', reject);
    outgoing.end(options.body);
  });
}

function control(root, value) {
  return new Promise((resolve, reject) => {
    const socket = connect(join(root, 'control.sock'));
    const blocks = [];
    socket.once('connect', () => socket.end(typeof value === 'string' ? value : JSON.stringify(value)));
    socket.on('data', block => blocks.push(block));
    socket.once('end', () => resolve(JSON.parse(Buffer.concat(blocks).toString())));
    socket.once('error', reject);
  });
}

async function events(root) {
  const names = (await fs.readdir(root)).filter(name => name.startsWith('event-')).sort();
  return Promise.all(names.map(async name => JSON.parse(await fs.readFile(join(root, name)))));
}

async function calibrate(facts, body) {
  assert.equal((await control(facts.root, { version: 1, kind: 'calibrate', selection })).status, 'selected');
  const reply = await read(facts.port);
  assert.equal(reply.status, 200);
  assert.deepEqual(reply.body, body);
  const state = await control(facts.root, { version: 1, kind: 'state' });
  const receiptBytes = await fs.readFile(state.calibrated.path);
  assert.equal(sha(receiptBytes), state.calibrated.sha256);
  return { state, receipt: JSON.parse(receiptBytes) };
}

function armed(calibration, body, extra = {}) {
  return { version: 1, kind: 'arm', calibrationSha256: calibration.state.calibrated.sha256,
    expectedSourceBodySha256: sha(body), calibrationContextSha256: 'b'.repeat(64),
    holdUntilUnixMillis: Date.now() + 2000, ...extra };
}

const normal = body => (incoming, outgoing) => {
  assert.equal(incoming.headers.authorization, authorization);
  outgoing.writeHead(200, { ETag: '"actual-etag"', 'Content-Length': String(body.length) });
  outgoing.end(body);
};

function firstArm(body, extra = {}) {
  return { version: 1, kind: 'arm_first_response', selection: { version: 1,
    targetPrefix: '/actual-bucket/.aos-direct-qualification/' + 'c'.repeat(32) + '/.aos-direct-upload/', host: 's3.fleet.test' },
    expectedSourceBodySha256: sha(body), expectedSourceBodyBytes: String(body.length),
    selectionContextSha256: 'd'.repeat(64), holdUntilUnixMillis: Date.now() + 2000, ...extra };
}

const FIRST_TARGET = '/actual-bucket/.aos-direct-qualification/' + 'c'.repeat(32) + '/.aos-direct-upload/actual-session/placement/payload';

test('first actual matching response holds without prior GET or predicted session', async () => {
  const body = Buffer.from('independently retained real source');
  await fixture(normal(body), async facts => {
    assert.equal((await control(facts.root, firstArm(body))).status, 'armed');
    let offered = false;
    const child = request({ hostname: '127.0.0.1', port: facts.port, path: FIRST_TARGET,
      headers, agent: false }, () => { offered = true; });
    child.on('error', () => {});
    child.end();
    for (let count = 0; count < 100 && !(await events(facts.root)).some(row => row.kind === 'response_held'); count++) {
      await delay(5);
    }
    const state = await control(facts.root, { version: 1, kind: 'state' });
    assert.equal(state.calibrated, null);
    assert.equal(state.attempted, true);
    assert.equal(offered, false);
    const receipt = JSON.parse(await fs.readFile(state.firstResponse.path));
    assert.equal(receipt.identity.target, FIRST_TARGET);
    assert.equal(receipt.response.versionId, null);
    assert.equal(receipt.response.sha256, sha(body));
    assert.equal(facts.received.length, 1);
    child.destroy();
    // Once used, ordinary subsequent reads still forward; they are never a
    // second held attempt or a replacement positive qualification receipt.
    assert.deepEqual((await read(facts.port, { target: FIRST_TARGET })).body, body);
    assert.equal((await events(facts.root)).filter(row => row.kind === 'response_held').length, 1);
  });
});

test('first-response nonmatching source, size, status or etag forwards unchanged', async () => {
  const body = Buffer.from('expected source');
  for (const change of ['source', 'size', 'status', 'etag', 'unsigned', 'prefix']) {
    await fixture((incoming, outgoing) => {
      const actual = change === 'source' ? Buffer.from('different bytes')
        : change === 'size' ? Buffer.from('short') : body;
      outgoing.writeHead(change === 'status' ? 412 : 200, {
        ETag: change === 'etag' ? '"changed"' : '"actual-etag"', 'Content-Length': String(actual.length) });
      outgoing.end(actual);
    }, async facts => {
      await control(facts.root, firstArm(body));
      const reply = await read(facts.port, { target: change === 'prefix' ? TARGET : FIRST_TARGET,
        headers: change === 'unsigned' ? { Host: headers.Host, 'If-Match': headers['If-Match'] } : headers });
      assert.equal(reply.status, change === 'status' ? 412 : 200);
      assert.equal(reply.headers.etag, change === 'etag' ? '"changed"' : '"actual-etag"');
      assert.equal((await control(facts.root, { version: 1, kind: 'state' })).attempted, false);
      assert.equal((await events(facts.root)).some(row => row.kind === 'response_held'), false);
      assert.equal(facts.received.length, 1);
    });
  }
});

test('first-response arm rejects invalid size, source, ceiling, prefix and mixed modes', async () => {
  await fixture(normal(Buffer.from('small')), async facts => {
    for (const extra of [{ expectedSourceBodyBytes: '0' }, { expectedSourceBodyBytes: '65537' },
      { expectedSourceBodyBytes: 5 }, { expectedSourceBodySha256: 'invented' },
      { holdUntilUnixMillis: Date.now() - 1 }, { holdUntilUnixMillis: Date.now() + 40000 },
      { selection: { version: 1, targetPrefix: '/unsafe/../', host: headers.Host } }]) {
      assert.equal((await control(facts.root, firstArm(Buffer.from('small'), extra))).status, 'refused');
    }
    assert.equal((await control(facts.root, firstArm(Buffer.from('small')))).status, 'armed');
    assert.equal((await control(facts.root, firstArm(Buffer.from('small')))).status, 'refused');
    assert.equal((await control(facts.root, { version: 1, kind: 'calibrate', selection })).status, 'refused');
  });
});

test('first response preserves actual full presigned URI and optional version', async () => {
  const body = Buffer.from('first complete queried source');
  const target = FIRST_TARGET + '?versionId=actual-version&X-Amz-Algorithm=AWS4-HMAC-SHA256'
    + '&X-Amz-Credential=test%2F20261002%2Fgarage%2Fs3%2Faws4_request'
    + '&X-Amz-Date=20261002T010000Z&X-Amz-Expires=30&X-Amz-SignedHeaders=host%3Bif-match'
    + '&X-Amz-Signature=' + 'e'.repeat(64);
  await fixture((incoming, outgoing) => {
    assert.equal(incoming.url, target);
    outgoing.writeHead(200, { ETag: '"actual-etag"', 'x-amz-version-id': 'actual-version',
      'Content-Length': String(body.length) });
    outgoing.end(body);
  }, async facts => {
    await control(facts.root, firstArm(body, { holdUntilUnixMillis: Date.now() + 200 }));
    await assert.rejects(read(facts.port, { target,
      headers: { Host: headers.Host, 'If-Match': headers['If-Match'] } }));
    const state = await control(facts.root, { version: 1, kind: 'state' });
    const receipt = JSON.parse(await fs.readFile(state.firstResponse.path));
    assert.equal(receipt.identity.target, FIRST_TARGET + '?versionId=actual-version');
    assert.equal(receipt.identity.signingMode, 'query');
    assert.equal(receipt.response.versionId, 'actual-version');
    assert.equal(JSON.parse(await fs.readFile(receipt.requestFile.path)).target, target);
  });
});

test('actual forwarded signed target and complete response calibrate; absent version remains null', async () => {
  const body = Buffer.from('actual bounded upstream bytes');
  await fixture(normal(body), async facts => {
    const calibration = await calibrate(facts, body);
    assert.equal(facts.received[0].target, TARGET);
    assert.equal(facts.received[0].headers.host, headers.Host);
    assert.equal(facts.received[0].headers['if-match'], headers['If-Match']);
    assert.equal(calibration.receipt.response.versionId, null);
    assert.equal(calibration.receipt.response.sha256, sha(body));
    assert.equal(calibration.receipt.upstreamComplete, true);
    for (const key of ['requestFile', 'bodyFile', 'headersFile']) {
      const file = calibration.receipt[key];
      assert.equal(sha(await fs.readFile(file.path)), file.sha256);
      assert.equal((await fs.stat(file.path)).mode & 0o777, 0o600);
    }
    assert.equal((await fs.stat(join(facts.root, 'control.sock'))).mode & 0o777, 0o600);
  });
});

test('hold consumes real response but sends no headers or body; actual peer close is distinct', async () => {
  const body = Buffer.from('real response to withhold');
  await fixture(normal(body), async facts => {
    const calibration = await calibrate(facts, body);
    assert.equal((await control(facts.root, armed(calibration, body))).status, 'armed');
    let headersReceived = false;
    const child = request({ hostname: '127.0.0.1', port: facts.port, path: TARGET, headers,
      agent: false }, () => { headersReceived = true; });
    child.on('error', () => {});
    child.end();
    for (let attempt = 0; attempt < 100 && !(await events(facts.root)).some(row => row.kind === 'response_held'); attempt++) {
      await delay(5);
    }
    assert.equal(headersReceived, false);
    assert.equal(facts.received.length, 2);
    child.destroy();
    for (let attempt = 0; attempt < 100 && !(await events(facts.root)).some(row => row.kind === 'downstream_closed'); attempt++) {
      await delay(5);
    }
    const held = (await events(facts.root)).find(row => row.kind === 'response_held');
    assert.equal(held.downstreamOfferedBytes, '0');
    assert.equal(held.remoteDrain, null);
    assert.equal((await events(facts.root)).filter(row => row.kind === 'downstream_closed').length, 1);
    assert.equal((await control(facts.root, { version: 1, kind: 'state' })).attempted, true);
    await assert.rejects(read(facts.port));
    assert.equal(facts.received.length, 2, 'replay must not reach upstream');
  });
});

test('wrong body, etag, returned version or status refuses hold without a manufactured response', async () => {
  const original = Buffer.from('calibrated bytes');
  for (const change of ['body', 'etag', 'version', 'status']) {
    await fixture((incoming, outgoing, call) => {
      const body = call === 2 && change === 'body' ? Buffer.from('different bytes!') : original;
      outgoing.writeHead(call === 2 && change === 'status' ? 412 : 200, {
        ETag: call === 2 && change === 'etag' ? '"different-etag"' : '"actual-etag"',
        'Content-Length': String(body.length),
        ...(call === 2 && change === 'version' ? { 'x-amz-version-id': 'changed-version' } : {}) });
      outgoing.end(body);
    }, async facts => {
      const calibration = await calibrate(facts, original);
      await control(facts.root, armed(calibration, original));
      await assert.rejects(read(facts.port));
      assert.equal(facts.received.length, 2);
      assert.equal((await events(facts.root)).some(row => row.kind === 'response_held'), false);
      assert.equal((await events(facts.root)).some(row => row.kind === 'selected_refused'), true);
    });
  }
});

test('arm refuses invented calibration, source mismatch, expired or extended deadline and extra fields', async () => {
  const body = Buffer.from('bounded');
  await fixture(normal(body), async facts => {
    const calibration = await calibrate(facts, body);
    for (const change of [{ calibrationSha256: '0'.repeat(64) },
      { expectedSourceBodySha256: '0'.repeat(64) }, { holdUntilUnixMillis: Date.now() - 1 },
      { holdUntilUnixMillis: Date.now() + 36000 }, { accept: true }]) {
      assert.equal((await control(facts.root, armed(calibration, body, change))).status, 'refused');
    }
    assert.equal((await control(facts.root, armed(calibration, body))).status, 'armed');
    assert.equal((await control(facts.root, armed(calibration, body))).status, 'refused');
    assert.equal(facts.received.length, 1);
  });
});

test('unsigned or weak conditional selected original refuses before upstream dispatch', async () => {
  for (const changed of [{ ...headers, 'If-Match': 'W/"actual-etag"' },
    { ...headers, Authorization: authorization.replace('host;if-match;', 'host;') }]) {
    await fixture(normal(Buffer.from('body')), async facts => {
      await control(facts.root, { version: 1, kind: 'calibrate', selection });
      await assert.rejects(read(facts.port, { headers: changed }));
      assert.equal(facts.received.length, 0);
      assert.equal((await control(facts.root, { version: 1, kind: 'state' })).calibrated, null);
    });
  }
});

test('selected body over64KiB or truncated transport cannot produce calibration', async () => {
  for (const truncated of [false, true]) {
    await fixture((incoming, outgoing) => {
      const body = Buffer.alloc(truncated ? 5 : 65537);
      outgoing.writeHead(200, { ETag: '"actual-etag"', 'Content-Length': truncated ? '6' : String(body.length) });
      outgoing.write(body);
      if (truncated) outgoing.socket.destroy(); else outgoing.end();
    }, async facts => {
      await control(facts.root, { version: 1, kind: 'calibrate', selection });
      await assert.rejects(read(facts.port));
      assert.equal((await control(facts.root, { version: 1, kind: 'state' })).calibrated, null);
    });
  }
});

test('ordinary unselected write streams unchanged; no selected-only body inventory is invented', async () => {
  const body = Buffer.alloc(262144, 7);
  await fixture((incoming, outgoing) => {
    const blocks = [];
    incoming.on('data', block => blocks.push(block));
    incoming.once('end', () => {
      assert.deepEqual(Buffer.concat(blocks), body);
      outgoing.writeHead(201, { ETag: '"other-object"' });
      outgoing.end('ordinary actual response');
    });
  }, async facts => {
    const reply = await read(facts.port, { method: 'PUT', target: '/ordinary-object', body,
      headers: { Host: 's3.fleet.test', 'Content-Length': String(body.length), Authorization: authorization } });
    assert.equal(reply.status, 201);
    assert.equal(reply.body.toString(), 'ordinary actual response');
    assert.deepEqual((await fs.readdir(facts.root)).sort(),
      ['command-line.private', 'control.sock', 'environment.private', 'ready.json']);
  });
});

test('closed control rejects duplicate fields and unknown selections without changing state', async () => {
  await fixture(normal(Buffer.from('body')), async facts => {
    assert.equal((await control(facts.root, '{"version":1,"version":1,"kind":"state"}')).status, 'refused');
    assert.equal((await control(facts.root, { version: 1, kind: 'calibrate',
      selection: { ...selection, accepts: true } })).status, 'refused');
    assert.equal((await control(facts.root, { version: 1, kind: 'state' })).calibrated, null);
    assert.equal(facts.received.length, 0);
  });
});

test('fixture hold ceiling ends a held response without an HTTP error substitute or second request', async () => {
  const body = Buffer.from('selected actual response');
  await fixture(normal(body), async facts => {
    const calibration = await calibrate(facts, body);
    await control(facts.root, armed(calibration, body, { holdUntilUnixMillis: Date.now() + 200 }));
    await assert.rejects(read(facts.port));
    const rows = await events(facts.root);
    assert.equal(rows.filter(row => row.kind === 'response_held').length, 1);
    assert.equal(rows.filter(row => row.kind === 'hold_deadline_reached').length, 1);
    assert.equal(rows.find(row => row.kind === 'hold_deadline_reached').remoteDrain, null);
    assert.equal(facts.received.length, 2);
  });
});

test('actual ranged response retains partial identity separately from whole object/version', async () => {
  const body = Buffer.from('part');
  await fixture((incoming, outgoing) => {
    assert.equal(incoming.headers.range, 'bytes=4-7');
    outgoing.writeHead(206, { ETag: '"actual-etag"', 'x-amz-version-id': 'real-provider-version',
      'Content-Range': 'bytes 4-7/20', 'Content-Length': '4' });
    outgoing.end(body);
  }, async facts => {
    await control(facts.root, { version: 1, kind: 'calibrate', selection: { ...selection, range: 'bytes=4-7' } });
    const reply = await read(facts.port, { headers: { ...headers, Range: 'bytes=4-7',
      Authorization: authorization.replace('host;if-match;', 'host;if-match;range;') } });
    assert.equal(reply.status, 206);
    const state = await control(facts.root, { version: 1, kind: 'state' });
    const receipt = JSON.parse(await fs.readFile(state.calibrated.path));
    assert.equal(receipt.response.contentRange, 'bytes 4-7/20');
    assert.equal(receipt.response.byteSize, '4');
    assert.equal(receipt.response.versionId, 'real-provider-version');
    assert.equal(receipt.response.sha256, sha(body));
  });
});

test('source-supported query signing preserves raw URI while fresh signature/date remain separate', async () => {
  const body = Buffer.from('conditional stored bytes');
  const query = signature => '?versionId=actual-version&X-Amz-Algorithm=AWS4-HMAC-SHA256'
    + '&X-Amz-Credential=test%2F20261002%2Fgarage%2Fs3%2Faws4_request'
    + '&X-Amz-Date=20261002T010000Z&X-Amz-Expires=30&X-Amz-SignedHeaders=host%3Bif-match'
    + '&X-Amz-Signature=' + signature;
  const target = signature => '/fresh-fixture/selected%2Fobject' + query(signature);
  const signedHeaders = { Host: 's3.fleet.test', 'If-Match': '"actual-etag"' };
  await fixture((incoming, outgoing) => {
    assert.equal(incoming.headers.authorization, undefined);
    outgoing.writeHead(200, { ETag: '"actual-etag"', 'Content-Length': String(body.length) });
    outgoing.end(body);
  }, async facts => {
    await control(facts.root, { version: 1, kind: 'calibrate', selection });
    assert.deepEqual((await read(facts.port, { target: target('c'.repeat(64)), headers: signedHeaders })).body, body);
    const state = await control(facts.root, { version: 1, kind: 'state' });
    const receipt = JSON.parse(await fs.readFile(state.calibrated.path));
    assert.equal(receipt.identity.target, TARGET);
    assert.equal(receipt.identity.signingMode, 'query');
    assert.equal(facts.received[0].target, target('c'.repeat(64)));
    await control(facts.root, armed({ state, receipt }, body, { holdUntilUnixMillis: Date.now() + 200 }));
    await assert.rejects(read(facts.port, { target: target('d'.repeat(64)), headers: signedHeaders }));
    assert.equal(facts.received[1].target, target('d'.repeat(64)));
    assert.equal((await events(facts.root)).filter(row => row.kind === 'response_held').length, 1);
  });
});
