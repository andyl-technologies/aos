/** One localhost real-browser harness; it does not imitate an AOS application. */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import * as fs from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { digest, withBrowser } from './_hub-direct-browser-cdp.mjs';

assert.deepEqual(process.argv.slice(2), ['--run-local-browser-harness']);
// The reviewed AOS timeout wrapper covers this whole process (55s + 5s kill).
// The client reserves the final 15s of this 55s deadline for browser cleanup.
const startedUnixMillis = Date.now();
const lifetimeDeadline = startedUnixMillis + 55000;
const runId = randomBytes(16).toString('hex');
const inputDirectory = `/tmp/aos-direct-browser-harness-${runId}`;
await fs.mkdir(inputDirectory, { mode: 0o700 });
const fixture = Buffer.from('bounded-browser-file');
const file = path.join(inputDirectory, 'source.bin');
await fs.writeFile(file, fixture, { mode: 0o600, flag: 'wx' });
const observed = { uploads: 0, uploadedSha256: null, abortedResponseClosed: false };
let origin;
const sockets = new Set();

function track(server) {
  server.on('connection', socket => {
    assert.ok(sockets.size < 32);
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  return server;
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
}

const provider = track(createServer((request, response) => {
  if (request.url === '/cors') {
    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Access-Control-Expose-Headers', 'ETag');
    response.setHeader('ETag', '"local-fixture"');
    response.end(fixture);
  } else if (request.url === '/cors-refused') {
    response.end('not exposed to the calling origin');
  } else {
    response.writeHead(404).end();
  }
}));

const server = track(createServer(async (request, response) => {
  if (request.url === '/' && request.method === 'GET') {
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    response.end('<!doctype html><title>CDP localhost harness</title><input type="file" id="fixture"><p>Local browser mechanics only.</p>');
    return;
  }
  if (request.url === '/upload' && request.method === 'PUT') {
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > 1024) { request.destroy(); return; }
      chunks.push(chunk);
    }
    observed.uploads += 1;
    observed.uploadedSha256 = digest(Buffer.concat(chunks));
    response.setHeader('ETag', '"local-upload"');
    response.end();
    return;
  }
  if (request.url === '/stream') {
    response.on('close', () => { observed.abortedResponseClosed = true; });
    response.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    response.write('bounded-prefix');
    return;
  }
  response.writeHead(404).end();
}));

try {
  origin = await listen(server);
  const providerOrigin = await listen(provider);
  const report = await withBrowser({
    version: 1, scope: 'local_browser_harness', runId,
    outputDirectory: `/tmp/aos-direct-browser-run-${runId}`,
    deadlineUnixMillis: lifetimeDeadline, origin,
    window: null, credentialsFile: null, cases: [],
  }, async ({ client, report }) => {
    await client.call('Page.navigate', { url: `${origin}/` });
    for (;;) {
      if (await client.evaluate('!!document.querySelector("#fixture") && document.readyState === "complete"')) break;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    const document = await client.call('DOM.getDocument');
    const input = await client.call('DOM.querySelector', { nodeId: document.root.nodeId, selector: '#fixture' });
    await client.call('DOM.setFileInputFiles', { nodeId: input.nodeId, files: [file] });
    const uploaded = await client.evaluate(`(async () => {
      const file = document.querySelector('#fixture').files[0];
      const bytes = await file.arrayBuffer();
      const sha256 = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(byte => byte.toString(16).padStart(2, '0')).join('');
      const reply = await fetch('/upload', { method: 'PUT', body: file });
      return { bytes: bytes.byteLength, sha256, status: reply.status, etag: reply.headers.get('etag') };
    })()`);
    assert.deepEqual(uploaded, { bytes: fixture.length, sha256: digest(fixture), status: 200, etag: '"local-upload"' });

    const cors = await client.evaluate(`(async () => {
      const response = await fetch(${JSON.stringify(`${providerOrigin}/cors`)});
      const etag = response.headers.get('etag');
      const body = await response.arrayBuffer();
      let refused = false;
      try { await fetch(${JSON.stringify(`${providerOrigin}/cors-refused`)}); } catch { refused = true; }
      return { status: response.status, bytes: body.byteLength, etag, refused };
    })()`);
    assert.deepEqual(cors, { status: 200, bytes: fixture.length, etag: '"local-fixture"', refused: true });

    assert.equal(await client.evaluate(`(async () => {
      const controller = new AbortController();
      const response = await fetch('/stream', { signal: controller.signal });
      const reader = response.body.getReader();
      const first = await reader.read();
      controller.abort();
      try { await reader.read(); return false; } catch (error) { return first.value.length > 0 && error.name === 'AbortError'; }
    })()`), true);

    await client.evaluate(`(async () => {
      const database = await new Promise((resolve, reject) => { const request = indexedDB.open('cdp-local-harness-v1', 1); request.onupgradeneeded = () => request.result.createObjectStore('records'); request.onerror = () => reject(new Error('db')); request.onsuccess = () => resolve(request.result); });
      await new Promise((resolve, reject) => { const transaction = database.transaction('records', 'readwrite'); transaction.objectStore('records').put(${JSON.stringify(digest(fixture))}, 'source'); transaction.oncomplete = resolve; transaction.onerror = reject; });
      database.close();
    })()`);
    const before = client.pageLoads ?? 0;
    await client.call('Page.reload');
    while ((client.pageLoads ?? 0) <= before) {
      assert.ok(Date.now() < client.deadline, 'local reload deadline');
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    const persisted = await client.evaluate(`(async () => {
      const database = await new Promise((resolve, reject) => { const request = indexedDB.open('cdp-local-harness-v1'); request.onsuccess = () => resolve(request.result); request.onerror = reject; });
      try { return await new Promise((resolve, reject) => { const request = database.transaction('records', 'readonly').objectStore('records').get('source'); request.onsuccess = () => resolve(request.result); request.onerror = reject; }); } finally { database.close(); }
    })()`);
    assert.equal(persisted, digest(fixture));
    report.cases.push({ kind: 'local_browser_mechanics', actualFileInput: true, actualFileSha256: digest(fixture), actualPutReply: true, corsAllowedAndRefused: true, etagExposed: true, abortControllerRejectedRead: true, indexedDbReloadPreserved: true, aosQualification: false });
    // The expected CORS refusal is a local negative case, not an AOS error.
    report.expectedCorsFailureCount = report.events.filter(row => row.kind === 'failed' && row.corsFailure).length;
  });
  assert.equal(observed.uploads, 1);
  assert.equal(observed.uploadedSha256, digest(fixture));
  assert.equal(observed.abortedResponseClosed, true);
  assert.equal(report.ownedBrowserGroupEmpty, true);
  assert.ok(Date.now() <= lifetimeDeadline, 'whole harness lifetime including cleanup');
  console.log(JSON.stringify({ scope: 'local_browser_harness', complete: true, receipt: report.receipt, observed, aosQualification: false }));
} finally {
  for (const socket of sockets) socket.destroy();
  await Promise.all([server, provider].map(value => new Promise(resolve => value.close(resolve))));
}
