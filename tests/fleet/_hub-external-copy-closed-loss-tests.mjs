// Controlled clients, TLS upstream and Core fixture envelopes; no provider effects.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, chmod, readFile } from 'node:fs/promises';
import { request } from 'node:http';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCopyClosedLoss } from './_hub-external-copy-closed-loss.mjs';

assert.equal(process.argv.length, 6, 'expected same-source codec/test ELF and fresh TLS key/certificate');
const [codecFile, fixtureElf, keyFile, certificateFile] = process.argv.slice(2);
const raw = await new Promise((resolve, reject) => {
  const child = spawn(fixtureElf, ['--exact',
    'copy_closed::tests::real_authenticators_check_positive_canonical_private_envelopes', '--nocapture'],
    { env: { ...process.env, AOS_COPY_CLOSED_RETAIN_CASE: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], errors = [];
  child.stdout.on('data', block => out.push(block));
  child.stderr.on('data', block => errors.push(block));
  child.once('error', reject);
  child.once('close', code => code === 0 ? resolve(Buffer.concat(out).toString())
    : reject(new Error('Core fixture generation refused: ' + Buffer.concat(errors).toString())));
});
const matches = [...raw.matchAll(/^CONTROLLED_CASE_ROOT=(.+)$/gm)];
assert.equal(matches.length, 1);
const fixtureRoot = matches[0][1];
const selection = JSON.parse(await readFile(join(fixtureRoot, 'selection.json')));
const observation = JSON.parse(await readFile(join(fixtureRoot, 'observation.json')));
const requestBody = await readFile(selection.request.file);
const replyBody = await readFile(selection.reply.file);
const root = await mkdtemp(join(tmpdir(), 'aos-copy-closed-transport-'));
await chmod(root, 0o700);
console.log('CONTROLLED_TRANSPORT_ROOT=' + root);
let correctSignature = false;
let calls = 0;
const upstream = createServer({ key: await readFile(keyFile), cert: await readFile(certificateFile) }, async (incoming, response) => {
  const chunks = [];
  for await (const block of incoming) chunks.push(block);
  assert.deepEqual(Buffer.concat(chunks), requestBody);
  assert.equal(incoming.headers['x-aos-storage-work-signature'], selection.requestSignature);
  calls += 1;
  response.writeHead(200, { 'content-type': 'application/json', 'content-length': String(replyBody.length),
    'x-aos-storage-work-signature': correctSignature ? selection.replySignature : selection.requestSignature });
  response.end(replyBody);
});
await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
let listener, succeeded = false;
try {
  const sha = bytes => createHash('sha256').update(bytes).digest('hex');
  listener = await createCopyClosedLoss({ version: 1, root, deploymentId: selection.deploymentId,
    sourceDigest: selection.sourceDigest, codecFile, codecSha256: sha(await readFile(codecFile)),
    codecSourceSha256: observation.codecSourceSha256, keyFile: selection.key.file,
    keySha256: selection.key.sha256 }, { listen: 0, upstream: upstream.address().port, upstreamTls: true });
  assert.equal(listener.ready.upstreamScheme, 'https');
  assert.equal(listener.ready.tlsServerName, 'localhost');
  await listener.command({ version: 1, kind: 'arm', captureId: 'a'.repeat(32),
    originalSha256: observation.originalSha256, lossUntilUnixMillis: Date.now() + 25000 });
  await assert.rejects(listener.command({ version: 1, kind: 'arm', captureId: 'a'.repeat(32),
    originalSha256: observation.originalSha256, lossUntilUnixMillis: Date.now() + 25000 }));
  const port = Number(listener.ready.listenAddress.split(':').at(-1));
  const send = () => new Promise((resolve, reject) => {
    const sent = request({ hostname: '127.0.0.1', port, method: 'POST',
      path: '/_internal/storage/external-copy/v1', headers: { 'content-type': 'application/json',
        'content-length': String(requestBody.length),
        'x-aos-storage-work-signature': selection.requestSignature } }, response => {
      const chunks = [];
      response.on('data', block => chunks.push(block));
      response.once('error', reject);
      response.once('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks),
        signature: response.headers['x-aos-storage-work-signature'] }));
    });
    sent.once('error', reject);
    sent.end(requestBody);
  });

  const refused = await send();
  assert.equal(refused.status, 200);
  assert.deepEqual(refused.body, replyBody);
  assert.equal(refused.signature, selection.requestSignature);
  assert.equal((await listener.command({ version: 1, kind: 'state' })).consumed, false);

  correctSignature = true;
  await assert.rejects(send());
  let state;
  for (let count = 0; count < 100; count += 1) {
    state = await listener.command({ version: 1, kind: 'state' });
    if (state.observation !== null) break;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(state.terminal, 'authenticated_closed_downstream_destroyed');
  assert.equal(state.consumed, true);
  assert.equal(state.nativeObservedLoss, null);
  assert.equal(state.providerSettlement, null);
  const verified = JSON.parse(await readFile(state.observation.verification.file));
  assert.equal(verified.scope, 'authenticated_copy_closed_envelope_only');
  assert.equal(verified.originalSha256, observation.originalSha256);
  assert.equal(verified.requestSha256, sha(requestBody));
  assert.equal(verified.replySha256, sha(replyBody));
  const lost = JSON.parse(await readFile(state.observation.loss.file));
  assert.equal(lost.downstreamDestroyInvoked, true);
  assert.equal(lost.nativeObservedLoss, null);

  const replay = await send();
  assert.equal(replay.status, 200);
  assert.deepEqual(replay.body, replyBody);
  assert.equal(replay.signature, selection.replySignature);
  assert.equal(calls, 3, 'actual controlled upstream calls');
  console.log('PASS controlled real-Core-MAC refusal, one-shot authenticated Closed loss, exact later forwarding');
  succeeded = true;
} finally {
  await listener?.close();
  await new Promise(resolve => upstream.close(resolve));
  if (succeeded) {
    console.log('Controlled raw envelopes/verification/loss retained:', root, fixtureRoot);
  } else {
    console.error('Failed controlled sources retained:', root, fixtureRoot);
  }
}
