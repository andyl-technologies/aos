/** Pure bounded-client regressions. These cases never launch Chrome. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BrowserRefusal, CdpClient, digest, parseProcessStat, requireSameOriginal,
  requireDistinctNewRun, requireSelectedAdmission, selectedManifestBegin,
  safeHeaders, safeNetworkEvent, safeUrl, summarizeCheckpoints, validateSelection,
} from './_hub-direct-browser-cdp.mjs';

assert.equal(process.execPath, '/nix/store/3gjq7k2jpwizjwaynhpdgwl5p4mf7lrz-nodejs-22.22.3/bin/node');
assert.equal(process.versions.openssl, '3.5.6');

function selection() {
  return {
    version: 1, scope: 'hosted_aos_browser', runId: 'a'.repeat(32),
    outputDirectory: `/tmp/aos-direct-browser-run-${'a'.repeat(32)}`,
    deadlineUnixMillis: 2000, origin: 'https://example.test',
    window: { file: '/tmp/private/window.json', sha256: 'b'.repeat(64), byteSize: '100' },
    credentialsFile: '/tmp/private/credentials.json',
    cases: [{ kind: 'login', privatePath: '/-/settings' }],
  };
}

test('hosted selection closes routes, fields, deadlines and initial login', () => {
  assert.equal(validateSelection(selection(), 1000).scope, 'hosted_aos_browser');
  for (const change of [
    value => { value.cases[0].privatePath = '//foreign.test/'; },
    value => { value.cases[0].privatePath = '/login?token=opaque'; },
    value => { value.cases[0].extra = true; },
    value => { value.deadlineUnixMillis = 601001; },
    value => { value.cases[0].kind = 'private_page'; },
    value => { value.disableSandbox = true; },
  ]) {
    const value = selection();
    change(value);
    assert.throws(() => validateSelection(value, 1000));
  }
});

test('multipart selection requires genuinely changed bounded source', () => {
  const value = selection();
  const source = { file: '/tmp/private/source', sha256: 'c'.repeat(64), byteSize: '8388609' };
  value.cases.push({ kind: 'cache_pause_resume', pagePath: '/-/cache', objectPath: 'nar/example.nar', source, changedSource: { ...source, file: '/tmp/private/changed', sha256: 'd'.repeat(64) } });
  assert.equal(validateSelection(value, 1000), value);
  value.cases[1].changedSource.sha256 = source.sha256;
  assert.throws(() => validateSelection(value, 1000), /multipart_changed_source_fixture/);
});

test('local harness cannot borrow hosted credentials, cases or origin', () => {
  const value = { ...selection(), scope: 'local_browser_harness', origin: 'http://127.0.0.1:1234', window: null, credentialsFile: null, cases: [] };
  assert.equal(validateSelection(value, 1000), value);
  assert.throws(() => validateSelection({ ...value, credentialsFile: '/tmp/private/auth' }, 1000));
  assert.throws(() => validateSelection({ ...value, origin: 'http://localhost:1234' }, 1000));
  assert.throws(() => validateSelection({ ...value, cases: selection().cases }, 1000));
});

test('network summaries discard credentials, paths, queries and body values', () => {
  const secret = 'opaque-sensitive-value';
  const raw = `https://user:${secret}@example.test/private/${secret}?signature=${secret}#${secret}`;
  const request = safeNetworkEvent('Network.requestWillBeSent', { requestId: secret, timestamp: 1, request: { method: 'PUT', url: raw, postData: secret, headers: { Authorization: secret } } });
  const response = safeNetworkEvent('Network.responseReceived', { requestId: secret, timestamp: 2, response: { url: raw, status: 200, headers: { ETag: secret, 'Set-Cookie': secret, Authorization: secret, 'Access-Control-Expose-Headers': 'ETag' } } });
  assert.equal(JSON.stringify([request, response]).includes(secret), false);
  assert.equal(response.headers.etagSha256, digest(secret));
  assert.deepEqual(safeHeaders({ Cookie: secret }), {});
  assert.equal(safeUrl(raw).queryPresent, true);
  assert.deepEqual(safeUrl('not-a-url'), { invalid: true });
});

function head(run = 'e'.repeat(64)) {
  return { scope: 'f'.repeat(64), runNonce: run, deploymentId: 'private-deployment', principalId: 'private-principal', intent: { expectedSha256: '1'.repeat(64), byteSize: '8388609', target: { cache: 'private-cache' } }, session: { state: 'active', session: { id: 'private-session' } } };
}

test('part observations are joined only to their exact saved original', async () => {
  const original = head();
  const other = head('2'.repeat(64));
  const rows = await summarizeCheckpoints([
    [`${original.scope}:active`, JSON.stringify(original)],
    [`${original.scope}:${original.runNonce}:7:1`, JSON.stringify({ original: { number: 1, sha256: '3'.repeat(64) }, serverObserved: {} })],
    [`${other.scope}:${other.runNonce}:8:1`, JSON.stringify({ original: { number: 1 }, serverObserved: {} })],
  ], digest);
  assert.equal(rows[1].originalSha256, rows[0].originalSha256);
  assert.equal(rows[2].originalSha256, null);
  assert.equal(JSON.stringify(rows).includes('private-principal'), false);
});

test('retired completion keeps original identity while new nonce differs', async () => {
  const original = head();
  const before = (await summarizeCheckpoints([[`${original.scope}:active`, JSON.stringify(original)]], digest))[0];
  const after = (await summarizeCheckpoints([[`${original.scope}:${original.runNonce}:retired`, JSON.stringify({ ...original, session: { ...original.session, state: 'committed' } })]], digest))[0];
  requireSameOriginal(before, after);
  assert.equal(after.retired, true);
  const newer = (await summarizeCheckpoints([[`${original.scope}:active`, JSON.stringify(head('2'.repeat(64)))]], digest))[0];
  assert.throws(() => requireSameOriginal(before, newer), /original_changed/);
});

test('registry admission has a separate immutable metadata commitment', async () => {
  const original = { deployment: 'private-deployment', principal: 'private-principal', begin: { registry: 'registry', generation: 'generation', manifestDigest: '3'.repeat(64) }, publicationId: 'publication' };
  const key = `publication-admission:${'4'.repeat(64)}`;
  const before = (await summarizeCheckpoints([[key, JSON.stringify(original)]], digest))[0];
  const replay = (await summarizeCheckpoints([[key, JSON.stringify(original)]], digest))[0];
  assert.equal(before.kind, 'publication_admission');
  assert.equal(before.originalSha256, replay.originalSha256);
  assert.equal(before.publicationSha256, digest('publication'));
  const changed = (await summarizeCheckpoints([[key, JSON.stringify({ ...original, begin: { ...original.begin, generation: 'replacement' } })]], digest))[0];
  assert.notEqual(before.originalSha256, changed.originalSha256);
  await assert.rejects(summarizeCheckpoints(Array.from({ length: 129 }, () => [key, '{}']), digest), /checkpoint_bound/);
});

test('same-generation retained admission refuses changed inventory or fields', async () => {
  const declaration = {
    registry: 'registry', generation: 'generation', refsDigest: 'a'.repeat(64),
    defaultCommit: 'b'.repeat(40), parentPublicationId: 'original-parent',
    objects: [{ path: 'object', sha256: 'c'.repeat(64), byteSize: '20', kind: 'immutable', mediaType: 'application/octet-stream' }],
  };
  const begin = selectedManifestBegin(declaration);
  const actual = { deployment: 'private-deployment', principal: 'private-principal', begin, publicationId: 'original-publication' };
  const rows = await summarizeCheckpoints([[`publication-admission:${'d'.repeat(64)}`, JSON.stringify(actual)]], digest);
  assert.equal(begin.manifestDigest, digest(JSON.stringify([['object', 'c'.repeat(64), 20, 'immutable', 'application/octet-stream']])));
  assert.equal(requireSelectedAdmission(rows, declaration).length, 1);
  for (const changed of [
    { ...declaration, objects: [{ ...declaration.objects[0], sha256: 'e'.repeat(64) }] },
    { ...declaration, objects: [...declaration.objects, { ...declaration.objects[0], path: 'another' }] },
    { ...declaration, refsDigest: 'f'.repeat(64) },
    { ...declaration, defaultCommit: 'f'.repeat(40) },
    { ...declaration, parentPublicationId: 'replacement-parent' },
  ]) {
    assert.throws(() => requireSelectedAdmission(rows, changed), /selected_admission_declaration_mismatch/);
  }
});

test('new run requires distinct server session and unchanged aborted history', async () => {
  const original = head();
  const initial = (await summarizeCheckpoints([[`${original.scope}:active`, JSON.stringify(original)]], digest))[0];
  const nextValue = { ...head('2'.repeat(64)), session: { state: 'active', session: { id: 'distinct-session' } } };
  const next = (await summarizeCheckpoints([[`${nextValue.scope}:active`, JSON.stringify(nextValue)]], digest))[0];
  const retired = (await summarizeCheckpoints([[`${original.scope}:${original.runNonce}:retired`, JSON.stringify({ ...original, session: { ...original.session, state: 'aborted' } })]], digest))[0];
  requireDistinctNewRun(initial, next, [retired]);
  assert.throws(() => requireDistinctNewRun(initial, { ...next, sessionSha256: initial.sessionSha256 }, [retired]), /new_run_reused_original_or_session/);
  assert.throws(() => requireDistinctNewRun(initial, next, [{ ...retired, state: 'committed' }]), /old_aborted_history_missing/);
  assert.throws(() => requireDistinctNewRun(initial, next, [{ ...retired, sessionSha256: next.sessionSha256 }]), /original_changed/);
  assert.throws(() => requireDistinctNewRun(initial, next, [{ ...retired, originalSha256: next.originalSha256 }]), /old_aborted_history_missing/);
});

test('process start field survives spaces and parentheses in command name', () => {
  const fields = ['S', '5', '7', ...Array(16).fill('0'), '12345'];
  assert.deepEqual(parseProcessStat(`9 (chrome (renderer)) ${fields.join(' ')}`), { parentPid: 5, processGroup: 7, startTicks: '12345' });
});

class FakeSocket extends EventTarget {
  send(raw) { this.last = JSON.parse(raw); }
  close() { this.dispatchEvent(new Event('close')); }
  answer(value) { this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(value) })); }
}

test('CDP errors expose only closed refusal, and closed transport rejects', async () => {
  const socket = new FakeSocket();
  const client = new CdpClient(socket, Date.now() + 1000);
  client.sessionId = 'session';
  const first = client.call('Runtime.evaluate');
  socket.answer({ id: socket.last.id, error: { message: 'opaque-sensitive-value' } });
  await assert.rejects(first, error => error instanceof BrowserRefusal && error.code === 'cdp_command_refused');
  const next = client.call('Page.enable');
  socket.close();
  await assert.rejects(next, /cdp_closed/);
  assert.throws(() => client.call('Page.enable'), /cdp_deadline_or_inflight/);
});
