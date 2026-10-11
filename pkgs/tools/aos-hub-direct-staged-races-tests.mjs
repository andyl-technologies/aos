// Production DTO/golden and controlled HTTPS tests; never provider qualification.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// Child-only injected filesystem delays exercise the actual driver path without
// exposing a production hook or changing the selected control/cutoff semantics.
if (['--marker-expiry-child', '--bounded-growth-child'].includes(process.argv[2])) {
  const [kind, driverFile, selectionFile, output, observationFile] = process.argv.slice(2);
  const selection = JSON.parse(await fs.readFile(selectionFile));
  const fixture = await import(pathToFileURL(driverFile));
  const originalOpen = fs.open.bind(fs);
  const originalFetch = globalThis.fetch;
  const observation = { markerReached: false, grew: false, completeFetchInvocations: 0,
    unboundedReads: 0, maximumReadRequest: 0, totalReadBytes: 0, refused: false };
  globalThis.fetch = (...args) => {
    if (new URL(args[0]).pathname.endsWith('/CompleteBatch')) observation.completeFetchInvocations += 1;
    return originalFetch(...args);
  };
  fs.open = async (file, ...args) => {
    const handle = await originalOpen(file, ...args);
    if (kind === '--marker-expiry-child' && String(file).endsWith('-CompleteBatch-dispatch-started.json')) {
      const sync = handle.sync.bind(handle);
      handle.sync = async () => {
        await sync();
        observation.markerReached = true;
        await new Promise(resolve => setTimeout(resolve, Math.max(0, selection.cutoffUnixMs - Date.now()) + 25));
      };
    }
    if (kind === '--bounded-growth-child' && file === selection.tokenFile) {
      const stat = handle.stat.bind(handle);
      const read = handle.read.bind(handle);
      const readFile = handle.readFile.bind(handle);
      handle.stat = async (...args) => {
        const sampled = await stat(...args);
        if (!observation.grew) {
          observation.grew = true;
          await fs.appendFile(file, Buffer.alloc(32768, 120));
        }
        return sampled;
      };
      handle.read = async (...args) => {
        observation.maximumReadRequest = Math.max(observation.maximumReadRequest, args[2]);
        const value = await read(...args);
        observation.totalReadBytes += value.bytesRead;
        return value;
      };
      handle.readFile = (...args) => {
        observation.unboundedReads += 1;
        return readFile(...args);
      };
    }
    return handle;
  };
  try {
    await fixture.run(selection, output);
  } catch {
    observation.refused = true;
  } finally {
    fs.open = originalOpen;
    globalThis.fetch = originalFetch;
    await fs.writeFile(observationFile, JSON.stringify(observation), { flag: 'wx', mode: 0o600 });
  }
  process.exit(observation.refused ? 1 : 0);
}

const [openssl, driverFile, productionRoot] = process.argv.slice(2);
assert(openssl && await fs.realpath(openssl) === openssl && openssl.startsWith('/nix/store/'));
assert(driverFile && productionRoot);
const driver = await import(pathToFileURL(driverFile));
const { intentFingerprint, manifestDigest, terminalDenial, PART_BYTES, sha } = driver;
const placement = { placementId: '17', placementFingerprint: '33'.repeat(32), placementResourceVersion: '2',
  writeSpecVersion: '3', bindingId: '4', bindingResourceVersion: '5', bindingWriteRevision: '6',
  profileFingerprint: '44'.repeat(32), privatePolicyDigest: '55'.repeat(32), checksumAlgorithm: 'sha256' };
const vectorIntent = { version: 1, clientOperationId: '11'.repeat(32),
  target: { kind: 'cache_object', cacheId: 'cache-one', path: 'object.nar' }, expectedSha256: '22'.repeat(32),
  byteSize: '8388609', partSize: String(PART_BYTES), dependencyPhase: 'content', transferMode: 'direct_required' };
const vectorParts = [1, 2].map(number => ({ part: { partNumber: number,
  offset: number === 1 ? '0' : String(PART_BYTES), byteSize: number === 1 ? String(PART_BYTES) : '1',
  sha256: '00'.repeat(32), checksum: { algorithm: 'sha256', value: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' } },
  etag: `"part-${number}"` }));
// These literals are asserted by the actual production Rust hasher in Proto
// direct_upload/tests.rs::canonical_binary_vectors_match_independent_node_implementation.
assert.equal(intentFingerprint(vectorIntent), 'c7d555fd5e57f1aefe86edd2575c6c77785dca50aee4b42e5414e69cf92d343f');
assert.equal(manifestDigest(vectorIntent, placement, vectorParts), 'f10226c14015cd379686f5a049168c22fc02f80096051df7e21f866e51a64e9b');
assert.throws(() => manifestDigest(vectorIntent, placement, vectorParts.slice(0, 1)));
assert.throws(() => manifestDigest(vectorIntent, placement, [...vectorParts].reverse()));
assert.throws(() => manifestDigest(vectorIntent, { ...placement, unknown: true }, vectorParts));
assert.throws(() => intentFingerprint({ ...vectorIntent, byteSize: '08388609' }));
const denialBody = Buffer.from('<Error><Code>NoSuchUpload</Code></Error>');
const denial = { status: 404, bytes: denialBody.length, eof: true, body: denialBody };
assert(terminalDenial(denial));
assert.equal(terminalDenial({ ...denial, bytes: denial.bytes + 1 }), false);
for (const changed of [{ status: 403 }, { status: 500 }, { eof: false },
  { body: Buffer.from('<Error><Code>SignatureDoesNotMatch</Code></Error>') }, { body: Buffer.alloc(0) },
  { body: Buffer.from('<Error><Code>NoSuchUpload</Code><Unclassified>extra</Unclassified></Error>') }]) {
  const response = { ...denial, ...changed };
  response.bytes = response.body.length;
  assert.equal(terminalDenial(response), false);
}
// Synthetic full-admission commitment deliberately differs from the smaller intent hash.
const exactSession = { sessionId: 'source-status', logicalFingerprint: sha(Buffer.from('synthetic-full-admission-original')) };
assert.notEqual(exactSession.logicalFingerprint, intentFingerprint(vectorIntent));
const exactStatus = { session: exactSession, intent: vectorIntent, placements: [placement], resourceVersion: '7' };
assert.deepEqual(driver.originalStatuses({ sessions: [exactStatus] }, exactSession, vectorIntent, placement), [exactStatus]);
for (const changed of [
  { session: { ...exactSession, logicalFingerprint: 'ab'.repeat(32) } },
  { intent: { ...vectorIntent, expectedSha256: 'ab'.repeat(32) } },
  { placements: [{ ...placement, bindingResourceVersion: '8' }] },
]) {
  assert.throws(() => driver.originalStatuses({ sessions: [{ ...exactStatus, ...changed }] },
    exactSession, vectorIntent, placement));
}
console.log('PASS production golden, exact status binding and closed denial refusals');

const root = await fs.mkdtemp('/tmp/aos-staged-race-tests-');
await fs.chmod(root, 0o700);
const publishedBytes = Buffer.from('{"kind":"synthetic_complete_image"}');
const temporaryPublication = path.join(root, 'publication-temporary.json');
const finalPublication = path.join(root, 'publication-final.json');
const validatePublication = value => assert(value.equals(publishedBytes));
await fs.writeFile(temporaryPublication, publishedBytes, { flag: 'wx', mode: 0o600 });
await fs.link(temporaryPublication, finalPublication);
assert.equal(await driver.publicationBytes(finalPublication, 65536, validatePublication), null);
await fs.writeFile(temporaryPublication, '{}');
await assert.rejects(() => driver.publicationBytes(finalPublication, 65536, validatePublication));
await fs.writeFile(temporaryPublication, publishedBytes);
await fs.unlink(temporaryPublication);
assert((await driver.publicationBytes(finalPublication, 65536, validatePublication)).equals(publishedBytes));
await assert.rejects(() => driver.publishPrivate(root, 'publication-final.json', Buffer.from('{}')));
assert((await fs.readFile(finalPublication)).equals(publishedBytes));
await driver.publishPrivate(root, 'publication-new.json', publishedBytes);
assert.equal((await fs.stat(path.join(root, 'publication-new.json'))).nlink, 1);
console.log('PASS atomic publication pending, malformed refusal and no replacement');

const key = path.join(root, 'key.pem');
const cert = path.join(root, 'cert.pem');
const generated = spawnSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
  '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', key, '-out', cert], { stdio: 'ignore' });
assert.equal(generated.status, 0);
await fs.chmod(key, 0o600);
const token = path.join(root, 'token');
await fs.writeFile(token, 'synthetic-private-app-session', { mode: 0o600 });
const sourceRef = async file => ({ file, sha256: sha(await fs.readFile(file)) });
const reportHelperSource = await sourceRef(path.join(productionRoot, 'pkgs/tools/aos-hub-direct-qualification.mjs'));
const protoSources = await Promise.all(['model.rs', 'validation.rs', 'batch.rs'].map(name => sourceRef(
  path.join(productionRoot, 'crates/aos-proto-types/src/direct_upload', name))));
const capabilityValue = (target, providerOrigin) => ({ target, deploymentId: 'synthetic-deployment',
  principalId: '88'.repeat(32), version: 1, capability: 'aos.direct.multipart.v1', transferMode: 'direct_required',
  configGeneration: '2', validUntil: String(Math.floor(Date.now() / 1000) + 90), maximumControlBytes: 262144,
  maximumBatchItems: 64, maximumBatchParts: 64, minimumObjectBytes: '1', maximumObjectBytes: '17179869184',
  minimumPartBytes: '5242880', maximumPartBytes: '67108864', profiles: [{
    ...Object.fromEntries(Object.entries(placement).filter(([field]) => field !== 'placementFingerprint')), providerOrigin }] });
let scenario;
let discoveredScenario;
let origin;
let sessions;
let methods;
let providerCalls;
let completeBodies;
let requestFailures = [];
let preparedCompleteBody = null;
const sorted = value => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
const server = https.createServer({ key: await fs.readFile(key), cert: await fs.readFile(cert) }, async (request, response) => {
  try {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks);
    const url = new URL(request.url, origin);
    if (url.pathname.startsWith('/stage/')) {
      const session = sessions.find(item => url.pathname === `/stage/${item.session.sessionId}`);
      assert(session);
      assert.equal(request.method, 'PUT');
      assert.equal(request.headers['content-length'], String(PART_BYTES));
      assert.equal(raw.length, PART_BYTES);
      assert.equal(sha(raw), session.intent.expectedSha256);
      assert.equal(request.headers['x-amz-checksum-sha256'], crypto.createHash('sha256').update(raw).digest('base64'));
      providerCalls.push({ session: session.session.sessionId, state: session.state, bytes: raw.length });
      if (session.physicalClosed) {
        response.writeHead(404);
        response.end(scenario === 'wrong-denial' ? '<Error><Code>AccessDenied</Code></Error>'
          : '<Error><Code>NoSuchUpload</Code></Error>');
      } else {
        response.writeHead(200, { etag: '"positive-original-part"' });
        response.end();
      }
      return;
    }
    if (url.pathname.startsWith('/visible/')) {
      const phase = url.pathname.slice('/visible/'.length);
      const session = sessions.find(item => item.intent.target.path === `${phase}.nar`);
      assert.equal(session.state, 'committed');
      response.end(driver.deterministicPayload(scenario.endsWith('external') ? 'external_s3' : 'managed_r2', phase));
      return;
    }
    assert.equal(request.headers.authorization, 'Bearer synthetic-private-app-session');
    const method = url.pathname.split('/').at(-1);
    methods.push(method);
    const body = JSON.parse(raw);
    let statuses = [];
    let grants = [];
    const item = body.items[0];
    if (method === 'BeginBatch') {
      const phase = item.target.path.split('.')[0];
      const actualPlacement = discoveredScenario ? { ...placement, placementFingerprint: sha(Buffer.from(`synthetic-final-key:${phase}`)) } : placement;
      if (scenario === 'capability-mismatch') actualPlacement.bindingResourceVersion = '9';
      if (scenario === 'capability-malformed-placement') actualPlacement.placementFingerprint = 'not-a-digest';
      const session = { session: { sessionId: `synthetic-${phase}`, logicalFingerprint: sha(Buffer.from(`synthetic-full-admission:${phase}`)) },
        resourceVersion: '7', intent: item, placements: [actualPlacement], state: 'creating', parts: [],
        nextCursor: null, outstandingGrants: true };
      session.physicalClosed = false;
      sessions.push(session);
      statuses = [session];
    } else if (method === 'GrantPartsBatch') {
      const session = sessions.find(value => value.session.sessionId === item.session.sessionId);
      assert.deepEqual(item.placement, session.placements[0]);
      const grant = { sessionId: session.session.sessionId, logicalFingerprint: session.session.logicalFingerprint,
        placement: session.placements[0], grantId: sha(Buffer.from(session.session.sessionId)), grantRevision: '1', part: item.part, method: 'PUT',
        url: `${origin}/stage/${session.session.sessionId}?partNumber=1&uploadId=actual-synthetic-upload&X-Amz-Signature=synthetic`,
        requiredHeaders: [{ name: 'content-length', value: String(PART_BYTES) },
          { name: 'x-amz-checksum-sha256', value: item.part.checksum.value }],
        expiresAt: String(Math.floor(Date.now() / 1000) + (scenario === 'expired-grant' ? -1 : 90)) };
      grants = [{ ...grant, part: scenario === 'changed-source' ? { ...grant.part, sha256: '00'.repeat(32) } : grant.part }];
    } else if (method === 'ReportPartsBatch') {
      assert.deepEqual(Object.keys(item), ['session', 'placement', 'operationId', 'grantId', 'grantRevision', 'observed']);
      assert.deepEqual(Object.keys(item.placement), Object.keys(placement));
      const session = sessions.find(value => value.session.sessionId === item.session.sessionId);
      assert.equal(item.observed.etag, '"positive-original-part"');
      assert.equal(item.observed.part.sha256, session.intent.expectedSha256);
      assert.deepEqual(item.placement, session.placements[0]);
      session.reportedPart = item.observed;
      statuses = [scenario === 'capability-substituted-session'
        ? { ...session, session: { ...session.session, logicalFingerprint: 'ab'.repeat(32) } } : session];
    } else if (method === 'CompleteBatch' || method === 'Abort') {
      const session = sessions.find(value => value.session.sessionId === item.session.sessionId);
      assert.equal(item.expectedResourceVersion, '7');
      if (method === 'CompleteBatch') {
        completeBodies.push(Buffer.from(raw));
        if (completeBodies.length > 1) assert(raw.equals(completeBodies[0]));
        if (scenario.startsWith('prepare')) assert(raw.equals(preparedCompleteBody));
        assert.deepEqual(item.manifests, [{ placement: session.placements[0],
          manifestDigest: manifestDigest(session.intent, session.placements[0], [session.reportedPart]), partCount: 1 }]);
        if (scenario === 'unknown-close' || scenario === 'prepare-unknown-start'
          || (['lost-next', 'prepare-accepted-lost-next'].includes(scenario) && completeBodies.length === 2)) {
          request.socket.destroy();
          return;
        }
        if (scenario === 'prepare-refused-start') {
          response.writeHead(503);
          response.end();
          return;
        }
        session.physicalClosed = true;
        session.state = completeBodies.length === 1 ? 'completing_staging' : 'committed';
      } else {
        session.physicalClosed = true;
        session.state = 'aborted';
      }
      statuses = [session];
    } else if (method === 'StatusBatch') {
      const session = sessions.find(value => value.session.sessionId === item.session.sessionId);
      assert.deepEqual(item, { session: session.session, after: null, maximumParts: 1 });
      statuses = [session];
    } else throw new Error('unexpected production control');
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(sorted({ operationId: body.operationId,
      sessions: statuses.map(({ physicalClosed, reportedPart, ...status }) => status), grants, errors: [] })));
  } catch (error) {
    if (error.code === 'ECONNRESET' && ['unknown-close', 'lost-next', 'prepare-unknown-start', 'prepare-accepted-lost-next'].includes(scenario)) return;
    requestFailures.push(error);
    response.destroy(error);
  }
});
server.listen(0, '127.0.0.1');
await new Promise(resolve => server.once('listening', resolve));
origin = `https://127.0.0.1:${server.address().port}`;
try {
  const pureTargets = { complete: { target: { kind: 'cache_object', cacheId: 'owned-fixture', path: 'complete.nar' }, finalReadUrl: null } };
  const pureCapabilities = capabilityValue({ kind: 'cache', cacheId: 'owned-fixture' }, origin);
  assert.deepEqual(driver.checkedCapabilities(pureCapabilities, pureTargets, origin, Date.now()), pureCapabilities);
  for (const field of Object.keys(placement).filter(field => field !== 'placementFingerprint')) {
    const changed = { ...placement, [field]: field.endsWith('Fingerprint') || field.endsWith('Digest')
      ? 'ab'.repeat(32) : field === 'checksumAlgorithm' ? 'md5' : '99' };
    assert.throws(() => driver.capabilityPlacement(changed, pureCapabilities));
  }
  for (const changed of [{ version: true }, { profiles: [] }, { extra: true },
    { target: { kind: 'cache', cacheId: 'substituted' } }, { maximumPartBytes: '5242880' }]) {
    assert.throws(() => driver.checkedCapabilities({ ...pureCapabilities, ...changed }, pureTargets, origin, Date.now()));
  }
  assert.throws(() => driver.capabilityPlacement({ ...placement, placementFingerprint: 'malformed' }, pureCapabilities));
  console.log('PASS actual capability shape, all public placement fields and owner/geometry refusals');

  for (scenario of ['managed', 'external', 'wrong-denial', 'changed-source', 'expired-grant', 'unknown-close',
    'growing-retained-input', 'prepare-marker-expiry', 'lost-next', 'prepare-accepted', 'prepare-accepted-lost-next', 'prepare-refused-start', 'prepare-unknown-start',
    'prepare', 'prepare-wrong-body', 'prepare-prior-dispatch', 'capabilities-managed', 'capabilities-external',
    'prepare-capabilities', 'capability-mismatch', 'capability-expired', 'capability-extra',
    'capability-wrong-owner', 'capability-malformed-placement', 'capability-substituted-session']) {
    sessions = [];
    methods = [];
    providerCalls = [];
    completeBodies = [];
    requestFailures = [];
    preparedCompleteBody = null;
    discoveredScenario = scenario.includes('capabilit');
    const scope = scenario.endsWith('external') ? 'external_s3' : 'managed_r2';
    const selection = { version: 1, runId: sha(Buffer.from(scenario)), scope, origin, tokenFile: token,
      providerOrigin: origin, providerPathPrefix: '/stage/', cutoffUnixMs: Date.now() + 15000, placement,
      targets: { complete: { target: { kind: 'cache_object', cacheId: 'owned-fixture', path: 'complete.nar' },
        finalReadUrl: `${origin}/visible/complete` }, abort: { target: { kind: 'cache_object', cacheId: 'owned-fixture',
        path: 'abort.nar' }, finalReadUrl: null } }, reportHelperSource, protoSources };
    const privateRef = async (name, value) => {
      const file = path.join(root, `${scenario}-${name}.json`);
      const raw = Buffer.from(JSON.stringify(value));
      await fs.writeFile(file, raw, { mode: 0o600 });
      return { file, sha256: sha(raw), byteSize: String(raw.length) };
    };
    if (discoveredScenario) {
      if (scenario === 'prepare-capabilities') {
        selection.targets.complete.target = { kind: 'publication_object', publicationId: 'synthetic-publication',
          surfaceObjectId: '23', path: 'complete.nar' };
      }
      const owner = scenario === 'prepare-capabilities'
        ? { kind: 'publication', publicationId: 'synthetic-publication' } : { kind: 'cache', cacheId: 'owned-fixture' };
      const value = capabilityValue(owner, origin);
      if (scenario === 'capability-expired') value.validUntil = String(Math.floor(Date.now() / 1000) - 1);
      if (scenario === 'capability-extra') value.profiles.push({ ...value.profiles[0], placementId: '18' });
      if (scenario === 'capability-wrong-owner') value.target.cacheId = 'substituted-owner';
      selection.capabilities = await privateRef('capabilities', value);
      delete selection.placement;
    }
    if (scenario.startsWith('prepare')) {
      delete selection.targets.abort;
      selection.preComplete = { actorWhoami: await privateRef('actor', { kind: 'synthetic_actor_no_auth_proof' }),
        runtimePins: await privateRef('runtime', { kind: 'synthetic_tuple_not_installed' }) };
    }
    if (scenario === 'growing-retained-input') {
      selection.tokenFile = path.join(root, `${scenario}-token.private`);
      await fs.writeFile(selection.tokenFile, 'synthetic-private-app-session', { flag: 'wx', mode: 0o600 });
    }
    if (scenario === 'prepare-marker-expiry') selection.cutoffUnixMs = Date.now() + 4000;
    const selectionFile = path.join(root, `${scenario}.json`);
    await fs.writeFile(selectionFile, JSON.stringify(selection), { mode: 0o600 });
    const output = path.join(root, `${scenario}-output`);
    const observationFile = path.join(root, `${scenario}-filesystem-observation.json`);
    const childArguments = scenario === 'prepare-marker-expiry'
      ? [process.argv[1], '--marker-expiry-child', driverFile, selectionFile, output, observationFile]
      : scenario === 'growing-retained-input'
        ? [process.argv[1], '--bounded-growth-child', driverFile, selectionFile, output, observationFile]
        : [driverFile, selectionFile, output];
    const child = spawn(process.execPath, childArguments, {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: cert }, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    const timer = setTimeout(() => child.kill('SIGKILL'), 20000);
    const childExit = new Promise(resolve => child.once('exit', resolve));
    if (scenario.startsWith('prepare')) {
      const preparedFile = path.join(output, 'pre-complete-prepared.json');
      let preparedRaw;
      while (!preparedRaw) {
        try {
          preparedRaw = await driver.publicationBytes(preparedFile, 65536, value => {
            const pending = JSON.parse(value);
            assert.equal(pending.state, 'prepared_unsent');
            assert.equal(pending.version, 1);
          });
          if (!preparedRaw) await new Promise(resolve => setTimeout(resolve, 10));
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
          assert.equal(child.exitCode, null);
          await new Promise(resolve => setTimeout(resolve, 10));
        }
      }
      const prepared = JSON.parse(preparedRaw);
      assert.equal(prepared.state, 'prepared_unsent');
      assert.equal(prepared.status.state, 'creating');
      assert.deepEqual(prepared.status.session, prepared.session);
      assert.deepEqual(prepared.status.placements, [prepared.placement]);
      assert.equal(prepared.status.resourceVersion, prepared.expectedResourceVersion);
      assert.deepEqual(methods, ['BeginBatch', 'GrantPartsBatch', 'ReportPartsBatch']);
      assert.equal(providerCalls.length, 1);
      const beginBody = JSON.parse(await fs.readFile(path.join(output, prepared.refs.beginBody.file)));
      assert.deepEqual(beginBody.items, [prepared.intent]);
      if (discoveredScenario) {
        assert.equal(prepared.refs.capabilities.sha256, selection.capabilities.sha256);
        assert.notEqual(prepared.session.logicalFingerprint, intentFingerprint(prepared.intent));
      }
      preparedCompleteBody = await fs.readFile(path.join(output, prepared.refs.completeBody.file));
      assert.equal(sha(preparedCompleteBody), prepared.refs.completeBody.sha256);
      const pending = JSON.parse(await fs.readFile(path.join(output, prepared.refs.pendingReceipt.file)));
      assert.deepEqual(pending.request, prepared.refs.completeBody);
      const observation = async name => {
        const file = path.join(root, `${scenario}-${name}.json`);
        const raw = Buffer.from(JSON.stringify({ kind: `synthetic_${name}_not_actual_qualification` }));
        await fs.writeFile(file, raw, { mode: 0o600 });
        return { file, sha256: sha(raw), byteSize: String(raw.length) };
      };
      const continuation = { version: 1, preparedSha256: sha(preparedRaw),
        completeBodySha256: prepared.refs.completeBody.sha256 };
      for (const key of ['runId', 'scope', 'session', 'placement', 'expectedResourceVersion', 'sourceSha256',
        'cutoffUnixMs', 'actorWhoami', 'runtimePins']) continuation[key] = prepared[key];
      continuation.admissionObservation = await observation('admission');
      continuation.wrapperObservation = await observation('wrapper');
      assert.deepEqual(driver.checkedContinuation(prepared, preparedRaw, continuation), continuation);
      if (scenario === 'prepare-wrong-body') continuation.completeBodySha256 = '00'.repeat(32);
      if (scenario === 'prepare-prior-dispatch') {
        const marker = prepared.refs.completeBody.file.replace('-request.json', '-dispatch-started.json');
        await fs.writeFile(path.join(output, marker), '{}', { flag: 'wx', mode: 0o600 });
      }
      await driver.publishPrivate(output, 'pre-complete-continuation.json', Buffer.from(JSON.stringify(continuation)));
    }
    const code = await childExit;
    clearTimeout(timer);
    assert.deepEqual(requestFailures, []);
    assert(!Buffer.concat(stdout).includes(Buffer.from('X-Amz-Signature')));
    assert(!Buffer.concat(stderr).includes(Buffer.from('synthetic-private-app-session')));
    if (scenario === 'changed-source' || scenario === 'expired-grant' || scenario === 'unknown-close'
      || scenario === 'growing-retained-input' || scenario === 'prepare-marker-expiry'
      || scenario === 'lost-next' || scenario === 'prepare-refused-start' || scenario === 'prepare-unknown-start'
      || scenario === 'prepare-wrong-body' || scenario === 'prepare-prior-dispatch'
      || scenario.startsWith('capability-')) {
      assert.equal(code, 1);
      if (scenario === 'growing-retained-input' || scenario === 'prepare-marker-expiry') {
        const observed = JSON.parse(await fs.readFile(observationFile));
        assert.equal(observed.refused, true);
        assert.equal(observed.completeFetchInvocations, 0);
        assert.equal(completeBodies.length, 0);
        if (scenario === 'prepare-marker-expiry') {
          assert.equal(observed.markerReached, true);
          assert.deepEqual(methods, ['BeginBatch', 'GrantPartsBatch', 'ReportPartsBatch']);
          assert.equal(providerCalls.length, 1);
        } else {
          assert.equal(observed.grew, true);
          assert.equal(observed.unboundedReads, 0);
          assert(observed.maximumReadRequest > 0 && observed.maximumReadRequest <= 16385);
          assert(observed.totalReadBytes > 0 && observed.totalReadBytes <= 16385);
          assert.deepEqual(methods, []);
          assert.equal(providerCalls.length, 0);
        }
      }
      else if (scenario === 'changed-source' || scenario === 'expired-grant') assert.equal(providerCalls.length, 0);
      else if (['unknown-close', 'prepare-refused-start', 'prepare-unknown-start'].includes(scenario)) assert.equal(methods.filter(value => value === 'CompleteBatch').length, 1);
      else if (scenario === 'lost-next') assert.equal(methods.filter(value => value === 'CompleteBatch').length, 2);
      else if (scenario === 'capability-expired' || scenario === 'capability-extra' || scenario === 'capability-wrong-owner') {
        assert.deepEqual(methods, []);
        assert.equal(providerCalls.length, 0);
      } else if (scenario === 'capability-mismatch' || scenario === 'capability-malformed-placement') {
        assert.deepEqual(methods, ['BeginBatch']);
        assert.equal(providerCalls.length, 0);
      } else if (scenario === 'capability-substituted-session') {
        assert.deepEqual(methods, ['BeginBatch', 'GrantPartsBatch', 'ReportPartsBatch']);
        assert.equal(providerCalls.length, 1);
      } else assert.equal(methods.filter(value => value === 'CompleteBatch').length, 0);
      assert(!methods.includes('Abort'));
    } else {
      assert.equal(code, 2, Buffer.concat(stderr).toString());
      const result = JSON.parse(await fs.readFile(path.join(output, 'result.json')));
      assert.equal(result.status, 'incomplete');
      if (['prepare', 'prepare-capabilities', 'prepare-accepted', 'prepare-accepted-lost-next'].includes(scenario)) {
        assert.equal(result.mode, 'pre_complete_handoff');
        assert.equal(result.results.length, 1);
        assert.equal(result.results[0].raceQualification, null);
        assert.deepEqual(result.results[0].observedStates, ['completing_staging']);
        assert.equal(providerCalls.length, 1);
        assert.deepEqual(methods, ['BeginBatch', 'GrantPartsBatch', 'ReportPartsBatch', 'CompleteBatch']);
        console.log('PASS controlled prepared original dispatch; no SQL/runtime qualification');
        if (!scenario.startsWith('prepare-accepted')) continue;
      }
      if (!scenario.startsWith('prepare-accepted')) {
        assert.equal(result.results.length, 2);
        if (discoveredScenario) {
          assert.notEqual(result.results[0].placement.placementFingerprint, result.results[1].placement.placementFingerprint);
          for (const value of result.results) {
            const actual = sessions.find(session => session.session.sessionId === value.session.sessionId);
            assert.deepEqual(value.placement, actual.placements[0]);
            assert.notEqual(actual.session.logicalFingerprint, intentFingerprint(actual.intent));
          }
        }
        assert.equal(providerCalls.length, 6);
        for (const value of result.results) {
          assert.equal(value.raceQualification, null);
          assert.equal(value.racing.providerStartWitness, null);
          assert.equal(value.late.deniedNoSuchUpload, scenario !== 'wrong-denial');
          assert.equal(value.cleanupSettlement, null);
          assert.equal(value.positiveEtag, '"positive-original-part"');
        }
        assert.equal(result.results[0].finalRead.bytes, String(PART_BYTES));
        assert.equal(methods.filter(value => value === 'CompleteBatch').length, 2);
        assert.deepEqual(result.results[0].completeCalls.map(call => call.callIndex), [1, 2]);
        assert(!methods.includes('StatusBatch'));
        assert.equal(methods.filter(value => value === 'Abort').length, 1);
      }
    }
    if (['prepare-accepted', 'prepare-accepted-lost-next', 'prepare-refused-start', 'prepare-unknown-start'].includes(scenario)) {
      const reference = async file => {
        const bytes = await fs.readFile(file);
        return { file, sha256: sha(bytes), byteSize: String(bytes.length) };
      };
      const prepared = JSON.parse(await fs.readFile(path.join(output, 'pre-complete-prepared.json')));
      const firstFile = path.join(output, prepared.refs.completeBody.file.replace('-request.json', '-response.json'));
      const accepted = { version: 1, prepared: await reference(path.join(output, 'pre-complete-prepared.json')),
        firstResponse: scenario === 'prepare-unknown-start'
          ? { file: firstFile, sha256: '00'.repeat(32), byteSize: '1' } : await reference(firstFile) };
      const acceptedFile = path.join(root, `${scenario}-accepted.json`);
      await fs.writeFile(acceptedFile, JSON.stringify(accepted), { flag: 'wx', mode: 0o600 });
      const before = { methods: methods.length, puts: providerCalls.length, complete: completeBodies.length };
      const continuedOutput = path.join(root, `${scenario}-continued`);
      const continuationChild = spawn(process.execPath,
        [driverFile, selectionFile, continuedOutput, '--continue-accepted', acceptedFile],
        { env: { ...process.env, NODE_EXTRA_CA_CERTS: cert }, stdio: ['ignore', 'pipe', 'pipe'] });
      const continuationErrors = [];
      continuationChild.stderr.on('data', chunk => continuationErrors.push(chunk));
      continuationChild.stdout.resume();
      const continuationTimer = setTimeout(() => continuationChild.kill('SIGKILL'), 20000);
      const continuedCode = await new Promise(resolve => continuationChild.once('exit', resolve));
      clearTimeout(continuationTimer);
      assert.deepEqual(requestFailures, []);
      assert.equal(providerCalls.length, before.puts);
      assert(methods.slice(before.methods).every(method => method === 'CompleteBatch'));
      if (scenario === 'prepare-accepted') {
        assert.equal(continuedCode, 2, Buffer.concat(continuationErrors).toString());
        assert.equal(completeBodies.length, before.complete + 1);
        const result = JSON.parse(await fs.readFile(path.join(continuedOutput, 'result.json')));
        assert.equal(result.mode, 'accepted_original_continuation');
        assert.equal(result.publicationCommit, 'not_invoked');
        assert.equal(result.status, 'incomplete');
        assert.deepEqual(result.results[0].completeCalls.map(call => call.callIndex), [1, 2]);
        assert.equal(result.results[0].terminalState, 'committed');
        // The same consumed original cannot start a second continuation process.
        await assert.rejects(() => driver.continueAcknowledged(selection, accepted,
          path.join(root, `${scenario}-duplicated`)));
        assert.equal(completeBodies.length, before.complete + 1);
      } else {
        assert.equal(continuedCode, 1);
        assert.equal(completeBodies.length, before.complete + (scenario === 'prepare-accepted-lost-next' ? 1 : 0));
      }
      assert(completeBodies.every(body => body.equals(preparedCompleteBody)));
      console.log(`PASS controlled ${scenario} continuation: no Begin/Grant/provider PUT or unknown replay`);
    }
    console.log(`PASS controlled ${scenario}; no provider qualification`);
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
