// Controlled callback/stub tests only. These establish structural refusal and
// exact API arguments, not genuine Miniflare state or provider qualification.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');
const { createManagedGcObserver } = require('./_hub-managed-gc-runner-observer.cjs');

const sha = value => createHash('sha256').update(value).digest('hex');
const copy = value => JSON.parse(JSON.stringify(value));

async function fixture() {
  const captureId = 'a'.repeat(32);
  const key = 'controlled/gc/object';
  const claim = { claim_id: 'actual-action', expected_etag: '"actual-tag"', expected_size: 42,
    expected_hash: `sha256:${'b'.repeat(64)}`, expected_provider_version: 'actual-upload' };
  const receipt = { claim, outcome: { kind: 'deleted', etag: claim.expected_etag } };
  const configurationBytes = Buffer.from('controlled configuration bytes');
  const options = { name: 'managed-worker', resourcePersistencePath: '/controlled/persistence',
    bindings: { HUB_DEPLOYMENT_ID: 'controlled-deployment',
      HUB_MANAGED_GC_SDK_OBSERVER: JSON.stringify({ version: 1, capture_id: captureId, prefix: 'controlled/gc' }) },
    r2Buckets: { REGISTRY_BUCKET: 'controlled-managed-bucket' },
    durableObjects: { HYBRID_OBJECT_GUARD: { className: 'HybridObjectGuard', useSQLite: true } } };
  const digest = 'c'.repeat(64);
  const r2 = { version: 1, observationScope: 'oci_sdk_emulator_namespace_readback', observedAt: 'controlled-time',
    runnerPid: 11, runnerStartTicks: '12', configurationSha256: sha(configurationBytes), runnerSha256: digest,
    miniflareVersion: 'controlled-version', miniflareModuleSha256: digest,
    miniflareEntryWorkerSha256: digest, miniflareBucketWorkerSha256: digest,
    shimSha256: digest, wasmSha256: digest, wasmByteSize: 42, sourceStorePath: '/controlled/source',
    buildDerivedSourceDigest: digest, buildDerivedScriptVersion: `emulated-${digest}`,
    workerName: options.name, bindingName: 'REGISTRY_BUCKET', namespaceId: 'controlled-managed-bucket',
    namespaceUniqueKey: 'miniflare-R2BucketObject', persistenceRoot: '/controlled/persistence/r2',
    namespaceObjectId: digest, workerdPid: 13, workerdStartTicks: '14', workerdExecutableSha256: digest };
  const guardReport = { version: 1, observationScope: 'selected_emulator_namespace_readback',
    observedAt: 'controlled-time', runnerPid: 11, runnerStartTicks: '12', configurationSha256: sha(configurationBytes),
    runnerSha256: digest, miniflareModuleSha256: digest, scriptSha256: digest,
    bindingName: 'HYBRID_OBJECT_GUARD', className: 'HybridObjectGuard', workerName: options.name,
    namespaceKey: 'actual-selected-namespace-key', persistenceRoot: '/controlled/persistence', objectIds: [] };
  const guardName = `${options.bindings.HUB_DEPLOYMENT_ID}:${sha(Buffer.from(key))}`;
  const state = { version: 1, captureId, key, guardName, deleteReceipts: { 'actual-action': receipt },
    pendingDelete: null, pendingMutation: null };
  const calls = [];
  const stub = { async fetch(url, request) {
    calls.push({ url, request: copy(request) });
    assert.equal(request.headers['x-aos-hybrid-object-key'], key);
    if (url.endsWith('/_e2e/managed-gc-state')) {
      assert.deepEqual(JSON.parse(request.body), { version: 1, capture_id: captureId, claim_ids: ['actual-action'] });
      return Response.json(state);
    }
    assert.ok(url.endsWith('/delete'));
    assert.deepEqual(JSON.parse(request.body), claim);
    return Response.json({ kind: 'delete', outcome: {
      etag: receipt.outcome.etag, kind: receipt.outcome.kind } });
  } };
  const runtime = {
    async getR2Bucket(binding, worker) {
      assert.equal(binding, 'REGISTRY_BUCKET'); assert.equal(worker, options.name);
      return { async head(selected) {
        calls.push({ sdkProxyHead: selected }); assert.equal(selected, key);
        return { size: 42, etag: 'actual-tag', version: 'actual-upload' };
      } };
    },
    async getDurableObjectNamespace(binding, worker) {
      assert.equal(binding, 'HYBRID_OBJECT_GUARD'); assert.equal(worker, options.name);
      return { idFromName(name) {
        assert.equal(name, guardName); return { toString: () => 'd'.repeat(64) };
      }, get: () => stub };
    },
  };
  const observer = await createManagedGcObserver(runtime, options, configurationBytes,
    { version: 1, captureId, prefix: 'controlled/gc' }, async () => copy(r2), async () => copy(guardReport));
  const snapshot = { version: 1, kind: 'managed-gc-snapshot', keys: [key], claimIds: ['actual-action'] };
  const replay = { version: 1, kind: 'managed-gc-positive-replay', key, claimId: 'actual-action',
    receiptSha256: sha(Buffer.from(JSON.stringify(receipt))) };
  return { observer, snapshot, replay, calls, state, receipt: copy(receipt), r2, guardReport };
}

test('actual callback values and exact stored claim are retained without coverage inference', async () => {
  const selected = await fixture();
  const snapshot = await selected.observer.snapshot(selected.snapshot);
  assert.deepEqual(snapshot.objects[selected.snapshot.keys[0]], {
    size: 42, etag: '"actual-tag"', version: 'actual-upload' });
  assert.equal(snapshot.backingIdentity, sha(Buffer.from(snapshot.originalR2NamespaceBase64, 'base64')));
  assert.equal(snapshot.coverage, undefined);
  assert.equal(snapshot.guards[selected.snapshot.keys[0]].deleteReceipts['actual-action'].claim.claim_id, 'actual-action');
  const replay = await selected.observer.physicalReplay(selected.replay);
  assert.equal(replay.guardBefore.sha256, replay.guardAfter.sha256);
  assert.equal(selected.calls.filter(call => call.url?.endsWith('/delete')).length, 1);
  assert.equal(replay.coverage, undefined);
});

test('unobserved, changed and unresolved claims refuse before physical replay', async () => {
  const selected = await fixture();
  await assert.rejects(selected.observer.physicalReplay(selected.replay));
  assert.equal(selected.calls.length, 0);
  await selected.observer.snapshot(selected.snapshot);
  for (const mutate of [
    () => { selected.state.deleteReceipts['actual-action'].claim.expected_provider_version = 'changed-upload'; },
    () => { selected.state.pendingDelete = { unknown: 'effect' }; },
    () => { selected.state.deleteReceipts['actual-action'] = null; },
  ]) {
    selected.state.deleteReceipts['actual-action'] = copy(selected.receipt);
    selected.state.pendingDelete = null;
    mutate();
    await assert.rejects(selected.observer.physicalReplay(selected.replay));
  }
  assert.equal(selected.calls.filter(call => call.url?.endsWith('/delete')).length, 0);
});

test('mapping/source changes refuse while raw dynamic object IDs are retained', async () => {
  const selected = await fixture();
  selected.guardReport.objectIds.push('e'.repeat(64));
  const snapshot = await selected.observer.snapshot(selected.snapshot);
  assert.deepEqual(snapshot.after.guard.objectIds, ['e'.repeat(64)]);
  assert.deepEqual(JSON.parse(Buffer.from(snapshot.originalGuardNamespaceBase64, 'base64')).objectIds, []);
  const before = selected.calls.length;
  selected.r2.workerdStartTicks = 'changed-start';
  await assert.rejects(selected.observer.snapshot(selected.snapshot));
  assert.equal(selected.calls.length, before);
});

test('closed key/claim bounds and exact snapshot scope refuse without SDK requests', async () => {
  const selected = await fixture();
  for (const changed of [
    { ...selected.snapshot, extra: true }, { ...selected.snapshot, keys: [] },
    { ...selected.snapshot, keys: ['other/object'] },
    { ...selected.snapshot, keys: [selected.snapshot.keys[0], selected.snapshot.keys[0]] },
    { ...selected.snapshot, claimIds: Array.from({ length: 33 }, (_, id) => `claim-${id}`) },
  ]) await assert.rejects(selected.observer.snapshot(changed));
  assert.equal(selected.calls.length, 0);
});
