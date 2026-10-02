// Observe actual local R2 metadata and retained GC guard state in a confined
// fixture capture. The installed Worker's Rust brackets supply business SDK
// call evidence; this Node proxy is not a business SDK observer or authority.
const { createHash } = require('node:crypto');
const path = require('node:path');

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value));
const hex = (value, length) => typeof value === 'string'
  && new RegExp(`^[0-9a-f]{${length}}$`).test(value);

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function fields(value, names) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...names].sort().join(',');
}

function claimId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);
}

function boundedUnique(values, validate) {
  return Array.isArray(values) && values.length > 0 && values.length <= 32
    && values.every(validate) && new Set(values).size === values.length;
}

function strongEtag(value) {
  requireCondition(typeof value === 'string' && value.length > 0
    && Buffer.byteLength(value) <= 512 && !/[\u0000-\u001f\u007f-\u009f]/u.test(value)
    && !value.startsWith('W/'), 'R2 metadata lacks a strong ETag');
  if (value.startsWith('"') && value.endsWith('"')) return value;
  requireCondition(!value.includes('"'), 'R2 ETag quoting differs');
  return `"${value}"`;
}

function objectIdentity(value) {
  if (value === null) return null;
  requireCondition(value && Number.isSafeInteger(value.size) && value.size >= 0
    && typeof value.version === 'string' && Buffer.byteLength(value.version) > 0
    && Buffer.byteLength(value.version) <= 512
    && !/[\u0000-\u001f\u007f-\u009f]/u.test(value.version),
  'R2 HEAD lacks actual bounded upload metadata');
  return { version: value.version, etag: strongEtag(value.etag), size: value.size };
}

function positiveReceipt(receipt, id) {
  return fields(receipt, ['claim', 'outcome'])
    && fields(receipt.claim, ['claim_id', 'expected_etag', 'expected_size',
      'expected_hash', 'expected_provider_version'])
    && receipt.claim.claim_id === id && claimId(id)
    && Number.isSafeInteger(receipt.claim.expected_size) && receipt.claim.expected_size >= 0
    && typeof receipt.claim.expected_hash === 'string'
    && /^sha256:[0-9a-f]{64}$/.test(receipt.claim.expected_hash)
    && typeof receipt.claim.expected_provider_version === 'string'
    && receipt.claim.expected_provider_version.length > 0
    && Buffer.byteLength(receipt.claim.expected_provider_version) <= 512
    && !/[\u0000-\u001f\u007f-\u009f]/u.test(receipt.claim.expected_provider_version)
    && typeof receipt.claim.expected_etag === 'string'
    && strongEtag(receipt.claim.expected_etag) === receipt.claim.expected_etag
    && fields(receipt.outcome, ['kind', 'etag']) && receipt.outcome.kind === 'deleted'
    && receipt.outcome.etag === receipt.claim.expected_etag;
}

async function readJson(response, maximum) {
  requireCondition(response.status === 200 && response.body,
    'Guard observation lacks an actual successful response');
  const reader = response.body.getReader();
  const chunks = [];
  let byteSize = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      byteSize += value.byteLength;
      if (byteSize > maximum) {
        await reader.cancel();
        throw new Error('Guard observation exceeds its response bound');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = Buffer.concat(chunks);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return { value: JSON.parse(text), base64: bytes.toString('base64'), sha256: sha256(bytes) };
}

const R2_FIELDS = ['version', 'observationScope', 'observedAt', 'runnerPid',
  'runnerStartTicks', 'configurationSha256', 'runnerSha256', 'miniflareVersion',
  'miniflareModuleSha256', 'miniflareEntryWorkerSha256', 'miniflareBucketWorkerSha256',
  'shimSha256', 'wasmSha256', 'wasmByteSize', 'sourceStorePath', 'buildDerivedSourceDigest',
  'buildDerivedScriptVersion', 'workerName', 'bindingName', 'namespaceId',
  'namespaceUniqueKey', 'persistenceRoot', 'namespaceObjectId', 'workerdPid',
  'workerdStartTicks', 'workerdExecutableSha256'];
const GUARD_FIELDS = ['version', 'observationScope', 'observedAt', 'runnerPid',
  'runnerStartTicks', 'configurationSha256', 'runnerSha256', 'miniflareModuleSha256',
  'scriptSha256', 'bindingName', 'className', 'workerName', 'namespaceKey',
  'persistenceRoot', 'objectIds'];

function sameStable(first, current, dynamic) {
  return Object.keys(first).every(key => dynamic.includes(key)
    || JSON.stringify(first[key]) === JSON.stringify(current[key]));
}

// Factory callbacks must be the existing pinned runner's real namespace
// observers. Controlled unit-test callbacks establish structural refusals only.
async function createManagedGcObserver(runtime, options, configurationBytes, selection,
  r2NamespaceReadback, guardNamespaceReadback) {
  requireCondition(fields(selection, ['version', 'captureId', 'prefix'])
    && selection.version === 1 && hex(selection.captureId, 32)
    && typeof selection.prefix === 'string' && Buffer.byteLength(selection.prefix) <= 512
    && selection.prefix.split('/').every(part => !['', '.', '..'].includes(part))
    && !/[\u0000-\u001f\u007f-\u009f]/u.test(selection.prefix),
  'Managed observer requires its exact dedicated capture selection');
  const selectedKey = key => typeof key === 'string' && Buffer.byteLength(key) <= 512
    && key.startsWith(`${selection.prefix}/`) && key.length > selection.prefix.length + 1
    && !/[\u0000-\u001f\u007f-\u009f]/u.test(key);
  const expectedSelection = { version: 1, capture_id: selection.captureId, prefix: selection.prefix };
  const configuredSelection = JSON.parse(options.bindings?.HUB_MANAGED_GC_SDK_OBSERVER ?? 'null');
  requireCondition(fields(configuredSelection, Object.keys(expectedSelection))
    && Object.keys(expectedSelection).every(key => configuredSelection[key] === expectedSelection[key]),
  'Installed Worker observer configuration differs');
  const deploymentId = options.bindings?.HUB_DEPLOYMENT_ID;
  const guardConfig = options.durableObjects?.HYBRID_OBJECT_GUARD;
  requireCondition(typeof deploymentId === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(deploymentId)
    && typeof options.name === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(options.name)
    && typeof options.resourcePersistencePath === 'string'
    && path.isAbsolute(options.resourcePersistencePath)
    && guardConfig?.className === 'HybridObjectGuard' && guardConfig.useSQLite === true
    && (guardConfig.scriptName === undefined || guardConfig.scriptName === options.name),
  'Managed observer requires its actual local bucket/guard/deployment mapping');
  const configurationSha256 = sha256(configurationBytes);
  const positives = new Map();
  let original;
  let busy = false;

  async function namespaces() {
    const r2 = JSON.parse(encode(await r2NamespaceReadback()).toString('utf8'));
    const guard = JSON.parse(encode(await guardNamespaceReadback()).toString('utf8'));
    requireCondition(fields(r2, R2_FIELDS) && fields(guard, GUARD_FIELDS)
      && encode(r2).length <= 16 * 1024 && encode(guard).length <= 128 * 1024
      && r2.version === 1 && guard.version === 1
      && r2.observationScope === 'oci_sdk_emulator_namespace_readback'
      && guard.observationScope === 'selected_emulator_namespace_readback'
      && r2.configurationSha256 === configurationSha256
      && guard.configurationSha256 === configurationSha256
      && r2.workerName === options.name && guard.workerName === options.name
      && r2.bindingName === 'REGISTRY_BUCKET' && guard.bindingName === 'HYBRID_OBJECT_GUARD'
      && r2.namespaceUniqueKey === 'miniflare-R2BucketObject'
      && guard.className === 'HybridObjectGuard'
      && r2.persistenceRoot === path.join(options.resourcePersistencePath, 'r2')
      && guard.persistenceRoot === options.resourcePersistencePath
      && r2.runnerPid === guard.runnerPid && r2.runnerStartTicks === guard.runnerStartTicks
      && r2.runnerSha256 === guard.runnerSha256
      && r2.miniflareModuleSha256 === guard.miniflareModuleSha256
      && r2.shimSha256 === guard.scriptSha256
      && hex(r2.namespaceObjectId, 64) && typeof guard.namespaceKey === 'string'
      && Array.isArray(guard.objectIds) && guard.objectIds.length <= 1024
      && guard.objectIds.every(id => hex(id, 64)) && new Set(guard.objectIds).size === guard.objectIds.length,
    'Actual namespace readback differs from configured backing');
    const bucket = options.r2Buckets?.REGISTRY_BUCKET;
    requireCondition((typeof bucket === 'string' ? bucket : bucket?.id) === r2.namespaceId,
      'Actual R2 namespace differs from the installed selected bucket');
    if (original) {
      requireCondition(sameStable(original.r2, r2, ['observedAt'])
        && sameStable(original.guard, guard, ['observedAt', 'objectIds']),
      'Installed namespace, source or process changed during observation');
    }
    return { r2, guard };
  }

  original = await namespaces();
  const originalR2Bytes = encode(original.r2);
  const originalGuardBytes = encode(original.guard);
  const backingIdentity = sha256(originalR2Bytes);

  async function inspected(key, ids) {
    const namespace = await runtime.getDurableObjectNamespace('HYBRID_OBJECT_GUARD', options.name);
    const guardName = `${deploymentId}:${sha256(Buffer.from(key))}`;
    const id = namespace.idFromName(guardName);
    const stubId = id.toString();
    requireCondition(hex(stubId, 64), 'Physical guard stub identity differs');
    const stub = namespace.get(id);
    const response = await stub.fetch('https://managed-gc-guard.invalid/_e2e/managed-gc-state', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-aos-hybrid-object-key': key },
      body: JSON.stringify({ version: 1, capture_id: selection.captureId, claim_ids: ids }),
    });
    const observation = await readJson(response, 128 * 1024);
    const value = observation.value;
    requireCondition(fields(value, ['version', 'captureId', 'key', 'guardName', 'deleteReceipts',
      'pendingDelete', 'pendingMutation']) && value.version === 1
      && value.captureId === selection.captureId && value.key === key && value.guardName === guardName
      && fields(value.deleteReceipts, ids), 'Retained state belongs to a different guard or capture');
    return { observation, stub, stubId };
  }

  async function exclusive(action) {
    requireCondition(!busy, 'Managed observation already has an active request');
    busy = true;
    try { return await action(); } finally { busy = false; }
  }

  async function snapshot(request) {
    return exclusive(async () => {
      requireCondition(fields(request, ['version', 'kind', 'keys', 'claimIds'])
        && request.version === 1 && request.kind === 'managed-gc-snapshot'
        && boundedUnique(request.keys, selectedKey) && boundedUnique(request.claimIds, claimId),
      'Managed snapshot selectors differ or exceed their bound');
      const before = await namespaces();
      const bucket = await runtime.getR2Bucket('REGISTRY_BUCKET', options.name);
      const objects = {};
      const guards = {};
      const guardReads = {};
      const pendingPositives = new Map();
      for (const key of request.keys) {
        objects[key] = objectIdentity(await bucket.head(key));
        const retained = await inspected(key, request.claimIds);
        guards[key] = retained.observation.value;
        guardReads[key] = { base64: retained.observation.base64,
          sha256: retained.observation.sha256, stubId: retained.stubId };
        for (const id of request.claimIds) {
          const receipt = guards[key].deleteReceipts[id];
          if (receipt !== null) {
            requireCondition(receipt.claim?.claim_id === id, 'Retained claim selector differs');
            if (positiveReceipt(receipt, id)) pendingPositives.set(`${key}\n${id}`, sha256(encode(receipt)));
          }
        }
      }
      const after = await namespaces();
      const result = { version: 1, kind: 'managed-gc-snapshot', backingIdentity,
        originalR2NamespaceBase64: originalR2Bytes.toString('base64'),
        originalGuardNamespaceBase64: originalGuardBytes.toString('base64'),
        before, after, objects, guards, guardReads };
      requireCondition(encode(result).length <= 1024 * 1024, 'Managed snapshot exceeds its metadata bound');
      requireCondition(new Set([...positives.keys(), ...pendingPositives.keys()]).size <= 32,
        'Managed positive replay selection exceeds its bound');
      for (const [key, digest] of pendingPositives) positives.set(key, digest);
      return result;
    });
  }

  async function physicalReplay(request) {
    return exclusive(async () => {
      requireCondition(fields(request, ['version', 'kind', 'key', 'claimId', 'receiptSha256'])
        && request.version === 1 && request.kind === 'managed-gc-positive-replay'
        && selectedKey(request.key) && claimId(request.claimId) && hex(request.receiptSha256, 64)
        && positives.get(`${request.key}\n${request.claimId}`) === request.receiptSha256,
      'Physical replay lacks a prior actual selected positive observation');
      const before = await namespaces();
      const retained = await inspected(request.key, [request.claimId]);
      const value = retained.observation.value;
      const receipt = value.deleteReceipts[request.claimId];
      requireCondition(value.pendingDelete === null && value.pendingMutation === null
        && positiveReceipt(receipt, request.claimId)
        && sha256(encode(receipt)) === request.receiptSha256,
      'Physical replay original is missing, changed or unresolved');
      const response = await retained.stub.fetch('https://managed-gc-guard.invalid/delete', {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-aos-hybrid-object-key': request.key },
        body: JSON.stringify(receipt.claim),
      });
      const reply = await readJson(response, 8192);
      requireCondition(fields(reply.value, ['kind', 'outcome']) && reply.value.kind === 'delete'
        && fields(reply.value.outcome, ['kind', 'etag'])
        && reply.value.outcome.kind === receipt.outcome.kind
        && reply.value.outcome.etag === receipt.outcome.etag,
      'Physical replay reply differs from the retained positive');
      const current = await inspected(request.key, [request.claimId]);
      requireCondition(current.stubId === retained.stubId
        && current.observation.sha256 === retained.observation.sha256,
      'Physical replay changed actual guard state');
      const after = await namespaces();
      return { version: 1, kind: 'managed-gc-positive-replay', backingIdentity, before, after,
        key: request.key, claimId: request.claimId, receiptSha256: request.receiptSha256,
        guardBefore: retained.observation, guardAfter: current.observation, reply,
        stubId: retained.stubId };
    });
  }

  return { snapshot, physicalReplay };
}

module.exports = { createManagedGcObserver };
