// Install one bounded fixture identity through actual Miniflare KV.
// This slot selects test identity only; SQL terminal claims and independently
// probed Delete capability remain prerequisites in the production handler.
const { createHash } = require('node:crypto');

const FIXTURE_KEY = 'managed-oci-terminal-cleanup-fixture-v1';
const MAX_RECORD_BYTES = 4096;
const PROFILE_FIELDS = [
  'anchor', 'bindingName', 'clockPolicy', 'deploymentId', 'maximumProviderRequests',
  'namespaceId', 'namespaceObjectId', 'namespaceUniqueKey', 'nativeOrigin',
  'privateStagePolicy', 'publicOrigin', 'workerName', 'workerScriptVersion', 'workerSourceDigest',
].sort().join(',');

function fields(value, expected) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === expected;
}

function decodeRecord(request) {
  if (!fields(request, 'kind,recordBase64,recordSha256,version') || request.version !== 1
      || request.kind !== 'managed-oci-cleanup-fixture-install'
      || typeof request.recordBase64 !== 'string'
      || request.recordBase64.length > Math.ceil(MAX_RECORD_BYTES / 3) * 4
      || !/^[a-f0-9]{64}$/.test(request.recordSha256 ?? '')) {
    throw new Error('Managed cleanup fixture request shape differs');
  }
  const bytes = Buffer.from(request.recordBase64, 'base64');
  if (bytes.length === 0 || bytes.length > MAX_RECORD_BYTES
      || bytes.toString('base64') !== request.recordBase64
      || !Buffer.from(bytes.toString('utf8')).equals(bytes)
      || createHash('sha256').update(bytes).digest('hex') !== request.recordSha256) {
    throw new Error('Managed cleanup fixture bytes differ');
  }
  const record = JSON.parse(bytes.toString('utf8'));
  if (!fields(record, 'profile,selection,version') || record.version !== 1
      || !fields(record.selection,
        'deploymentId,expiresAt,issuedAt,placementPrefix,protectedProfileDigest,scriptVersion,sourceDigest,uncertaintySeconds')
      || !fields(record.profile, PROFILE_FIELDS)
      || !fields(record.profile.clockPolicy, 'mode,uncertaintySeconds,version')
      || !fields(record.profile.privateStagePolicy, 'namespace,policyDigest,policyId')
      || !fields(record.profile.anchor, 'object,sha256')
      || !fields(record.profile.anchor.object, 'etag,key,provider_version,size')) {
    throw new Error('Managed cleanup fixture record is not closed');
  }
  return { bytes, record };
}

async function installManagedCleanupFixture(runtime, options, request, namespaceObservation) {
  const { bytes, record } = decodeRecord(request);
  const bindings = options.bindings ?? {};
  const { selection, profile } = record;
  const namespace = options.kvNamespaces?.HUB_OCI_SDK_EMULATOR_ACCEPTANCE;
  if (typeof namespace !== 'string' || !namespace
      || Object.entries(options.kvNamespaces).some(([name, value]) =>
        name !== 'HUB_OCI_SDK_EMULATOR_ACCEPTANCE'
          && (typeof value === 'string' ? value : value?.id) === namespace)
      || !/^qualification\/oci-terminal-cleanup\/[a-z0-9-]{1,64}$/.test(selection.placementPrefix)
      || selection.placementPrefix !== bindings.HUB_MANAGED_OCI_CLEANUP_FIXTURE_PREFIX
      || profile.namespaceId !== bindings.HUB_MANAGED_OCI_CLEANUP_FIXTURE_NAMESPACE
      || selection.deploymentId !== bindings.HUB_DEPLOYMENT_ID
      || profile.deploymentId !== selection.deploymentId
      || profile.publicOrigin !== bindings.HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN
      || profile.nativeOrigin !== bindings.HUB_HYBRID_ORIGIN_URL
      || profile.clockPolicy.version !== 1 || profile.clockPolicy.mode !== 'bounded_utc'
      || profile.clockPolicy.mode !== bindings.HUB_DIRECT_UPLOAD_CLOCK_MODE
      || profile.clockPolicy.uncertaintySeconds !== bindings.HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS
      || String(selection.uncertaintySeconds) !== profile.clockPolicy.uncertaintySeconds
      || !Number.isInteger(profile.maximumProviderRequests)
      || profile.maximumProviderRequests < 2 || profile.maximumProviderRequests > 32
      || String(profile.maximumProviderRequests) !== bindings.HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS
      || !/^[a-f0-9]{64}$/.test(selection.protectedProfileDigest)
      || !/^[a-f0-9]{64}$/.test(selection.sourceDigest)
      || profile.workerSourceDigest !== selection.sourceDigest
      || profile.workerScriptVersion !== selection.scriptVersion
      || selection.scriptVersion !== `emulated-${selection.sourceDigest}`) {
    throw new Error('Managed cleanup fixture configured audience differs');
  }

  const checkWindow = () => {
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(selection.issuedAt) || !Number.isSafeInteger(selection.expiresAt)
        || !Number.isSafeInteger(selection.uncertaintySeconds)
        || selection.uncertaintySeconds < 1 || selection.uncertaintySeconds >= 30
        || selection.issuedAt <= 0 || selection.expiresAt - selection.issuedAt <= 0
        || selection.expiresAt - selection.issuedAt > 600
        || now < selection.issuedAt || now + selection.uncertaintySeconds >= selection.expiresAt) {
      throw new Error('Managed cleanup fixture window refused');
    }
  };
  const checkInstallation = observed => {
    const mapping = {
      workerName: observed.workerName, bindingName: observed.bindingName,
      namespaceId: observed.namespaceId, namespaceObjectId: observed.namespaceObjectId,
      namespaceUniqueKey: observed.namespaceUniqueKey,
      workerSourceDigest: observed.buildDerivedSourceDigest,
      workerScriptVersion: observed.buildDerivedScriptVersion,
    };
    if (observed.observationScope !== 'oci_sdk_emulator_namespace_readback'
        || observed.runnerPid !== process.pid
        || Object.entries(mapping).some(([name, value]) => profile[name] !== value)) {
      throw new Error('Managed cleanup fixture actual installation differs');
    }
    checkWindow();
    return observed;
  };

  const before = checkInstallation(await namespaceObservation());
  const registry = await runtime.getKVNamespace('HUB_OCI_SDK_EMULATOR_ACCEPTANCE', before.workerName);
  checkWindow();
  const encoded = bytes.toString('utf8');
  const existing = await registry.get(FIXTURE_KEY);
  checkWindow();
  if (existing !== null && existing !== encoded) {
    throw new Error('Managed cleanup fixture slot retains different bytes');
  }
  if (existing === null) await registry.put(FIXTURE_KEY, encoded);
  checkWindow();
  const retained = await registry.get(FIXTURE_KEY);
  checkWindow();
  if (retained !== encoded) throw new Error('Managed cleanup fixture KV readback differs');
  const after = checkInstallation(await namespaceObservation());
  if (before.configurationSha256 !== after.configurationSha256
      || before.runnerStartTicks !== after.runnerStartTicks || before.workerdPid !== after.workerdPid
      || before.workerdStartTicks !== after.workerdStartTicks
      || before.wasmSha256 !== after.wasmSha256 || before.shimSha256 !== after.shimSha256) {
    throw new Error('Managed cleanup runtime changed during fixture installation');
  }
  return { version: 1, status: 'stored', key: FIXTURE_KEY,
    recordSha256: request.recordSha256, byteSize: String(bytes.length),
    recordBase64: Buffer.from(retained).toString('base64'), runnerPid: after.runnerPid,
    runnerStartTicks: after.runnerStartTicks, configurationSha256: after.configurationSha256,
    sourceDigest: selection.sourceDigest, scriptVersion: selection.scriptVersion,
    namespaceId: after.namespaceId, namespaceObjectId: after.namespaceObjectId,
    scope: 'confined fixture identity stored in actual emulator KV; no Delete permission or provider effect' };
}

module.exports = { installManagedCleanupFixture, decodeRecord, FIXTURE_KEY, MAX_RECORD_BYTES };
