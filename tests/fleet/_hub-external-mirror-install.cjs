// Confined storage of an independently reviewed functional Mirror artifact.
// Rust derives and verifies the slot; this owner stores exact bytes only.
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

const ARTIFACT_FIELDS = [
  'deploymentId', 'directEvidenceSha256', 'execution', 'externalDomainSha256',
  'installation', 'issuedAt', 'maximumObjectBytes', 'placementPrefix',
  'protectedProfile', 'publicOrigin', 'purpose', 'reviewerKeyId', 'scriptVersion',
  'signature', 'sourceDigest', 'upstreamBase', 'validUntil', 'version',
].sort().join(',');

const INSTALLATION_FIELDS = [
  'artifactManifestSha256', 'clockObservationSha256', 'configurationSha256',
  'namespaceObservationSha256', 'nativeExecutableSha256',
  'prerequisiteArtifactSha256', 'providerContractObservationSha256',
  'scriptSha256', 'wasmSha256',
].sort().join(',');

function closed(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === fields;
}

function hash(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function installExternalMirrorFunctional(runtime, options, request, namespaceObservation) {
  const bindings = options.bindings ?? {};
  const namespaces = options.kvNamespaces;
  const registryId = namespaces?.HUB_EXTERNAL_MIRROR_FUNCTIONAL_ACCEPTANCE;
  if (!closed(request, 'artifactBase64,artifactSha256,key,kind,version')
      || request.version !== 1 || request.kind !== 'external-mirror-functional-install'
      || typeof request.key !== 'string'
      || !/^controlled-external-mirror-v1:[0-9a-f]{64}$/.test(request.key)
      || typeof request.artifactBase64 !== 'string'
      || !/^[0-9a-f]{64}$/.test(request.artifactSha256 ?? '')
      || !namespaces || Array.isArray(namespaces)
      || typeof registryId !== 'string' || !registryId
      || Object.entries(namespaces).some(([name, value]) =>
        name !== 'HUB_EXTERNAL_MIRROR_FUNCTIONAL_ACCEPTANCE'
          && (typeof value === 'string' ? value : value?.id) === registryId)
      || bindings.HUB_EXTERNAL_MIRROR_FUNCTIONAL_PROBE !== '1'
      || !/^[0-9a-f]{64}$/.test(bindings.HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_PUBLIC_KEY ?? '')
      || typeof namespaceObservation !== 'function') {
    throw new Error('External Mirror typed storage selection differs');
  }

  const bytes = Buffer.from(request.artifactBase64, 'base64');
  if (!bytes.length || bytes.length > 32 * 1024
      || bytes.toString('base64') !== request.artifactBase64
      || hash(bytes) !== request.artifactSha256
      || !Buffer.from(bytes.toString('utf8'), 'utf8').equals(bytes)) {
    throw new Error('External Mirror typed storage bytes differ');
  }
  const artifact = JSON.parse(bytes.toString('utf8'));
  if (!closed(artifact, ARTIFACT_FIELDS) || artifact.version !== 1
      || artifact.purpose !== 'full_and_pull_through_functional_probe_v1'
      || artifact.execution !== 'emulated_external'
      || artifact.reviewerKeyId !== bindings.HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_KEY_ID
      || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(artifact.reviewerKeyId ?? '')
      || artifact.deploymentId !== bindings.HUB_DEPLOYMENT_ID
      || artifact.publicOrigin !== bindings.HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN
      || !/^[0-9a-f]{64}$/.test(artifact.sourceDigest ?? '')
      || artifact.scriptVersion !== `emulated-${artifact.sourceDigest}`
      || !/^[0-9a-f]{128}$/.test(artifact.signature ?? '')
      || !/^[0-9a-f]{64}$/.test(artifact.directEvidenceSha256 ?? '')
      || !/^[0-9a-f]{64}$/.test(artifact.externalDomainSha256 ?? '')
      || !closed(artifact.installation, INSTALLATION_FIELDS)
      || Object.values(artifact.installation).some(value =>
        typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))
      || !closed(artifact.protectedProfile, 'profile,runtimeQualification')) {
    throw new Error('External Mirror typed storage purpose or installed audience differs');
  }
  const root = /^\.aos-mirror-qualification\/([0-9a-f]{32})\/final$/.exec(artifact.placementPrefix);
  if (!root || artifact.upstreamBase !== `https://aos.andyl.org:4778/fleet-mirror/${root[1]}`
      || !Number.isSafeInteger(artifact.maximumObjectBytes)
      || artifact.maximumObjectBytes < 1 || artifact.maximumObjectBytes > 512 * 1024 * 1024
      || !Number.isSafeInteger(artifact.issuedAt) || !Number.isSafeInteger(artifact.validUntil)
      || artifact.issuedAt <= 0 || artifact.validUntil <= artifact.issuedAt
      || artifact.validUntil - artifact.issuedAt > 900) {
    throw new Error('External Mirror typed storage reserved scope or window differs');
  }

  const mirror = JSON.parse(bindings.HUB_EXTERNAL_MIRROR_CONSUMER ?? 'null');
  if (!mirror || mirror.version !== 1 || !Array.isArray(mirror.domains)
      || mirror.domains.filter(domain =>
        isDeepStrictEqual(domain.profile, artifact.protectedProfile)).length !== 1) {
    throw new Error('External Mirror typed storage profile is not the installed domain');
  }
  const selectedDomain = mirror.domains.find(domain =>
    isDeepStrictEqual(domain.profile, artifact.protectedProfile));
  if (!isDeepStrictEqual(selectedDomain.issuer_installation,
      artifact.protectedProfile.profile.issuerInstallation)) {
    throw new Error('External Mirror typed storage issuer differs from the installed profile');
  }

  const checkWindow = () => {
    const now = Math.floor(Date.now() / 1000);
    if (now < artifact.issuedAt || now >= artifact.validUntil) {
      throw new Error('External Mirror typed storage original is outside its window');
    }
  };
  const checkNamespace = observed => {
    const guard = observed?.namespaces?.filter(value => value.bindingName === 'EXTERNAL_OBJECT_GUARD');
    if (observed?.version !== 1
        || observed.observationScope !== 'selected_external_copy_namespace_readback'
        || observed.runnerPid !== process.pid
        || !/^[0-9]+$/.test(observed.runnerStartTicks ?? '')
        || observed.applicationWorkerName !== options.name
        || observed.persistenceRoot !== options.resourcePersistencePath
        || observed.configurationSha256 !== artifact.installation.configurationSha256
        || observed.scriptSha256 !== artifact.installation.scriptSha256
        || guard?.length !== 1 || guard[0].className !== 'ExternalObjectGuard'
        || guard[0].workerName !== observed.sourceWorkerName
        || typeof guard[0].namespaceKey !== 'string' || !guard[0].namespaceKey) {
      throw new Error('External Mirror typed storage live namespace differs');
    }
    return observed;
  };
  checkWindow();
  const before = checkNamespace(await namespaceObservation());
  checkWindow();
  const registry = await runtime.getKVNamespace('HUB_EXTERNAL_MIRROR_FUNCTIONAL_ACCEPTANCE', options.name);
  checkWindow();
  const existing = await registry.get(request.key);
  const encoded = bytes.toString('utf8');
  if (existing !== null && existing !== encoded) {
    throw new Error('External Mirror typed storage slot retains different bytes');
  }
  checkWindow();
  if (existing === null) await registry.put(request.key, encoded);
  checkWindow();
  const retained = await registry.get(request.key);
  if (retained !== encoded) throw new Error('External Mirror typed storage readback differs');
  const after = checkNamespace(await namespaceObservation());
  checkWindow();
  for (const field of ['runnerStartTicks', 'configurationSha256', 'runnerSha256',
    'isolationModuleSha256', 'miniflareModuleSha256', 'scriptSha256', 'applicationWorkerName',
    'sourceWorkerName', 'persistenceRoot']) {
    if (before[field] !== after[field]) {
      throw new Error('External Mirror typed storage installation changed during storage');
    }
  }
  if (!isDeepStrictEqual(before.namespaces.map(({ objectIds, ...identity }) => identity),
      after.namespaces.map(({ objectIds, ...identity }) => identity))) {
    throw new Error('External Mirror typed storage namespace changed during storage');
  }
  return {
    version: 1, status: 'stored', key: request.key, artifactSha256: request.artifactSha256,
    byteSize: String(bytes.length), runnerPid: after.runnerPid,
    runnerStartTicks: after.runnerStartTicks, artifactBase64: Buffer.from(retained).toString('base64'),
  };
}

module.exports = { installExternalMirrorFunctional };
