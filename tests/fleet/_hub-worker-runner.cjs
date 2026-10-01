// Serve the built Worker with real workerd and persistent Miniflare bindings.
// Persistent bindings and direct workerd dispatch keep the fleet independent
// of Wrangler's live development proxy and external Request.cf discovery.
const { createHash } = require('node:crypto');
const { chmodSync, closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  readlinkSync, readSync, realpathSync, writeFileSync, writeSync, fsyncSync, mkdirSync, existsSync } = require('node:fs');
const { createRequire } = require('node:module');
const { createServer } = require('node:net');
const path = require('node:path');

function acceptanceRegistryServer(runtime, socketPath, bindings, namespaceObservation, ociNamespaceObservation, ociAnchorCreation) {
  const parent = lstatSync(path.dirname(socketPath));
  if (!parent.isDirectory() || parent.uid !== process.getuid() || (parent.mode & 0o077)) {
    throw new Error('Acceptance control requires an owner-private directory');
  }
  const sockets = new Set();
  const server = createServer({ allowHalfOpen: true }, socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
    const chunks = [];
    let byteSize = 0;
    socket.setTimeout(10_000, () => socket.destroy());
    socket.on('data', bytes => {
      byteSize += bytes.length;
      if (byteSize > 96 * 1024) {
        socket.destroy();
        return;
      }
      chunks.push(bytes);
    });
    socket.once('end', async () => {
      try {
        const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        const fields = Object.keys(request).sort().join(',');
        if (request.version === 1 && fields === 'kind,version'
            && request.kind === 'namespace-readback') {
          socket.end(JSON.stringify(await namespaceObservation()) + '\n');
          return;
        }
        if (request.version === 1 && fields === 'kind,version'
            && request.kind === 'oci-sdk-namespace-readback') {
          socket.end(JSON.stringify(await ociNamespaceObservation()) + '\n');
          return;
        }
        if (request.version === 1 && request.kind === 'oci-sdk-anchor-create') {
          socket.end(JSON.stringify(await ociAnchorCreation(request)) + '\n');
          return;
        }
        if (request.version !== 1 || fields !== 'artifactBase64,artifactSha256,key,version') {
          throw new Error('Invalid acceptance installation request');
        }
        if (typeof request.artifactBase64 !== 'string' || typeof request.key !== 'string'
            || !/^[0-9a-f]{64}$/.test(request.artifactSha256)) {
          throw new Error('Invalid acceptance installation identity');
        }
        const bytes = Buffer.from(request.artifactBase64, 'base64');
        const digest = createHash('sha256').update(bytes).digest('hex');
        if (bytes.length > 64 * 1024 || bytes.toString('base64') !== request.artifactBase64
            || digest !== request.artifactSha256
            || !Buffer.from(bytes.toString('utf8'), 'utf8').equals(bytes)) {
          throw new Error('Acceptance installation bytes changed');
        }
        const artifact = JSON.parse(bytes.toString('utf8'));
        const identity = request.key.split('/');
        if (identity.length !== 4 || identity[0] !== 'aos.direct-upload.acceptance.v1'
            || identity[1] !== artifact.deploymentId || identity[2] !== artifact.sourceDigest
            || identity[3] !== artifact.scriptVersion || artifact.version !== 1
            || artifact.executionKind !== 'emulated_external'
            || artifact.deploymentId !== bindings.HUB_DEPLOYMENT_ID
            || artifact.publicOrigin !== bindings.HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN
            || !/^[0-9a-f]{64}$/.test(artifact.sourceDigest)
            || artifact.scriptVersion !== `emulated-${artifact.sourceDigest}`
            || !/^[0-9a-f]{128}$/.test(artifact.signature)) {
          throw new Error('Acceptance installation differs from emulator audience');
        }
        // This writes an independently reviewed artifact through the real KV
        // API. Worker dispatch still verifies its signature and complete typed
        // evidence against the installed verifier and exact runtime/profile.
        const registry = await runtime.getKVNamespace('HUB_DIRECT_UPLOAD_ACCEPTANCE');
        const existing = await registry.get(request.key);
        if (existing !== null && existing !== bytes.toString('utf8')) {
          throw new Error('Acceptance registry already retains a different artifact');
        }
        await registry.put(request.key, bytes.toString('utf8'));
        const retained = await registry.get(request.key);
        if (retained !== bytes.toString('utf8')) {
          throw new Error('Acceptance registry readback differs');
        }
        socket.end(JSON.stringify({
          version: 1, status: 'installed', key: request.key,
          artifactSha256: digest, byteSize: String(bytes.length), runnerPid: process.pid,
        }) + '\n');
      } catch {
        socket.end(JSON.stringify({ version: 1, status: 'refused' }) + '\n');
      }
    });
  });
  const ready = new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      chmodSync(socketPath, 0o600);
      resolve();
    });
  });
  return {
    ready,
    close: () => new Promise(resolve => {
      for (const socket of sockets) socket.destroy();
      server.close(resolve);
    }),
  };
}

// This observation uses a version-specific internal namespace proxy. Any change
// to the installed plugin or its entry worker requires a fresh source review.
const OCI_MINIFLARE_PIN = Object.freeze({
  version: '5.20260801.0-alpha',
  moduleSha256: '973b3563e0e4ac82531642131ebff32b77edfced4ba7f56123a2b09d37c15d01',
  entryWorkerSha256: 'b2fb3bd5bbbbfb0cda1466267d253aa6398f8ab905d7eb46bfa58f22c432cf71',
  bucketWorkerSha256: '9936813cefd2b631103eec819d20fbf99e134c224736f73063b6ffff3230c817',
});

function ociHashFile(filename, maximum, followLink = false) {
  const flags = constants.O_RDONLY | constants.O_NONBLOCK
    | (followLink ? 0 : constants.O_NOFOLLOW);
  const descriptor = openSync(filename, flags);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size > BigInt(maximum)) {
      throw new Error('OCI observation file exceeds its regular-file bound');
    }
    const digest = createHash('sha256');
    const block = Buffer.alloc(1024 * 1024);
    let byteSize = 0;
    for (let length; (length = readSync(descriptor, block, 0, block.length, null)) !== 0;) {
      byteSize += length;
      if (byteSize > maximum) throw new Error('OCI observation file grew beyond its bound');
      digest.update(block.subarray(0, length));
    }
    const after = fstatSync(descriptor, { bigint: true });
    const fields = ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'];
    if (fields.some(field => before[field] !== after[field])
        || BigInt(byteSize) !== before.size) {
      throw new Error('OCI observation file changed during hashing');
    }
    return { sha256: digest.digest('hex'), byteSize: String(byteSize) };
  } finally {
    closeSync(descriptor);
  }
}

function ociProcText(filename, maximum = 8192) {
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const buffer = Buffer.alloc(maximum + 1);
    const count = readSync(descriptor, buffer, 0, buffer.length, null);
    if (count > maximum) throw new Error('OCI process input exceeds its bound');
    return buffer.subarray(0, count).toString('utf8');
  } finally {
    closeSync(descriptor);
  }
}

function ociProcessIdentity(pid) {
  const directory = `/proc/${pid}`;
  const fields = ociProcText(`${directory}/stat`).split(') ').at(-1).trim().split(/\s+/);
  const owner = lstatSync(directory).uid;
  const executable = readlinkSync(`${directory}/exe`);
  if (fields.length < 20 || fields[0] === 'Z' || !/^[1-9][0-9]*$/.test(fields[19])
      || owner !== process.getuid() || !path.isAbsolute(executable)) {
    throw new Error('OCI process identity is unavailable');
  }
  return { pid, startTicks: fields[19], parentPid: Number(fields[1]), owner, executable };
}

function ociSameProcess(before, after) {
  return ['pid', 'startTicks', 'parentPid', 'owner', 'executable']
    .every(field => before[field] === after[field]);
}

function ociWorkerdIdentity(expectedExecutable) {
  const children = ociProcText(`/proc/${process.pid}/task/${process.pid}/children`)
    .trim().split(/\s+/).filter(Boolean);
  if (children.length > 32 || children.some(pid => !/^[1-9][0-9]{0,9}$/.test(pid))) {
    throw new Error('OCI runtime child set exceeds its bound');
  }
  const matches = children.map(pid => ociProcessIdentity(Number(pid)))
    .filter(child => child.executable === expectedExecutable);
  if (matches.length !== 1 || matches[0].parentPid !== process.pid) {
    throw new Error('OCI observation requires one exact runtime child');
  }
  return matches[0];
}

function ociLocalR2Selection(api, options) {
  const parsed = api.R2OptionsSchema.parse(options);
  const entries = api.namespaceEntries(parsed.r2Buckets);
  const selected = entries.filter(([binding]) => binding === 'REGISTRY_BUCKET');
  if (selected.length !== 1 || typeof options.name !== 'string'
      || !/^[a-zA-Z0-9_.-]{1,128}$/.test(options.name)) {
    throw new Error('OCI observation requires one selected Worker R2 binding');
  }
  const [, bucket] = selected[0];
  if (Object.keys(bucket).sort().join(',') !== 'id' || typeof bucket.id !== 'string'
      || !/^[a-zA-Z0-9_.-]{1,128}$/.test(bucket.id)
      || entries.some(([binding, value]) => binding !== 'REGISTRY_BUCKET' && value.id === bucket.id)
      || typeof options.resourcePersistencePath !== 'string'
      || !path.isAbsolute(options.resourcePersistencePath)
      || options.resourcePersistencePath.length > 4096) {
    // Remote bindings and S3 credential aliases have different custody and
    // cannot be admitted by this local SDK attachment observation.
    throw new Error('OCI observation requires an unambiguous local R2 namespace');
  }
  return {
    workerName: options.name,
    bindingName: 'REGISTRY_BUCKET',
    namespaceId: bucket.id,
    namespaceUniqueKey: 'miniflare-R2BucketObject',
    persistenceRoot: path.join(options.resourcePersistencePath, 'r2'),
  };
}

function ociMiniflareImplementation(load) {
  const modulePath = load.resolve('miniflare');
  const moduleRoot = path.resolve(path.dirname(modulePath), '../..');
  const packageBytes = ociProcText(path.join(moduleRoot, 'package.json'), 16384);
  const version = JSON.parse(packageBytes).version;
  const moduleFile = ociHashFile(modulePath, 8 * 1024 * 1024);
  const entryFile = ociHashFile(path.join(path.dirname(modulePath),
    'workers/shared/object-entry.worker.js'), 1024 * 1024);
  const bucketFile = ociHashFile(path.join(path.dirname(modulePath),
    'workers/r2/bucket.worker.js'), 1024 * 1024);
  if (version !== OCI_MINIFLARE_PIN.version || moduleFile.sha256 !== OCI_MINIFLARE_PIN.moduleSha256
      || entryFile.sha256 !== OCI_MINIFLARE_PIN.entryWorkerSha256
      || bucketFile.sha256 !== OCI_MINIFLARE_PIN.bucketWorkerSha256) {
    throw new Error('OCI Miniflare implementation differs from the reviewed API');
  }
  return { version, moduleFile, entryFile, bucketFile };
}

async function ociNamespaceObjectId(runtime, mapping) {
  await runtime.getR2Bucket(mapping.bindingName, mapping.workerName);
  const namespace = await runtime._getInternalDurableObjectNamespace(
    'r2', 'r2:bucket', 'R2BucketObject',
  );
  const namespaceObjectId = namespace.idFromName(mapping.namespaceId).toString();
  if (!/^[0-9a-f]{64}$/.test(namespaceObjectId)) {
    throw new Error('OCI namespace returned an invalid object identity');
  }
  return namespaceObjectId;
}

async function observeOciSdkNamespace(runtime, load, options, configurationBytes, selection, configurationPath) {
  if (!selection || Object.keys(selection).sort().join(',') !== 'sourceStorePath,wasmPath,workerdPath'
      || Object.values(selection).some(value => typeof value !== 'string'
        || !path.isAbsolute(value) || value.length > 4096)) {
    throw new Error('OCI namespace observation requires explicit installed inputs');
  }
  if (!/^\/nix\/store\/[0-9a-z]{32}-[^/]+$/.test(selection.sourceStorePath)
      || !lstatSync(selection.sourceStorePath).isDirectory()
      || realpathSync(selection.sourceStorePath) !== selection.sourceStorePath
      || selection.wasmPath !== path.join(path.dirname(options.scriptPath), 'index.wasm')) {
    throw new Error('OCI installed source or Wasm selection differs');
  }

  const { version, moduleFile, entryFile, bucketFile } = ociMiniflareImplementation(load);
  const api = load('miniflare');
  const mapping = ociLocalR2Selection(api, options);
  const runner = ociProcessIdentity(process.pid);
  const runtimePath = realpathSync(selection.workerdPath);
  const workerd = ociWorkerdIdentity(runtimePath);
  const runtimeFile = ociHashFile(runtimePath, 512 * 1024 * 1024, true);
  const observedExecutable = ociHashFile(`/proc/${workerd.pid}/exe`, 512 * 1024 * 1024, true);
  const shimFile = ociHashFile(options.scriptPath, 2 * 1024 * 1024);
  const wasmFile = ociHashFile(selection.wasmPath, 64 * 1024 * 1024);
  if (runtimeFile.sha256 !== observedExecutable.sha256
      || typeof runtime._getInternalDurableObjectNamespace !== 'function') {
    throw new Error('OCI runtime executable or namespace API differs');
  }

  // Selecting the installed proxy and deriving an ID dispatch no object SDK
  // operations. The independently retained anchor read is a separate gate.
  const namespaceObjectId = await ociNamespaceObjectId(runtime, mapping);
  if (!/^[0-9a-f]{64}$/.test(namespaceObjectId)
      || !ociSameProcess(runner, ociProcessIdentity(process.pid))
      || !ociSameProcess(workerd, ociWorkerdIdentity(runtimePath))) {
    throw new Error('OCI namespace or process changed during observation');
  }
  const retainedConfiguration = ociHashFile(configurationPath, 1024 * 1024);
  const configurationSha256 = createHash('sha256').update(configurationBytes).digest('hex');
  if (retainedConfiguration.sha256 !== configurationSha256) {
    throw new Error('OCI installed configuration changed');
  }
  const sourceDigest = createHash('sha256').update(selection.sourceStorePath).digest('hex');
  return {
    version: 1,
    observationScope: 'oci_sdk_emulator_namespace_readback',
    observedAt: new Date().toISOString(),
    runnerPid: runner.pid,
    runnerStartTicks: runner.startTicks,
    configurationSha256,
    runnerSha256: ociHashFile(__filename, 1024 * 1024).sha256,
    miniflareVersion: version,
    miniflareModuleSha256: moduleFile.sha256,
    miniflareEntryWorkerSha256: entryFile.sha256,
    miniflareBucketWorkerSha256: bucketFile.sha256,
    shimSha256: shimFile.sha256,
    wasmSha256: wasmFile.sha256,
    wasmByteSize: wasmFile.byteSize,
    sourceStorePath: selection.sourceStorePath,
    buildDerivedSourceDigest: sourceDigest,
    buildDerivedScriptVersion: `emulated-${sourceDigest}`,
    ...mapping,
    namespaceObjectId,
    workerdPid: workerd.pid,
    workerdStartTicks: workerd.startTicks,
    workerdExecutableSha256: observedExecutable.sha256,
  };
}

function ociDecodeBytes(encoded, digest, maximum) {
  if (typeof encoded !== 'string' || encoded.length > Math.ceil(maximum / 3) * 4
      || !/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error('OCI original encoding exceeds its bound');
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length > maximum || bytes.toString('base64') !== encoded
      || createHash('sha256').update(bytes).digest('hex') !== digest) {
    throw new Error('OCI original bytes differ');
  }
  return bytes;
}

function ociAnchorOriginal(originalBytes) {
  if (!Buffer.from(originalBytes.toString('utf8'), 'utf8').equals(originalBytes)) {
    throw new Error('OCI anchor original is not exact UTF-8');
  }
  const original = JSON.parse(originalBytes.toString('utf8'));
  const canonical = JSON.stringify(Object.fromEntries(Object.keys(original).sort()
    .map(field => [field, original[field]]))) + '\n';
  if (!Buffer.from(canonical).equals(originalBytes)) {
    throw new Error('OCI anchor original is not exact canonical JSON');
  }
  const fields = 'expiresAt,issuedAt,namespaceObservationBase64,namespaceObservationSha256,payloadBase64,payloadByteSize,payloadSha256,runId,version';
  if (Object.keys(original).sort().join(',') !== fields || original.version !== 1
      || typeof original.runId !== 'string' || !/^[0-9a-f]{32}$/.test(original.runId)
      || typeof original.issuedAt !== 'string' || typeof original.expiresAt !== 'string'
      || !/^[1-9][0-9]{0,11}$/.test(original.issuedAt)
      || !/^[1-9][0-9]{0,11}$/.test(original.expiresAt)
      || Number(original.expiresAt) <= Number(original.issuedAt)
      || Number(original.expiresAt) - Number(original.issuedAt) > 30) {
    throw new Error('OCI anchor original differs from its closed scope');
  }
  const payload = ociDecodeBytes(original.payloadBase64, original.payloadSha256, 1024);
  if (payload.length === 0 || original.payloadByteSize !== String(payload.length)) {
    throw new Error('OCI anchor payload length differs');
  }
  const namespaceBytes = ociDecodeBytes(original.namespaceObservationBase64,
    original.namespaceObservationSha256, 16384);
  return { original, payload, namespace: JSON.parse(namespaceBytes.toString('utf8')) };
}

function ociPersistBytes(filename, bytes) {
  const descriptor = openSync(filename, constants.O_WRONLY | constants.O_CREAT
    | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    let offset = 0;
    while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset, bytes.length - offset);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  const directory = openSync(path.dirname(filename), constants.O_RDONLY
    | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    fsyncSync(directory);
  } finally {
    closeSync(directory);
  }
}

function ociAnchorIdentity(object, key, expectedSize) {
  if (!object || object.key !== key || object.size !== expectedSize
      || typeof object.version !== 'string' || !/^[0-9a-f]{32}$/.test(object.version)
      || typeof object.httpEtag !== 'string' || !/^"[0-9a-f]{32}"$/.test(object.httpEtag)) {
    throw new Error('OCI anchor SDK returned a different positive incarnation');
  }
  return { key, provider_version: object.version, etag: object.httpEtag, size: object.size };
}

async function ociAnchorBody(object, maximum, current) {
  if (!object.body || typeof object.body.getReader !== 'function') {
    throw new Error('OCI conditional read returned no body');
  }
  const reader = object.body.getReader();
  const chunks = [];
  let byteSize = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      current();
      if (done) break;
      if (!(value instanceof Uint8Array) || value.byteLength === 0) {
        throw new Error('OCI anchor stream returned an invalid chunk');
      }
      byteSize += value.byteLength;
      if (byteSize > maximum) throw new Error('OCI anchor read exceeds its bound');
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, byteSize);
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
}

async function createOciSdkAnchor(runtime, options, request, namespaceObservation) {
  if (!options.ociAnchorEnabled || Object.keys(request).sort().join(',')
      !== 'kind,originalBase64,originalSha256,version'
      || request.version !== 1 || request.kind !== 'oci-sdk-anchor-create') {
    throw new Error('OCI anchor effect requires explicit isolated fixture selection');
  }
  const originalBytes = ociDecodeBytes(request.originalBase64, request.originalSha256, 32768);
  const { original, payload, namespace } = ociAnchorOriginal(originalBytes);
  let lastClock = Number(original.issuedAt);
  let diagnosticStage = 'pre_dispatch';
  let diagnosticCode = 'clock_invalid';
  const current = () => {
    const now = Math.floor(Date.now() / 1000);
    if (now < lastClock || now < Number(original.issuedAt) || now >= Number(original.expiresAt)) {
      diagnosticCode = 'clock_invalid';
      throw new Error('OCI anchor original clock expired or moved backward');
    }
    lastClock = now;
  };
  current();
  const observed = await namespaceObservation();
  current();
  const fields = Object.keys(observed).sort();
  if (Object.keys(namespace).sort().join(',') !== fields.join(',')
      || fields.some(field => field !== 'observedAt' && namespace[field] !== observed[field])
      || observed.observationScope !== 'oci_sdk_emulator_namespace_readback'
      || !/^oci-sdk-qualification-[0-9a-f]{32}$/.test(observed.namespaceId)) {
    throw new Error('OCI anchor namespace differs from the retained dedicated mapping');
  }
  const root = options.resourcePersistencePath;
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.uid !== process.getuid()
      || (rootMetadata.mode & 0o077) || realpathSync(root) !== root) {
    throw new Error('OCI anchor persistence custody differs');
  }
  const journalRoot = path.join(root, 'oci-sdk-anchor-journal');
  if (!existsSync(journalRoot)) {
    mkdirSync(journalRoot, { mode: 0o700 });
    const parent = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      fsyncSync(parent);
    } finally {
      closeSync(parent);
    }
  }
  const journalMetadata = lstatSync(journalRoot);
  if (!journalMetadata.isDirectory() || journalMetadata.uid !== process.getuid()
      || (journalMetadata.mode & 0o077) || realpathSync(journalRoot) !== journalRoot) {
    throw new Error('OCI anchor journal custody differs');
  }
  const journal = path.join(journalRoot, original.runId);
  // An existing run, including an unknown original, never dispatches again.
  mkdirSync(journal, { mode: 0o700 });
  ociPersistBytes(path.join(journal, 'original.json'), originalBytes);
  const parent = openSync(journalRoot, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    fsyncSync(parent);
  } finally {
    closeSync(parent);
  }

  const key = `.aos-oci-sdk-qualification/${original.runId}/anchor`;
  const invocations = { put: 0, get: 0 };
  let outcome;
  try {
    diagnosticStage = 'select_sdk_bucket';
    diagnosticCode = 'sdk_call_failed';
    current();
    const bucket = await runtime.getR2Bucket(observed.bindingName, observed.workerName);
    current();
    diagnosticStage = 'conditional_create';
    diagnosticCode = 'sdk_call_failed';
    invocations.put++;
    const written = await bucket.put(key, payload, {
      onlyIf: { etagDoesNotMatch: '*' }, sha256: original.payloadSha256,
    });
    current();
    if (written === null) {
      diagnosticCode = 'conditional_create_refused';
      outcome = { version: 1, status: 'refused', reason: 'conditional_create_refused' };
    } else {
      diagnosticStage = 'created_identity';
      diagnosticCode = 'identity_invalid';
      const positive = ociAnchorIdentity(written, key, payload.length);
      current();
      // R2Conditional uses the unquoted SDK ETag; the retained identity keeps
      // the canonical quoted HTTP ETag validated above.
      const conditionalEtag = positive.etag.slice(1, -1);
      diagnosticStage = 'conditional_read';
      diagnosticCode = 'sdk_call_failed';
      invocations.get++;
      const read = await bucket.get(key, { onlyIf: { etagMatches: conditionalEtag } });
      current();
      diagnosticStage = 'read_identity';
      diagnosticCode = 'identity_invalid';
      const retained = ociAnchorIdentity(read, key, payload.length);
      if (JSON.stringify(retained) !== JSON.stringify(positive)) {
        diagnosticCode = 'identity_changed';
        throw new Error('OCI anchor changed between conditional effects');
      }
      diagnosticStage = 'read_body';
      diagnosticCode = 'body_invalid';
      const bytes = await ociAnchorBody(read, payload.length, current);
      current();
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      if (bytes.length !== payload.length || sha256 !== original.payloadSha256) {
        diagnosticStage = 'full_body_check';
        diagnosticCode = 'body_mismatch';
        throw new Error('OCI anchor full read differs from its original');
      }
      outcome = { version: 1, status: 'observed', anchor: { object: positive, sha256 } };
    }
  } catch {
    // No error proves absence after a possible dispatch. Keep the original,
    // known objects and unknown effects; status never resumes or deletes them.
    outcome = { version: 1, status: 'unknown', reason: 'no_complete_positive_receipt' };
  }
  const completedAt = new Date().toISOString();
  if (outcome.status === 'observed'
      && Date.parse(completedAt) >= Number(original.expiresAt) * 1000) {
    diagnosticStage = 'completion';
    diagnosticCode = 'clock_invalid';
    outcome = { version: 1, status: 'unknown', reason: 'no_complete_positive_receipt' };
  }
  if (outcome.status !== 'observed') {
    // Fixed diagnostic labels stay in the private journal. They never turn an
    // unknown effect into absence or expose an SDK error, key, or payload.
    ociPersistBytes(path.join(journal, 'diagnostic.json'), Buffer.from(JSON.stringify({
      version: 1, stage: diagnosticStage, code: diagnosticCode,
    }) + '\n'));
  }
  const receipt = { ...outcome, runId: original.runId, originalSha256: request.originalSha256,
    namespaceObservationSha256: original.namespaceObservationSha256,
    completedAt, sdkInvocations: invocations };
  ociPersistBytes(path.join(journal, 'receipt.json'), Buffer.from(JSON.stringify(receipt) + '\n'));
  return receipt;
}

async function main() {
  const [toolingRoot, configurationPath] = process.argv.slice(2);
  if (!toolingRoot || !configurationPath) {
    throw new Error('Pass the Miniflare tooling root and Worker configuration');
  }

  // Resolve the pinned Miniflare distribution from the installed tool closure.
  const load = createRequire(path.join(
    toolingRoot, 'lib/node_modules/wrangler/node_modules/fleet-runner.cjs',
  ));
  const {
    Miniflare, QueuesOptionsSchema, QueueConsumerOptionsSchema,
    DurableObjectsOptionsSchema, getDurableObjectUniqueKey,
  } = load('miniflare');
  const configurationBytes = readFileSync(configurationPath);
  const {
    certificatePath, privateKeyPath, queueObservationPath, namespaceObservationPath,
    acceptanceSocketPath, ociSdkNamespaceObservation, ociSdkAnchorEnabled, ...options
  } = JSON.parse(configurationBytes);
  const queueOptions = QueuesOptionsSchema.parse(options);
  if (queueObservationPath && 'maxConcurrentInvocations' in QueueConsumerOptionsSchema.shape) {
    throw new Error('Reassess the actual emulator consumer invocation support');
  }
  const runtime = new Miniflare({
    ...options,
    modules: true,
    modulesRoot: path.dirname(options.scriptPath),
    modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
    cf: false,
    https: true,
    httpsCert: readFileSync(certificatePath, 'utf8'),
    httpsKey: readFileSync(privateKeyPath, 'utf8'),
  });
  const namespaceObservation = async () => {
    const parsed = DurableObjectsOptionsSchema.parse(options);
    const guard = parsed.durableObjects?.HYBRID_OBJECT_GUARD;
    if (!guard || typeof guard !== 'object' || guard.className !== 'HybridObjectGuard'
        || guard.useSQLite !== true || typeof options.name !== 'string'
        || typeof options.resourcePersistencePath !== 'string') {
      throw new Error('Namespace observation requires the configured SQLite guard');
    }
    const workerName = guard.scriptName ?? options.name;
    const namespaceKey = getDurableObjectUniqueKey(
      guard.className, workerName, guard.unsafeUniqueKey,
    );
    if (typeof namespaceKey !== 'string') {
      throw new Error('Namespace observation requires persistent identity');
    }
    const objectIds = await runtime.listDurableObjectIds('HYBRID_OBJECT_GUARD', options.name);
    if (!Array.isArray(objectIds) || objectIds.length > 1024
        || objectIds.some(value => typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))) {
      throw new Error('Namespace readback exceeds its observation contract');
    }
    return {
      version: 1,
      observationScope: 'selected_emulator_namespace_readback',
      observedAt: new Date().toISOString(),
      runnerPid: process.pid,
      runnerStartTicks: readFileSync(`/proc/${process.pid}/stat`, 'utf8')
        .split(') ').at(-1).trim().split(/\s+/)[19],
      configurationSha256: createHash('sha256').update(configurationBytes).digest('hex'),
      runnerSha256: createHash('sha256').update(readFileSync(__filename)).digest('hex'),
      miniflareModuleSha256: createHash('sha256').update(readFileSync(load.resolve('miniflare'))).digest('hex'),
      scriptSha256: createHash('sha256').update(readFileSync(options.scriptPath)).digest('hex'),
      bindingName: 'HYBRID_OBJECT_GUARD',
      className: guard.className,
      workerName,
      namespaceKey,
      persistenceRoot: options.resourcePersistencePath,
      objectIds,
    };
  };

  let acceptanceServer;
  let closing;
  const stop = () => {
    closing ??= (async () => {
      if (acceptanceServer) await acceptanceServer.close();
      await runtime.dispose();
    })();
    closing.catch(error => {
      console.error(error);
      process.exitCode = 1;
    });
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);

  try {
    console.info('Fleet Worker ready:', (await runtime.ready).href);
    if (namespaceObservationPath) {
      // This is actual local runtime namespace enumeration at a specific time.
      // Empty IDs confer no authority admission or provider qualification.
      writeFileSync(`${namespaceObservationPath}.${process.pid}.json`,
        JSON.stringify(await namespaceObservation()) + '\n', { flag: 'wx', mode: 0o600 });
    }
    if (acceptanceSocketPath) {
      acceptanceServer = acceptanceRegistryServer(
        runtime, acceptanceSocketPath, options.bindings, namespaceObservation,
        () => observeOciSdkNamespace(runtime, load, options, configurationBytes,
          ociSdkNamespaceObservation, configurationPath),
        request => createOciSdkAnchor(runtime, { ...options,
          ociAnchorEnabled: ociSdkAnchorEnabled === true }, request,
          () => observeOciSdkNamespace(runtime, load, options, configurationBytes,
            ociSdkNamespaceObservation, configurationPath)),
      );
      await acceptanceServer.ready;
    }
    if (queueObservationPath) {
      // Retain only supported options parsed by the installed runtime after it
      // becomes ready. The private full configuration is committed by hash.
      const startTicks = readFileSync(`/proc/${process.pid}/stat`, 'utf8')
        .split(') ').at(-1).trim().split(/\s+/)[19];
      writeFileSync(`${queueObservationPath}.${process.pid}.json`, JSON.stringify({
        version: 1,
        runnerPid: process.pid,
        runnerStartTicks: startTicks,
        configurationSha256: createHash('sha256').update(configurationBytes).digest('hex'),
        invocationBoundSupport: 'unsupported',
        queueOptions,
      }) + '\n', { flag: 'wx', mode: 0o600 });
    }
  } catch (error) {
    if (acceptanceServer) await acceptanceServer.close();
    await runtime.dispose();
    throw error;
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}

module.exports = { acceptanceRegistryServer, observeOciSdkNamespace, ociLocalR2Selection,
  ociHashFile, ociProcessIdentity, ociWorkerdIdentity, ociMiniflareImplementation,
  ociNamespaceObjectId, createOciSdkAnchor, ociAnchorOriginal, OCI_MINIFLARE_PIN };
