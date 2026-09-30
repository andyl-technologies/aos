// Serve the built Worker with real workerd and persistent Miniflare bindings.
// Persistent bindings and direct workerd dispatch keep the fleet independent
// of Wrangler's live development proxy and external Request.cf discovery.
const { createHash } = require('node:crypto');
const { chmodSync, lstatSync, readFileSync, writeFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const { createServer } = require('node:net');
const path = require('node:path');

function acceptanceRegistryServer(runtime, socketPath, bindings, namespaceObservation) {
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
    acceptanceSocketPath, ...options
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

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
