// Controlled mapping tests inspect actual pinned schemas, not live namespaces.
const assert = require('node:assert/strict');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { createCopyIsolation } = require('./_hub-external-copy-isolation.cjs');

const api = require(process.argv[2]);
const root = mkdtempSync(path.join(tmpdir(), 'aos-copy-mapping-'));
const scriptPath = path.join(root, 'worker.js');
writeFileSync(scriptPath, 'export default {};\n');
const options = {
  name: 'copy-app', scriptPath, modules: true,
  resourcePersistencePath: root, host: '127.0.0.1', port: 4675,
  durableObjects: {
    EXTERNAL_OBJECT_GUARD: { className: 'ExternalObjectGuard', useSQLite: true },
    HYBRID_BINDING_STATE: { className: 'HybridBindingState', useSQLite: true },
    HYBRID_OBJECT_GUARD: { className: 'HybridObjectGuard', useSQLite: true },
  },
  bindings: { HUB_TOPOLOGY: 'hybrid' },
  kvNamespaces: { ACCEPTANCE: 'actual-configured-name' },
  queueProducers: { QUEUE: 'configured-queue' },
  queueConsumers: { 'configured-queue': {} }, routes: ['test.invalid/*'],
};

(async () => {
  try {
    const original = structuredClone(options);
    const local = createCopyIsolation(api, options, { version: 1, sourceWorkerName: options.name });
    assert.equal(local.options.durableObjects.EXTERNAL_OBJECT_GUARD.scriptName, options.name);
    assert.equal(local.options.workers, undefined);
    assert.deepEqual(options, original);

    const remote = createCopyIsolation(api, options, { version: 1, sourceWorkerName: 'copy-source' });
    const [app, source] = remote.options.workers;
    assert.equal(remote.options.port, options.port);
    assert.equal(remote.options.resourcePersistencePath, root);
    assert.equal(app.scriptPath, source.scriptPath);
    assert.equal(app.durableObjects.EXTERNAL_OBJECT_GUARD.scriptName, 'copy-source');
    assert.equal(source.durableObjects.HYBRID_BINDING_STATE.scriptName, 'copy-source');
    assert.deepEqual(app.durableObjects.HYBRID_OBJECT_GUARD, options.durableObjects.HYBRID_OBJECT_GUARD);
    assert.deepEqual(app.bindings, source.bindings);
    assert.deepEqual(app.kvNamespaces, source.kvNamespaces);
    assert.ok(app.queueConsumers);
    for (const field of ['queueConsumers', 'queueProducers', 'routes', 'crons']) {
      assert.equal(source[field], undefined);
    }

    assert.throws(() => createCopyIsolation(api, options, { version: 1, sourceWorkerName: 'copy-source', pass: true }));
    const wrong = structuredClone(options);
    wrong.durableObjects.EXTERNAL_OBJECT_GUARD.className = 'HybridObjectGuard';
    assert.throws(() => createCopyIsolation(api, wrong, { version: 1, sourceWorkerName: 'copy-source' }));
    wrong.durableObjects.EXTERNAL_OBJECT_GUARD = {
      ...options.durableObjects.EXTERNAL_OBJECT_GUARD, scriptName: 'older-source',
    };
    assert.throws(() => createCopyIsolation(api, wrong, { version: 1, sourceWorkerName: 'copy-source' }));

    const calls = [];
    const runtime = { listDurableObjectIds: async (binding, worker) => {
      calls.push([binding, worker]);
      return ['a'.repeat(64)];
    } };
    const observed = await remote.namespaceReadback(runtime, {
      configurationBytes: Buffer.from(JSON.stringify(options)),
      miniflareModulePath: require.resolve(process.argv[2]), runnerPath: __filename,
    });
    assert.deepEqual(calls, [['EXTERNAL_OBJECT_GUARD', 'copy-app'], ['HYBRID_BINDING_STATE', 'copy-app']]);
    assert.equal(observed.namespaces[0].namespaceKey,
      api.getDurableObjectUniqueKey('ExternalObjectGuard', 'copy-source'));
    assert.equal(observed.participatingIsolateIdentity, null);
    assert.equal(observed.sourceWorkerName, 'copy-source');
    assert.match(observed.isolationModuleSha256, /^[a-f0-9]{64}$/);
    assert.ok(Number(observed.runnerStartTicks) > 0);
    console.log('PASS 4 controlled Copy mapping/schema/namespace tests; no live runtime proof');
  } finally {
    rmSync(root, { recursive: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
