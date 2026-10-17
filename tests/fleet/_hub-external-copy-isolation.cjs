// Initial, confined Copy worker mapping and actual namespace observations.
// Worker names are configuration facts; participating isolate identities come
// only from the authenticated Copy invocation's actual pool observations.
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function workerName(value) {
  return typeof value === 'string' && /^[a-z][a-z0-9-]{0,95}$/.test(value);
}

function sharedKeys(api) {
  if (!api.PLUGINS || typeof api.PLUGINS !== 'object') {
    throw new Error('Pinned Miniflare lacks its declared shared option schemas');
  }
  const keys = new Set();
  for (const plugin of Object.values(api.PLUGINS)) {
    let schema = plugin.sharedOptions;
    if (!schema) continue;
    for (let depth = 0; !schema.shape && depth < 4; depth += 1) {
      if (typeof schema.innerType !== 'function') break;
      schema = schema.innerType();
    }
    if (!schema.shape || typeof schema.shape !== 'object') {
      throw new Error('Pinned shared option schema is not inspectable');
    }
    for (const key of Object.keys(schema.shape)) keys.add(key);
  }
  if (!keys.has('resourcePersistencePath') || !keys.has('port')) {
    throw new Error('Pinned shared option contract is incomplete');
  }
  return keys;
}

function createCopyIsolation(api, options, selection) {
  if (!selection || Object.keys(selection).sort().join(',') !== 'sourceWorkerName,version'
      || selection.version !== 1 || !workerName(selection.sourceWorkerName)
      || !workerName(options.name) || options.workers !== undefined
      || typeof options.scriptPath !== 'string'
      || typeof options.resourcePersistencePath !== 'string') {
    throw new Error('Copy mapping requires one exact fresh initial worker selection');
  }
  if (typeof api.getDurableObjectUniqueKey !== 'function'
      || !api.DurableObjectsOptionsSchema) {
    throw new Error('Pinned Miniflare namespace APIs are unavailable');
  }
  const initialScriptSha256 = digest(readFileSync(options.scriptPath));
  const initialModuleSha256 = digest(readFileSync(__filename));

  const classes = {
    EXTERNAL_OBJECT_GUARD: 'ExternalObjectGuard',
    HYBRID_BINDING_STATE: 'HybridBindingState',
  };
  const parsed = api.DurableObjectsOptionsSchema.parse(options);
  const mapped = { ...options, durableObjects: { ...options.durableObjects } };
  for (const [binding, className] of Object.entries(classes)) {
    const value = parsed.durableObjects?.[binding];
    if (!value || typeof value !== 'object' || value.className !== className
        || value.useSQLite !== true
        || (value.scriptName !== undefined && value.scriptName !== options.name)) {
      throw new Error('Copy mapping lacks the exact initial SQLite namespace');
    }
    mapped.durableObjects[binding] = {
      ...options.durableObjects[binding], scriptName: selection.sourceWorkerName,
    };
  }

  let executionOptions = mapped;
  if (selection.sourceWorkerName !== options.name) {
    const shared = {}, application = {};
    const keys = sharedKeys(api);
    for (const [key, value] of Object.entries(mapped)) {
      (keys.has(key) ? shared : application)[key] = value;
    }
    const source = { ...application, name: selection.sourceWorkerName };
    // This role receives protected DO calls, rather than another public or
    // scheduled application. The actual module and all authority bindings stay
    // identical; these deliberate trigger exclusions are retained below.
    for (const key of ['queueProducers', 'queueConsumers', 'routes', 'crons']) delete source[key];
    executionOptions = { ...shared, workers: [application, source] };
  }

  async function namespaceReadback(runtime, provenance) {
    if (!provenance || !Buffer.isBuffer(provenance.configurationBytes)
        || typeof provenance.miniflareModulePath !== 'string'
        || typeof provenance.runnerPath !== 'string') {
      throw new Error('Copy namespace observation lacks actual source originals');
    }
    const measure = () => ({
      runnerSha256: digest(readFileSync(provenance.runnerPath)),
      isolationModuleSha256: digest(readFileSync(__filename)),
      miniflareModuleSha256: digest(readFileSync(provenance.miniflareModulePath)),
      scriptSha256: digest(readFileSync(options.scriptPath)),
    });
    const before = measure();
    if (before.scriptSha256 !== initialScriptSha256
        || before.isolationModuleSha256 !== initialModuleSha256) {
      throw new Error('Copy namespace source changed after initial mapping');
    }
    const observations = [];
    for (const [bindingName, className] of Object.entries(classes)) {
      const actual = mapped.durableObjects[bindingName];
      const namespaceKey = api.getDurableObjectUniqueKey(
        className, actual.scriptName, actual.unsafeUniqueKey,
      );
      const objectIds = await runtime.listDurableObjectIds(bindingName, options.name);
      if (typeof namespaceKey !== 'string' || namespaceKey.length > 512
          || !Array.isArray(objectIds) || objectIds.length > 1024
          || objectIds.some(id => typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id))) {
        throw new Error('Copy namespace readback exceeds its exact observation bound');
      }
      observations.push({ bindingName, className, workerName: actual.scriptName,
        namespaceKey, objectIds });
    }
    if (JSON.stringify(measure()) !== JSON.stringify(before)) {
      throw new Error('Copy namespace source changed during actual readback');
    }
    return {
      version: 1, observationScope: 'selected_external_copy_namespace_readback',
      observedAt: new Date().toISOString(), runnerPid: process.pid,
      runnerStartTicks: readFileSync(`/proc/${process.pid}/stat`, 'utf8')
        .split(') ').at(-1).trim().split(/\s+/)[19],
      configurationSha256: digest(provenance.configurationBytes),
      ...before,
      applicationWorkerName: options.name, sourceWorkerName: selection.sourceWorkerName,
      sourceTriggerExclusions: selection.sourceWorkerName === options.name ? []
        : ['queueProducers', 'queueConsumers', 'routes', 'crons'],
      persistenceRoot: options.resourcePersistencePath, namespaces: observations,
      participatingIsolateIdentity: null,
    };
  }

  return { options: executionOptions, namespaceReadback };
}

module.exports = { createCopyIsolation };
