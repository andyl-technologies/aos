// Observe or evict one configured immutable documentation Cache API entry.
// This local fixture never admits content or changes a provider object.
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');

const CACHE_API_PIN = Object.freeze({
  version: '5.20260801.0-alpha',
  moduleSha256: '973b3563e0e4ac82531642131ebff32b77edfced4ba7f56123a2b09d37c15d01',
  cacheWorkerSha256: '5288ba51fd6fbc75dd393e00fb6c1dfa49770af2a702d7e9171a88cf23709c99',
  cacheEntrySha256: '718045b6a0ce1059e1fae7587ce3e8a4a151c65f176a3897f66df1f669e49f27',
});

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function publicDocumentCacheKey(bindings, selection) {
  if (!selection || Object.keys(selection).sort().join(',')
      !== 'assetVersion,bodyBytes,documentSha256,registrySlug'
      || !/^[a-z][a-z0-9-]{0,63}\/[a-z][a-z0-9-]{0,63}$/.test(selection.registrySlug)
      || !/^[0-9a-f]{64}$/.test(selection.documentSha256)
      || !/^[0-9a-f]{8}$/.test(selection.assetVersion)
      || !Number.isSafeInteger(selection.bodyBytes)
      || selection.bodyBytes < 1 || selection.bodyBytes > 256 * 1024
      || typeof bindings?.HUB_DEPLOYMENT_ID !== 'string'
      || !/^[A-Za-z0-9_.-]{1,128}$/.test(bindings.HUB_DEPLOYMENT_ID)) {
    throw new Error('Public document cache selection differs');
  }
  const origin = new URL(bindings.HUB_EXTERNAL_URL);
  if (origin.protocol !== 'https:' || origin.href !== `${origin.origin}/`
      || origin.username || origin.password) {
    throw new Error('Public document cache origin differs');
  }
  const url = `${origin.origin}/${selection.registrySlug}/-/api/v1/documentation/sha256:${selection.documentSha256}`;
  const digest = createHash('sha256');
  const commit = value => {
    const bytes = Buffer.from(value);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    digest.update(length).update(bytes);
  };
  for (const value of ['aos-hybrid-public-cache-v1', bindings.HUB_DEPLOYMENT_ID,
    selection.assetVersion, url]) commit(value);
  // Match the fixed real requests: Accept */*, Accept-Encoding identity, and
  // no Accept-Language. Do not accept a caller-supplied cache URL or variant.
  for (const value of ['*/*', 'identity', null]) {
    if (value !== null) commit(value);
    digest.update(Buffer.alloc(8));
  }
  return { key: `${origin.origin}/_internal/hybrid-public-cache/${digest.digest('hex')}`, url };
}

function installedCacheApi(load) {
  const modulePath = load.resolve('miniflare');
  const version = JSON.parse(readFileSync(path.resolve(path.dirname(modulePath),
    '../../package.json'))).version;
  const moduleSha256 = sha256(readFileSync(modulePath));
  const cacheWorkerSha256 = sha256(readFileSync(path.join(path.dirname(modulePath), 'workers/cache/cache.worker.js')));
  const cacheEntrySha256 = sha256(readFileSync(path.join(path.dirname(modulePath), 'workers/cache/cache-entry.worker.js')));
  if (version !== CACHE_API_PIN.version || moduleSha256 !== CACHE_API_PIN.moduleSha256
      || cacheWorkerSha256 !== CACHE_API_PIN.cacheWorkerSha256 || cacheEntrySha256 !== CACHE_API_PIN.cacheEntrySha256) {
    throw new Error('Cache observation API changed');
  }
  return { version, moduleSha256, cacheWorkerSha256, cacheEntrySha256 };
}

async function cachedDocument(cache, key, selection) {
  const response = await cache.match(key);
  if (response === undefined) return null;
  if (response.status !== 200 || !response.body) {
    throw new Error('Cached documentation response differs');
  }
  const reader = response.body.getReader();
  const digest = createHash('sha256');
  let byteSize = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      byteSize += value.byteLength;
      if (byteSize > selection.bodyBytes) throw new Error('Cached documentation exceeded its selected size');
      digest.update(value);
    }
  } finally {
    // A response may be backed by a tee or remote proxy whose cancellation
    // promise waits on another reader. Cancellation never proves drainage.
    void reader.cancel().catch(() => {});
  }
  const bodySha256 = digest.digest('hex');
  const expiry = response.headers.get('x-aos-front-cache-expires');
  if (byteSize !== selection.bodyBytes || bodySha256 !== selection.documentSha256
      || !/^[1-9][0-9]{0,18}$/.test(expiry ?? '')) {
    throw new Error('Cached documentation identity differs');
  }
  return { bodySha256, byteSize: String(byteSize), expiresAtUnixSeconds: expiry };
}

async function observePublicDocumentCache(runtime, load, options, configurationBytes, selection, request, observerSha256) {
  if (!request || Object.keys(request).sort().join(',') !== 'kind,version'
      || request.version !== 1 || !['public-document-cache-readback',
        'public-document-cache-evict'].includes(request.kind)
      || typeof options.name !== 'string' || options.workers !== undefined
      || typeof runtime.getCaches !== 'function' || !/^[0-9a-f]{64}$/.test(observerSha256)) {
    throw new Error('Cache observation request or selected worker differs');
  }
  const implementation = installedCacheApi(load);
  const { key, url } = publicDocumentCacheKey(options.bindings, selection);
  const caches = await runtime.getCaches();
  const cache = caches.default;
  const before = await cachedDocument(cache, key, selection);
  let deleted = null;
  let after = before;
  if (request.kind === 'public-document-cache-evict') {
    if (before === null) throw new Error('Selected document cache entry is absent');
    deleted = await cache.delete(key);
    after = await cachedDocument(cache, key, selection);
    if (deleted !== true || after !== null) throw new Error('Exact document cache eviction is unknown');
  }
  return {
    version: 1, observationScope: 'selected_public_document_cache_api', kind: request.kind,
    runnerPid: process.pid,
    runnerStartTicks: readFileSync(`/proc/${process.pid}/stat`, 'utf8')
      .split(') ').at(-1).trim().split(/\s+/)[19],
    configurationSha256: sha256(configurationBytes), cacheObserverSha256: observerSha256,
    miniflareVersion: implementation.version,
    miniflareModuleSha256: implementation.moduleSha256,
    cacheWorkerSha256: implementation.cacheWorkerSha256,
    cacheEntrySha256: implementation.cacheEntrySha256,
    shimSha256: sha256(readFileSync(options.scriptPath)),
    workerName: options.name, documentUrlSha256: sha256(url), cacheKeySha256: sha256(key),
    observedAtUnixMillis: String(Date.now()), before, deleted, after,
  };
}

module.exports = { CACHE_API_PIN, publicDocumentCacheKey, installedCacheApi, observePublicDocumentCache };
