// A single-object fault adapter for a fresh controlled provider namespace.
// The owning TLS fixture must verify its real request signature before calling
// read(). This adapter supplies neither authentication nor a provider contract.
import { createHash } from 'node:crypto';

const digest = (body) => createHash('sha256').update(body).digest('hex');
const hexadecimal = /^[0-9a-f]{64}$/;
const maximumBytes = 32 * 1024 * 1024;

function closed(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== [...fields].sort().join(',')) {
    throw new Error('queue fault provider schema differs');
  }
}

function identity(object) {
  if (!object || !Buffer.isBuffer(object.bytes) || object.bytes.length === 0
      || object.bytes.length > maximumBytes || typeof object.version !== 'string'
      || !/^[A-Za-z0-9_-]{1,128}$/.test(object.version)
      || typeof object.etag !== 'string' || !/^"[A-Za-z0-9_-]{1,128}"$/.test(object.etag)) {
    throw new Error('queue fault provider object is not a bounded actual incarnation');
  }
  return {
    version: object.version,
    etag: object.etag,
    sha256: digest(object.bytes),
    byteSize: object.bytes.length,
  };
}

function identityDigest(value) {
  return digest(JSON.stringify([value.version, value.etag, value.sha256, value.byteSize]));
}

function publicIdentity(value) {
  return {
    identityDigest: identityDigest(value),
    versionDigest: digest(value.version),
    etagDigest: digest(value.etag),
    sha256: value.sha256,
    byteSize: value.byteSize,
  };
}

/** Confines an explicit replacement to one actually completed fixture object. */
export function queueFaultProvider(objects, selection) {
  closed(selection, ['version', 'runDigest', 'bucket', 'key', 'expected']);
  closed(selection.expected, ['version', 'etag', 'sha256', 'byteSize']);
  const prefix = `.aos-direct-qualification/${selection.runDigest}/queue-fault/`;
  if (!(objects instanceof Map) || selection.version !== 1
      || typeof selection.runDigest !== 'string' || !hexadecimal.test(selection.runDigest)
      || typeof selection.bucket !== 'string' || !/^[a-z0-9-]{3,63}$/.test(selection.bucket)
      || typeof selection.key !== 'string' || !selection.key.startsWith(prefix)
      || selection.key.length > 1024
      || selection.key.slice(prefix.length).split('/').some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) {
    throw new Error('queue fault provider selection is outside its fresh namespace');
  }
  const bucket = selection.bucket;
  const key = selection.key;
  const runDigest = selection.runDigest;
  const keyDigest = digest(key);
  const oldIdentity = identity(objects.get(key));
  if (identityDigest(oldIdentity) !== identityDigest(selection.expected)) {
    throw new Error('queue fault provider selection differs from the actual closed object');
  }
  let replaced = false;
  let armed = false;
  let sequence = 0;
  const observations = [];
  const counters = { replacements: 0, reads: 0, refusedReads: 0, responseOfferedBytes: 0 };

  function record(kind, facts) {
    if (observations.length >= 4096) throw new Error('queue fault provider observation bound reached');
    observations.push({ version: 1, runDigest, keyDigest, sequence: sequence++,
      atMillis: Date.now(), kind, ...facts });
  }

  function validateTrigger(trigger) {
    closed(trigger, ['version', 'runDigest', 'keyDigest', 'expectedIdentityDigest']);
    if (replaced || observations.length >= 4096
        || trigger.version !== 1 || trigger.runDigest !== runDigest
        || trigger.keyDigest !== keyDigest
        || trigger.expectedIdentityDigest !== identityDigest(oldIdentity)
        || identityDigest(identity(objects.get(key))) !== identityDigest(oldIdentity)) {
      throw new Error('queue fault provider replacement refused before mutation');
    }
  }

  function replace(trigger) {
    validateTrigger(trigger);

    // Retiring an old serving incarnation is an explicit adversarial fixture
    // action. The original identity remains in the audit; no accepted provider
    // immutability property is inferred from this deliberately injected fault.
    const bytes = Buffer.from(objects.get(key).bytes);
    bytes[0] ^= 0xff;
    const actualSha = digest(bytes);
    const replacement = { bytes, version: `queue-fault-${actualSha.slice(0, 32)}`,
      etag: `"queue-fault-${actualSha.slice(0, 32)}"` };
    objects.set(key, replacement);
    replaced = true;
    armed = false;
    counters.replacements++;
    const newIdentity = identity(replacement);
    record('source_replaced', { old: publicIdentity(oldIdentity), current: publicIdentity(newIdentity) });
    return { version: 1, runDigest, keyDigest, old: publicIdentity(oldIdentity),
      current: publicIdentity(newIdentity), replacements: counters.replacements };
  }

  function arm(trigger) {
    validateTrigger(trigger);
    if (armed) throw new Error('queue fault provider replacement already armed');
    armed = true;
    record('replacement_armed', { old: publicIdentity(oldIdentity) });
    return { version: 1, runDigest, keyDigest, armed: true, replacements: 0 };
  }

  function read(request, response) {
    const url = new URL(request.url, 'https://controlled-provider.invalid');
    let requestKey;
    try {
      requestKey = decodeURIComponent(url.pathname.slice(bucket.length + 2));
    } catch {
      return false;
    }
    if (!url.pathname.startsWith(`/${bucket}/`) || requestKey !== key) return false;
    if (!['GET', 'HEAD'].includes(request.method)) return false;
    const versions = url.searchParams.getAll('versionId');
    const requestedVersion = versions.length === 1 ? versions[0] : null;
    const ifMatch = request.headers['if-match'];
    if (armed && request.method === 'GET' && versions.length <= 1 && !request.headers.range
        && (requestedVersion === null || requestedVersion === oldIdentity.version)
        && (typeof ifMatch !== 'string' || ifMatch === oldIdentity.etag)) {
      // The explicit admin arm precedes delivery. Applying it inside the first
      // selected actual read avoids guessing queue scheduling or delaying work.
      replace({ version: 1, runDigest, keyDigest, expectedIdentityDigest: identityDigest(oldIdentity) });
    }
    const object = objects.get(key);
    const actual = identity(object);
    // Other SigV4 query fields remain the owning fixture's responsibility.
    // Do not invent a conditional failure for an unconditional production GET.
    // Such a read receives the actual current bytes; its source hash verifier
    // must refuse them independently, and conditional admission stays unknown.
    const status = versions.length > 1 || request.headers.range ? 400
      : requestedVersion !== null && requestedVersion !== actual.version ? 404
        : typeof ifMatch === 'string' && ifMatch !== actual.etag ? 412 : 200;
    const offered = status === 200 && request.method === 'GET' ? object.bytes.length : 0;
    counters.reads++;
    if (status !== 200) counters.refusedReads++;
    counters.responseOfferedBytes += offered;
    record(typeof ifMatch === 'string' || requestedVersion !== null ? 'conditional_read' : 'unconditional_read',
      { method: request.method, status,
      requestedVersionDigest: requestedVersion === null ? null : digest(requestedVersion),
      ifMatchDigest: typeof ifMatch === 'string' ? digest(ifMatch) : null,
      current: publicIdentity(actual), responseOfferedBytes: offered });
    response.writeHead(status, { ETag: actual.etag, 'x-amz-version-id': actual.version,
      'Content-Length': status === 200 ? object.bytes.length : 0 });
    response.end(offered ? object.bytes : undefined);
    return true;
  }

  async function administer(request, response) {
    if (!['/fixture/queue-fault/replace-source', '/fixture/queue-fault/arm-source-replacement']
      .includes(request.url)) return false;
    // This handler belongs to a separate owner-only loopback listener. Never
    // route it through a provider socket or a Worker service binding.
    if (request.method !== 'POST' || !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(request.socket.remoteAddress)) {
      response.writeHead(403).end();
      return true;
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > 2048) {
        response.writeHead(413).end();
        return true;
      }
      chunks.push(chunk);
    }
    try {
      const trigger = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const reply = request.url.endsWith('/arm-source-replacement') ? arm(trigger) : replace(trigger);
      response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(reply));
    } catch {
      response.writeHead(409).end();
    }
    return true;
  }

  return Object.freeze({ read, administer, replace, arm,
    trigger: Object.freeze({ version: 1, runDigest, keyDigest,
      expectedIdentityDigest: identityDigest(oldIdentity) }),
    snapshot: () => ({ version: 1, runDigest, keyDigest, counters: { ...counters },
      observations: structuredClone(observations),
      scope: 'controlled provider store and offered response bytes; no client consumption or SDK acceptance' }),
    privateIdentities: () => ({ old: { ...oldIdentity }, current: identity(objects.get(key)) }),
  });
}
