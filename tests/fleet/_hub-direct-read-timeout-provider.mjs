// One deliberately unresponsive conditional GET in a fresh local fixture.
// The owning TLS provider verifies the real request signature before read().
// This adapter never writes, replaces or deletes an object or supplies auth.
import { createHash } from 'node:crypto';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hexadecimal = /^[0-9a-f]{64}$/;

/** Selects an already completed bounded object for one actual read timeout. */
export function readTimeoutProvider(objects, selection, observe) {
  if (!(objects instanceof Map) || !selection
      || Object.keys(selection).sort().join(',') !== 'bucket,expected,key,runDigest,version'
      || selection.version !== 1 || !hexadecimal.test(selection.runDigest)
      || !/^[a-z0-9-]{3,63}$/.test(selection.bucket)
      || selection.key !== `.aos-direct-read-qualification/${selection.runDigest}/timeout/object`
      || !selection.expected || Object.keys(selection.expected).sort().join(',') !== 'byteSize,etag,sha256,version'
      || typeof observe !== 'function') {
    throw new Error('Read timeout selection differs from its fresh fixture namespace');
  }
  const object = objects.get(selection.key);
  if (!object || !Buffer.isBuffer(object.bytes) || object.bytes.length < 16
      || object.bytes.length > 32 * 1024 * 1024
      || !/^[A-Za-z0-9_-]{1,128}$/.test(object.version)
      || !/^"[A-Za-z0-9_-]{1,128}"$/.test(object.etag)
      || object.version !== selection.expected.version || object.etag !== selection.expected.etag
      || object.bytes.length !== selection.expected.byteSize || digest(object.bytes) !== selection.expected.sha256) {
    throw new Error('Read timeout selection differs from the actual completed object');
  }
  const retained = { version: object.version, etag: object.etag, byteSize: object.bytes.length,
    sha256: digest(object.bytes) };
  let dispatched = false;
  let sequence = 0;
  const events = [];

  function read(request, response) {
    const url = new URL(request.url, 'https://controlled-read-provider.invalid');
    let key;
    try { key = decodeURIComponent(url.pathname.slice(selection.bucket.length + 2)); }
    catch { return false; }
    if (request.method !== 'GET' || !url.pathname.startsWith(`/${selection.bucket}/`) || key !== selection.key) {
      return false;
    }
    const versions = url.searchParams.getAll('versionId');
    if (dispatched || versions.length !== 1 || versions[0] !== retained.version
        || request.headers['if-match'] !== retained.etag || request.headers.range
        || objects.get(selection.key) !== object || digest(object.bytes) !== retained.sha256) {
      throw new Error('Read timeout original changed or was replayed');
    }
    dispatched = true;
    const started = process.hrtime.bigint();
    const record = kind => {
      const event = { version: 1, kind, sequence: sequence++, runDigest: selection.runDigest,
        keyDigest: digest(key), versionDigest: digest(retained.version), etagDigest: digest(retained.etag),
        atUnixMillis: String(Date.now()), elapsedNanoseconds: String(process.hrtime.bigint() - started),
        method: 'GET', status: null, responseOfferedBytes: '0' };
      events.push(event);
      observe(event);
    };
    record('read_started');
    let forced = false;
    // No HTTP error replaces the timeout. A peer cancellation is observed
    // separately; the fixture bounds its own open socket at 35 real seconds.
    const timer = setTimeout(() => {
      forced = true;
      record('fixture_timeout');
      response.destroy();
    }, 35_000);
    response.once('close', () => {
      clearTimeout(timer);
      if (!forced) record('peer_closed');
    });
    return true;
  }

  return Object.freeze({ read, snapshot: () => ({ version: 1, runDigest: selection.runDigest,
    keyDigest: digest(selection.key), reads: dispatched ? 1 : 0, events: structuredClone(events),
    scope: 'actual confined fixture GET and offered bytes; peer closure is not Worker/SDK success or physical settlement' }) });
}
