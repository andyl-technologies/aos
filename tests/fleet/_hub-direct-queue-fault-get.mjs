// A selected production GET is paused before opening an upstream connection.
// This owner is independent of the existing calibration/64KiB response holds.
import { createHash } from 'node:crypto';
import { createServer, request as requestUpstream } from 'node:http';
import { createServer as createControlServer } from 'node:net';
import { constants, promises as fs } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const HEX = /^[0-9a-f]{64}$/;
const MAX_CONTROL = 16384;
const fail = (condition, message) => { if (!condition) throw new Error(message); };
const closed = (value, fields) => value && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');

async function privateBytes(path) {
  const file = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat();
    fail(before.isFile() && before.uid === process.getuid() && before.nlink === 1
      && !(before.mode & 0o077) && before.size > 0 && before.size <= MAX_CONTROL,
    'GET owner input custody differs');
    const bytes = await file.readFile();
    const after = await file.stat();
    fail(bytes.length === before.size && after.ino === before.ino && after.size === before.size
      && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs,
    'GET owner input changed');
    return bytes;
  } finally { await file.close(); }
}

export function selectedGet(request, selection) {
  if (request.method !== 'GET') return null;
  const target = new URL(request.url, 'http://unused.test');
  if (target.pathname !== selection.path) return null;
  const values = name => {
    const found = [];
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      if (request.rawHeaders[index].toLowerCase() === name) found.push(request.rawHeaders[index + 1]);
    }
    fail(found.length <= 1, 'selected GET has duplicated conditional headers');
    return found[0] ?? null;
  };
  fail(values('host') === selection.host && values('range') === null
    && values('transfer-encoding') === null && [null, '0'].includes(values('content-length')),
  'selected GET authority or framing differs');
  const etag = values('if-match');
  fail(typeof etag === 'string' && /^"[!\x23-\x7e]{1,256}"$/.test(etag),
    'selected GET lacks a strong original condition');
  const authorization = values('authorization');
  // The actual stage executor uses a header signature. Presigned requests are
  // outside this selected hook; they are never stripped or rewritten.
  const signature = authorization?.match(/^AWS4-HMAC-SHA256 Credential=([^ ,]+), SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$/);
  fail(signature && signature[2].split(';').includes('host')
    && signature[2].split(';').includes('if-match') && values('x-amz-date') !== null
    && values('x-amz-content-sha256') !== null, 'selected GET condition is not signed');
  const query = [...target.searchParams];
  const providerVersion = target.searchParams.get('versionId');
  fail(query.length <= 1 && (query.length === 0 || query[0][0] === 'versionId')
    && (providerVersion === null || /^[A-Za-z0-9_-]{1,256}$/.test(providerVersion))
    && providerVersion !== 'null', 'selected GET version is not a bounded actual incarnation');
  // The original closed incarnation does not exist at pre-Complete arm time.
  // Observe it from this actual selected request; the controller independently
  // checks server intent and old full source bytes before any replacement.
  return { method: 'GET', pathSha256: sha(target.pathname), targetSha256: sha(request.url),
    hostSha256: sha(values('host')), ifMatch: etag, ifMatchSha256: sha(etag),
    providerVersion, signedHeaders: signature[2],
    authorizationSha256: sha(authorization), sourceSha256: selection.sourceSha256,
    fullObjectBytes: selection.fullObjectBytes, runDigest: selection.runDigest };
}

export async function createGetOwner(root, ports = { listen: 3904, upstream: 3903 }) {
  const metadata = await fs.lstat(root);
  fail(metadata.isDirectory() && metadata.uid === process.getuid() && !(metadata.mode & 0o077)
    && await fs.realpath(root) === resolve(root), 'GET owner root custody differs');
  let selected = null;
  let active = null;
  let closedOwner = false;
  let sequence = 0;
  const events = [];
  const stat = (await fs.readFile('/proc/self/stat', 'utf8')).split(') ').at(-1).trim().split(/\s+/);
  const owner = { pid: process.pid, ownerUid: process.getuid(), startTicks: stat[19] };

  async function event(kind, fields = {}) {
    const row = { version: 1, sequence: sequence++, kind, atUnixMs: Date.now(), owner, ...fields };
    const file = await fs.open(`${root}/event-${String(row.sequence).padStart(4, '0')}.json`, 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(row)); await file.sync(); }
    finally { await file.close(); }
    events.push(row);
    return row;
  }

  function release(reason) {
    if (!active || active.released) return false;
    active.released = true;
    active.reason = reason;
    clearTimeout(active.timer);
    active.resolve();
    return true;
  }

  function arm(value) {
    fail(!selected && !active && !closedOwner && closed(value,
      ['version', 'runDigest', 'host', 'path', 'sourceSha256', 'fullObjectBytes', 'cutoffUnixMs']),
    'GET selection cannot overlap or repeat');
    fail(value.version === 1 && HEX.test(value.runDigest) && HEX.test(value.sourceSha256)
      && value.host === 's3.fleet.test' && /^\/fleet-s3\/[A-Za-z0-9_./-]{1,1024}$/.test(value.path)
      && !value.path.split('/').some(part => part === '.' || part === '..')
      && value.fullObjectBytes === '8388608'
      && Number.isSafeInteger(value.cutoffUnixMs) && value.cutoffUnixMs > Date.now()
      && value.cutoffUnixMs <= Date.now() + 20000, 'GET selection bounds differ');
    selected = structuredClone(value);
    return { status: 'armed', runDigest: value.runDigest, owner };
  }

  async function handle(request, response) {
    let held = null;
    let upstream = null;
    // Subscribe before persistence or any other await. A closed downstream is
    // never treated as an owned live request, even if its event write is slow.
    response.once('close', () => {
      if (!response.writableFinished) {
        if (held) { held.disconnected = true; release('downstream_closed'); }
        upstream?.destroy();
      }
    });
    try {
      const identity = selected ? selectedGet(request, selected) : null;
      if (identity) {
        const original = selected;
        selected = null;
        let resolve_;
        held = { identity, released: false, disconnected: response.destroyed,
          resolve: () => resolve_(), reason: null, timer: null };
        active = held;
        const waiting = new Promise(resolve => { resolve_ = resolve; });
        held.timer = setTimeout(() => release('deadline'), Math.max(0, original.cutoffUnixMs - Date.now()));
        request.pause();
        await event('get_held_before_forward', { ...identity, cutoffUnixMs: original.cutoffUnixMs,
          upstreamOpened: false, disconnected: held.disconnected });
        if (held.disconnected || response.destroyed) release('downstream_closed');
        await waiting;
        await event('get_hold_released', { runDigest: identity.runDigest, reason: held.reason,
          disconnected: held.disconnected, upstreamOpened: false });
        if (held.reason !== 'explicit' || held.disconnected || response.destroyed) {
          response.destroy();
          return;
        }
      }
      // Forward the exact method, raw URI, Host and signed headers once. No
      // denial reply is synthesized and no failed provider request is replayed.
      upstream = requestUpstream({ hostname: '127.0.0.1', port: ports.upstream,
        method: request.method, path: request.url, headers: request.rawHeaders }, incoming => {
        response.writeHead(incoming.statusCode, incoming.rawHeaders);
        incoming.on('error', () => response.destroy());
        incoming.pipe(response);
      });
      upstream.on('error', () => response.destroy());
      request.on('error', () => upstream.destroy());
      request.pipe(upstream);
      request.resume();
    } catch {
      if (held) release('unknown');
      response.destroy();
    }
  }

  const server = createServer({ maxHeaderSize: MAX_CONTROL }, handle);
  const control = createControlServer({ allowHalfOpen: true }, socket => {
    socket.setTimeout(1000, () => socket.destroy());
    const pieces = [];
    let bytes = 0;
    socket.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > MAX_CONTROL) socket.destroy(); else pieces.push(chunk);
    });
    socket.on('end', () => {
      try {
        const request = JSON.parse(Buffer.concat(pieces));
        let result;
        if (closed(request, ['kind', 'selection']) && request.kind === 'arm') result = arm(request.selection);
        else if (closed(request, ['kind', 'runDigest']) && request.kind === 'release') {
          fail(active?.identity.runDigest === request.runDigest, 'release does not own this GET');
          result = { status: release('explicit') ? 'released' : 'already_released', owner };
        } else if (closed(request, ['kind']) && request.kind === 'observe') {
          result = { owner, selectedRun: selected?.runDigest ?? null,
            held: active ? { ...active.identity, released: active.released, reason: active.reason,
              disconnected: active.disconnected } : null, events };
        } else throw new Error('unsupported GET owner control');
        socket.end(JSON.stringify(result));
      } catch { socket.end(JSON.stringify({ status: 'refused_or_unknown' })); }
    });
  });
  const listen = (target, ...args) => new Promise((resolve_, reject) => {
    target.once('error', reject); target.listen(...args, resolve_);
  });
  await listen(server, ports.listen, '127.0.0.1');
  await listen(control, `${root}/control.sock`);
  await fs.chmod(`${root}/control.sock`, 0o600);
  const ready = { version: 1, ...owner, listenerSourceSha256: sha(await fs.readFile(fileURLToPath(import.meta.url))),
    listenAddress: `127.0.0.1:${server.address().port}`, upstreamAddress: `127.0.0.1:${ports.upstream}`,
    controlSocket: `${root}/control.sock` };
  const pendingReady = `${root}/ready.pending`;
  const readyFile = await fs.open(pendingReady, 'wx', 0o600);
  try { await readyFile.writeFile(JSON.stringify(ready)); await readyFile.sync(); }
  finally { await readyFile.close(); }
  await fs.link(pendingReady, `${root}/ready.json`);
  await fs.unlink(pendingReady);
  return { ready, arm, observe: () => ({ held: active, events }), release,
    close: async () => {
      closedOwner = true; release('owner_stopped');
      server.closeAllConnections();
      await Promise.all([new Promise(resolve_ => server.close(resolve_)),
        new Promise(resolve_ => control.close(resolve_))]);
    } };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  fail(process.argv.length === 4 && process.argv[2] === '--config', 'use --config privateConfigPath');
  const configuration = JSON.parse(await privateBytes(resolve(process.argv[3])));
  fail(closed(configuration, ['version', 'root']) && configuration.version === 1,
    'GET owner configuration differs');
  const listener = await createGetOwner(configuration.root);
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.once(signal, () => listener.close().then(() => process.exit(0)));
  }
}
