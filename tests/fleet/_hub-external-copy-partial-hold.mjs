// Confined partial-body observation for a real conditional Copy source read.
// This listener never creates authority or objects. The untouched provider
// response and actual Worker observations must be joined independently.
import { createHash } from 'node:crypto';
import { constants, promises as fs } from 'node:fs';
import { createServer, request as upstreamRequest } from 'node:http';
import { createServer as controlServer } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PREFIX_BYTES = 65536;
const HEADER_BOUND = 16384;
const CONTROL_BOUND = 4096;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value));
const requireFact = (condition, message) => { if (!condition) throw new Error(message); };
const closed = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');

function header(headers, name) {
  const values = [];
  for (let index = 0; index < headers.length; index += 2) {
    if (headers[index].toLowerCase() === name) values.push(headers[index + 1]);
  }
  requireFact(values.length <= 1, 'Duplicate selected header');
  return values[0] ?? null;
}

function selectedIdentity(request, configuration) {
  if (request.method !== 'GET' || header(request.rawHeaders, 'host') !== configuration.host) return null;
  const rawTarget = request.url;
  if (typeof rawTarget !== 'string' || rawTarget.length > 8192
      || !rawTarget.split('?')[0].startsWith(configuration.targetPrefix)) return null;
  const etag = header(request.rawHeaders, 'if-match');
  const range = header(request.rawHeaders, 'range');
  if (!/^"[!\x23-\x7e]{1,256}"$/.test(etag ?? '')
      || !/^bytes=0-[1-9][0-9]*$/.test(range ?? '')
      || BigInt(range.slice(8)) < BigInt(PREFIX_BYTES)
      || header(request.rawHeaders, 'transfer-encoding') !== null
      || ![null, '0'].includes(header(request.rawHeaders, 'content-length'))) return null;
  const url = new URL(rawTarget, 'http://selected.invalid');
  const authorization = header(request.rawHeaders, 'authorization');
  let signedHeaders;
  if (authorization !== null) {
    const signed = authorization.match(/^AWS4-HMAC-SHA256 Credential=[^ ,]+, SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$/);
    if (!signed || url.searchParams.has('X-Amz-Signature')) return null;
    signedHeaders = signed[1].split(';');
  } else {
    if (url.searchParams.getAll('X-Amz-SignedHeaders').length !== 1
        || url.searchParams.getAll('X-Amz-Signature').length !== 1
        || !/^[0-9a-f]{64}$/.test(url.searchParams.get('X-Amz-Signature') ?? '')) return null;
    signedHeaders = (url.searchParams.get('X-Amz-SignedHeaders') ?? '').split(';');
  }
  if (!['host', 'if-match', 'range'].every(name => signedHeaders.includes(name))) return null;
  // The signer shape is an observation selector, never verification. The real
  // unchanged request still goes to Garage, which accepts or refuses it.
  return { method: request.method, targetSha256: sha(rawTarget), host: configuration.host,
    ifMatch: etag, range, signatureVerification: null };
}

async function retain(root, name, bytes) {
  const file = await fs.open(`${root}/${name}`, constants.O_WRONLY | constants.O_CREAT
    | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  return { path: `${root}/${name}`, sha256: sha(bytes), byteSize: String(bytes.length) };
}

async function hashExecutable() {
  const file = await fs.open('/proc/self/exe', constants.O_RDONLY);
  const digest = createHash('sha256');
  const block = Buffer.alloc(PREFIX_BYTES);
  let size = 0;
  try {
    while (true) {
      const { bytesRead } = await file.read(block, 0, block.length, null);
      if (bytesRead === 0) return digest.digest('hex');
      size += bytesRead;
      requireFact(size <= 512 * 1024 * 1024, 'Executable observation exceeds bound');
      digest.update(block.subarray(0, bytesRead));
    }
  } finally { await file.close(); }
}

function listen(server, ...args) {
  return new Promise((resolve_, reject) => {
    server.once('error', reject);
    server.listen(...args, () => { server.off('error', reject); resolve_(); });
  });
}

function nextBounded(reply) {
  return new Promise((resolve_, reject) => {
    const cleanup = () => {
      reply.off('readable', take); reply.off('end', take);
      reply.off('error', failed); reply.off('aborted', aborted);
    };
    const failed = error => { cleanup(); reject(error); };
    const aborted = () => failed(new Error('Actual provider response aborted'));
    const take = () => {
      const value = reply.read(PREFIX_BYTES);
      if (value !== null) { cleanup(); resolve_({ done: false, value }); }
      else if (reply.readableEnded) { cleanup(); resolve_({ done: true }); }
      else if (reply.destroyed) aborted();
    };
    reply.on('readable', take); reply.on('end', take);
    reply.once('error', failed); reply.once('aborted', aborted);
    take();
  });
}

export async function createCopyPartialHold(
  configuration, ports = { listen: 3903, upstream: 3902 }, configurationSha256 = null,
) {
  requireFact(closed(configuration, ['version', 'root', 'targetPrefixes', 'host'])
    && configuration.version === 1 && configuration.host === 's3.fleet.test'
    && typeof configuration.root === 'string' && configuration.root === resolve(configuration.root)
    && Array.isArray(configuration.targetPrefixes) && configuration.targetPrefixes.length >= 1
    && configuration.targetPrefixes.length <= 2
    && new Set(configuration.targetPrefixes).size === configuration.targetPrefixes.length
    && configuration.targetPrefixes.every(prefix => typeof prefix === 'string' && prefix.length <= 2048
      && /^\/[A-Za-z0-9._/-]+\/$/.test(prefix) && !prefix.startsWith('//')
      && !prefix.split('/').some(part => part === '.' || part === '..')
      && /\/\.aos-direct-qualification\/external-oci\/[0-9a-f]{32}\/registry\/$/.test(prefix)), 'Partial Copy initial selection differs');
  const root = configuration.root;
  const metadata = await fs.lstat(root);
  requireFact(metadata.isDirectory() && metadata.uid === process.getuid()
    && (metadata.mode & 0o777) === 0o700 && await fs.realpath(root) === root,
  'Partial Copy custody differs');
  const cases = [];
  for (const [index, targetPrefix] of configuration.targetPrefixes.entries()) {
    const caseRoot = `${root}/case-${index}`;
    await fs.mkdir(caseRoot, { mode: 0o700 });
    cases.push({ root: caseRoot, targetPrefix, ceiling: null, used: false, selected: false,
      prefixReceipt: null, releaseHeld: null, ordinal: 0, recorderHealthy: true, terminal: null });
  }
  const tasks = new Set(), sockets = new Set();

  async function event(state, kind, facts = {}) {
    if (state.ordinal >= 16) { state.recorderHealthy = false; return; }
    const row = { version: 1, kind, ordinal: state.ordinal++, unixMillis: String(Date.now()), ...facts };
    await retain(state.root, `event-${String(row.ordinal).padStart(2, '0')}.json`, encode(row));
  }

  async function forwardPrefix(state, response, reply, identity, requestReceipt) {
    requireFact(Buffer.byteLength(JSON.stringify(reply.rawHeaders)) <= HEADER_BOUND,
      'Selected real headers exceed bound');
    const length = header(reply.rawHeaders, 'content-length');
    if (![200, 206].includes(reply.statusCode) || header(reply.rawHeaders, 'etag') !== identity.ifMatch
        || typeof length !== 'string' || !/^[1-9][0-9]*$/.test(length)
        || BigInt(length) <= BigInt(PREFIX_BYTES)) {
      await event(state, 'response_not_held', { status: reply.statusCode, providerSettlement: null });
      response.writeHead(reply.statusCode, reply.rawHeaders);
      await new Promise((resolve_, reject) => {
        reply.once('error', reject); reply.once('end', resolve_); reply.pipe(response);
      });
      return;
    }
    const headersReceipt = await retain(state.root, 'response-headers.private', encode(reply.rawHeaders));
    response.writeHead(reply.statusCode, reply.rawHeaders);
    const blocks = [];
    let offered = 0, remainder = Buffer.alloc(0), sourceEof = false;
    while (offered < PREFIX_BYTES) {
      const next = await nextBounded(reply);
      requireFact(!next.done && next.value.length <= PREFIX_BYTES, 'Source ended or block exceeds bound');
      const count = Math.min(next.value.length, PREFIX_BYTES - offered);
      const prefix = next.value.subarray(0, count);
      blocks.push(prefix);
      offered += count;
      if (!response.write(prefix)) await new Promise((resolve_, reject) => {
        response.once('drain', resolve_);
        response.once('close', () => reject(new Error('Downstream closed before prefix')));
      });
      remainder = next.value.subarray(count);
    }
    reply.pause();
    const prefixFile = await retain(state.root, 'offered-prefix.private', Buffer.concat(blocks, PREFIX_BYTES));
    state.prefixReceipt = await retain(state.root, 'prefix-receipt.private.json', encode({
      version: 1, scope: 'actual_provider_partial_response_offering', identity, requestReceipt,
      headersReceipt, prefixFile, downstreamOfferedBytes: String(offered),
      upstreamComplete: false, workerConsumedBytes: null, remoteDrain: null,
    }));
    await event(state, 'prefix_offered', { prefixReceipt: state.prefixReceipt });
    if (response.destroyed || reply.destroyed || Date.now() >= state.ceiling) return;
    await new Promise(resolve_ => { state.releaseHeld = resolve_; });
    state.releaseHeld = null;
    if (response.destroyed || reply.destroyed) return;
    if (remainder.length) { response.write(remainder); offered += remainder.length; }
    reply.resume();
    while (true) {
      const next = await nextBounded(reply);
      if (next.done) { sourceEof = true; break; }
      requireFact(next.value.length <= PREFIX_BYTES, 'Source continuation block exceeds bound');
      offered += next.value.length;
      if (!response.write(next.value)) await new Promise((resolve_, reject) => {
        response.once('drain', resolve_);
        response.once('close', () => reject(new Error('Downstream closed during continuation')));
      });
    }
    requireFact(String(offered) === length, 'Actual provider body ended at another size');
    response.end();
    state.terminal = { kind: 'source_eof', actualUpstreamComplete: reply.complete,
      downstreamOfferedBytes: String(offered) };
    await event(state, 'source_eof', { actualUpstreamComplete: reply.complete, sourceEof,
      downstreamOfferedBytes: String(offered), workerConsumedBytes: null, remoteDrain: null });
  }

  const server = createServer({ maxHeaderSize: HEADER_BOUND }, (request, response) => {
    const task = (async () => {
      let timeout = null;
      const state = cases.find(value => value.ceiling !== null && !value.selected
        && Date.now() < value.ceiling && request.url?.split('?')[0].startsWith(value.targetPrefix));
      let identity = null;
      try {
        if (state) identity = selectedIdentity(request, { ...configuration, targetPrefix: state.targetPrefix });
      } catch { /* A malformed selector remains an ordinary unchanged provider request. */ }
      if (identity) state.selected = true;
      const upstream = upstreamRequest({ hostname: '127.0.0.1', port: ports.upstream,
        method: request.method, path: request.url, headers: request.rawHeaders,
        setHost: false, maxHeaderSize: HEADER_BOUND, agent: false });
      response.once('close', () => {
        upstream.destroy();
        if (identity) {
          state.releaseHeld?.();
          event(state, 'downstream_closed', { remoteDrain: null })
            .catch(() => { state.recorderHealthy = false; });
        }
      });
      request.once('aborted', () => upstream.destroy());
      try {
        const requestReceipt = identity ? await retain(state.root, 'request.private.json', encode({
          method: request.method, target: request.url, rawHeaders: request.rawHeaders,
        })) : null;
        if (identity) timeout = setTimeout(() => {
          upstream.destroy(); response.destroy(); state.releaseHeld?.();
        }, Math.max(1, state.ceiling - Date.now()));
        await new Promise((resolve_, reject) => {
          upstream.once('error', reject);
          upstream.once('response', reply => {
            if (identity) {
              forwardPrefix(state, response, reply, identity, requestReceipt).then(resolve_, reject);
            } else {
              response.writeHead(reply.statusCode, reply.rawHeaders);
              reply.once('error', reject); reply.once('end', resolve_); reply.pipe(response);
            }
          });
          request.pipe(upstream);
        });
      } catch (error) {
        if (identity && state.terminal === null) state.terminal = { kind: 'unknown' };
        if (identity) await event(state, 'selected_unknown', {
          reason: String(error.message).slice(0, 256), remoteDrain: null,
        });
        upstream.destroy(); response.destroy();
        if (identity) state.releaseHeld?.();
      } finally {
        if (timeout) clearTimeout(timeout);
      }
    })();
    tasks.add(task);
    task.finally(() => tasks.delete(task));
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });

  async function command(value) {
    const state = cases.find(candidate => candidate.targetPrefix === value?.targetPrefix);
    requireFact(state, 'Unknown initial partial Copy prefix');
    if (closed(value, ['version', 'kind', 'targetPrefix']) && value.version === 1 && value.kind === 'state') {
      return { version: 1, targetPrefix: state.targetPrefix, selected: state.selected,
        prefixReceipt: state.prefixReceipt, recorderHealthy: state.recorderHealthy,
        terminal: state.terminal, pendingLocalHold: state.releaseHeld !== null, providerSettlement: null };
    }
    if (closed(value, ['version', 'kind', 'targetPrefix']) && value.version === 1 && value.kind === 'release') {
      requireFact(state.releaseHeld !== null && Date.now() < state.ceiling, 'No current partial hold to release');
      await event(state, 'fixture_released', { remoteDrain: null }); state.releaseHeld();
      return { version: 1, status: 'released', providerSettlement: null };
    }
    requireFact(closed(value, ['version', 'kind', 'targetPrefix', 'holdUntilUnixMillis']) && value.version === 1
      && value.kind === 'arm' && !state.used && Number.isSafeInteger(value.holdUntilUnixMillis)
      && value.holdUntilUnixMillis > Date.now() && value.holdUntilUnixMillis - Date.now() <= 35000,
    'Partial hold arm differs');
    state.used = true; state.ceiling = value.holdUntilUnixMillis;
    await event(state, 'armed', { ceilingUnixMillis: String(state.ceiling) });
    return { version: 1, status: 'armed' };
  }
  const control = controlServer({ allowHalfOpen: true }, socket => {
    const blocks = []; let size = 0;
    socket.setTimeout(2000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('data', block => { size += block.length; if (size > CONTROL_BOUND) socket.destroy(); else blocks.push(block); });
    socket.once('end', () => {
      Promise.resolve().then(() => command(JSON.parse(Buffer.concat(blocks).toString('utf8'))))
        .then(value => socket.end(encode(value)), () => socket.end(encode({ version: 1, status: 'refused' })));
    });
  });
  await listen(server, ports.listen, '127.0.0.1');
  await listen(control, `${root}/control.sock`);
  await fs.chmod(`${root}/control.sock`, 0o600);
  const ready = { version: 1, scope: 'copy_partial_response_listener', pid: process.pid,
    startTicks: (await fs.readFile('/proc/self/stat', 'utf8')).split(') ').at(-1).trim().split(/\s+/)[19],
    ownerUid: process.getuid(), configurationSha256,
    executableSha256: await hashExecutable(),
    commandLine: await retain(root, 'command-line.private', await fs.readFile('/proc/self/cmdline')),
    environment: await retain(root, 'environment.private', await fs.readFile('/proc/self/environ')),
    listenerSourceSha256: sha(await fs.readFile(fileURLToPath(import.meta.url))),
    listenAddress: `127.0.0.1:${server.address().port}`, upstreamAddress: `127.0.0.1:${ports.upstream}`,
    controlSocket: `${root}/control.sock`, prefixBytes: String(PREFIX_BYTES),
    selectedPrefixes: configuration.targetPrefixes, bodyBlockBound: String(PREFIX_BYTES),
  };
  await retain(root, 'ready.json', encode(ready));
  return { ready, command, close: async () => {
    for (const socket of sockets) socket.destroy();
    for (const state of cases) state.releaseHeld?.();
    await Promise.allSettled([...tasks]);
    await Promise.all([new Promise(resolve_ => server.close(resolve_)), new Promise(resolve_ => control.close(resolve_))]);
  } };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  requireFact(process.argv.length === 4 && process.argv[2] === '--config', 'Use --config privateConfigPath');
  const descriptor = await fs.open(resolve(process.argv[3]), constants.O_RDONLY | constants.O_NOFOLLOW);
  let configuration, configurationSha256;
  try {
    const before = await descriptor.stat();
    requireFact(before.isFile() && before.uid === process.getuid() && (before.mode & 0o777) === 0o600
      && before.nlink === 1 && before.size <= CONTROL_BOUND, 'Partial Copy configuration custody differs');
    const bytes = await descriptor.readFile();
    const after = await descriptor.stat();
    requireFact(before.size === after.size && before.mtimeMs === after.mtimeMs
      && before.ctimeMs === after.ctimeMs && bytes.length === before.size, 'Partial Copy configuration changed');
    configuration = JSON.parse(bytes);
    configurationSha256 = sha(bytes);
  } finally { await descriptor.close(); }
  const listener = await createCopyPartialHold(configuration, undefined, configurationSha256);
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => listener.close().then(() => process.exit(0)));
}
