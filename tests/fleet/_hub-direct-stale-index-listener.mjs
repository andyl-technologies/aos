// Fixed fixture-only storage-work forwarding with one retained info/refs hold.
// This listener neither verifies HMACs nor creates provider permission.
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ROUTE = '/_internal/storage/v1/execute';
const BODY_LIMIT = 1024 * 1024;
const CONTROL_LIMIT = 64 * 1024;
// Two configured publisher envelopes can overlap (2 * (8 bulk + 32 metadata)).
// This is a fixture transport ceiling, not Worker SDK admission or a load result.
const MAX_REQUESTS = 128;
const MAX_RETAINED_ROWS = 204704;
const MAX_RETAINED_BYTES = 512 * 1024 * 1024;
const FIELDS = ['version', 'root', 'listenPort', 'upstreamHost', 'upstreamPort',
  'originHost', 'certificateFile', 'privateKeyFile', 'caFile', 'holdModuleFile'];

function exact(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...fields].sort().join('\0');
}

function privateRoot(root) {
  const observed = fs.lstatSync(root);
  if (!path.isAbsolute(root) || !observed.isDirectory()
      || observed.uid !== process.getuid() || (observed.mode & 0o077)) {
    throw new Error('listener_root_custody');
  }
}

function retain(root, name, value) {
  const descriptor = fs.openSync(path.join(root, name),
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW, 0o600);
  try {
    fs.writeFileSync(descriptor, JSON.stringify(value) + '\n');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  const parent = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}

function boundedFile(file, maximum) {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.size > maximum) throw new Error('listener_file_bound');
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (bytes.length !== before.size || before.ino !== after.ino
        || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new Error('listener_file_changed');
    }
    return bytes;
  } finally { fs.closeSync(descriptor); }
}

async function requestBytes(request, maximum) {
  const declared = request.headers['content-length'];
  if (!/^(0|[1-9][0-9]*)$/.test(declared ?? '')
      || Number(declared) > maximum || request.headers['transfer-encoding'] !== undefined) {
    throw new Error('listener_request_framing');
  }
  const chunks = [];
  let count = 0;
  request.setTimeout(5000, () => request.destroy(new Error('listener_body_timeout')));
  for await (const chunk of request) {
    count += chunk.length;
    if (count > maximum || count > Number(declared)) throw new Error('listener_request_bound');
    chunks.push(chunk);
  }
  request.setTimeout(0);
  if (count !== Number(declared)) throw new Error('listener_request_length');
  return Buffer.concat(chunks, count);
}

/** Starts only the fixed metadata route and an owner-private control socket. */
export async function startListener(configuration) {
  if (!exact(configuration, FIELDS) || configuration.version !== 1
      || configuration.upstreamHost !== 'worker' || configuration.upstreamPort !== 443
      || configuration.originHost !== 'aos.andyl.org'
      || !Number.isInteger(configuration.listenPort)
      || configuration.listenPort < 0 || configuration.listenPort > 65535) {
    throw new Error('listener_configuration');
  }
  privateRoot(configuration.root);
  const module = await import(pathToFileURL(configuration.holdModuleFile));
  const ca = boundedFile(configuration.caFile, 1024 * 1024);
  const certificate = boundedFile(configuration.certificateFile, 64 * 1024);
  const key = boundedFile(configuration.privateKeyFile, 64 * 1024);
  const root = configuration.root;
  let hold = null;
  let active = 0;
  let sequence = 0;
  let shuttingDown = false;
  let retainedRows = 0;
  let retainedBytes = 0;
  let overflow = false;
  let dispatched = 0;
  let refused = 0;
  let capacityRefusals = 0;

  function transportStatus() {
    return { version: 1, requests: sequence, active, offeredDispatches: dispatched,
      refusedRequests: refused, capacityRefusals,
      retainedRows, retainedBytes, overflow, maximumActiveRequests: MAX_REQUESTS,
      maximumRetainedRows: MAX_RETAINED_ROWS, maximumRetainedBytes: MAX_RETAINED_BYTES,
      scope: 'fixture_execute_transport_observations_only' };
  }

  function retainTransport(name, value) {
    const size = Buffer.byteLength(JSON.stringify(value) + '\n');
    if (overflow || retainedRows >= MAX_RETAINED_ROWS
        || retainedBytes + size > MAX_RETAINED_BYTES) {
      if (!overflow) {
        overflow = true;
        retain(root, 'transport-overflow.json', transportStatus());
      }
      return false;
    }
    retain(root, name, value);
    retainedRows += 1;
    retainedBytes += size;
    return true;
  }

  const server = https.createServer({ cert: certificate, key }, async (request, response) => {
    if (shuttingDown || request.method !== 'POST' || request.url !== ROUTE
        || request.headers.host !== configuration.originHost) {
      response.writeHead(404).end();
      return;
    }
    const invocation = ++sequence;
    if (overflow || active >= MAX_REQUESTS) {
      refused += 1;
      capacityRefusals += 1;
      if (!overflow) retainTransport(`refused-${invocation}.json`, {
        version: 1, observedAtUnixMillis: String(Date.now()),
        outcome: 'transport_capacity_refused_before_body', providerOutcome: null,
      });
      response.writeHead(503).end();
      return;
    }
    active += 1;
    let upstream = null;
    let finished = false;
    let ownsHold = false;
    const disconnected = () => {
      if (!finished && ownsHold && hold?.status().state === 'held') hold.close();
      // Destroying a transport is not evidence of Worker/provider drain.
      upstream?.destroy();
    };
    response.on('close', disconnected);
    try {
      const body = await requestBytes(request, BODY_LIMIT);
      const headers = request.rawHeaders.slice();
      if (hold) {
        const waiting = hold.beforeDispatch(request, body);
        const observed = hold.status();
        ownsHold = observed.state === 'held'
          && observed.requestSha256 === crypto.createHash('sha256').update(body).digest('hex');
        await waiting;
        if (ownsHold && Date.now() >= Number(hold.status().expiresAtUnixSeconds) * 1000) {
          throw new Error('listener_original_expired_before_forward');
        }
      }
      if (response.destroyed || shuttingDown) throw new Error('listener_caller_closed');
      if (!retainTransport(`dispatch-${invocation}.json`, {
        version: 1, method: request.method, route: request.url,
        bodyBytes: String(body.length), bodySha256: crypto.createHash('sha256').update(body).digest('hex'),
        rawHeaders: headers, observedAtUnixMillis: String(Date.now()),
      })) throw new Error('listener_transport_evidence_overflow');
      dispatched += 1;
      await new Promise((resolve, reject) => {
        upstream = https.request({ hostname: configuration.upstreamHost,
          port: configuration.upstreamPort, servername: configuration.originHost,
          ca, rejectUnauthorized: true, method: request.method, path: request.url,
          headers }, received => {
          response.writeHead(received.statusCode, received.rawHeaders);
          received.on('error', reject);
          received.on('end', resolve);
          received.pipe(response);
        });
        upstream.setTimeout(35000, () => upstream.destroy(new Error('listener_upstream_timeout')));
        upstream.on('error', reject);
        upstream.end(body);
      });
      finished = true;
    } catch {
      refused += 1;
      if (!overflow) retainTransport(`refused-${invocation}.json`, {
          version: 1, observedAtUnixMillis: String(Date.now()),
          outcome: 'transport_failed_or_refused', providerOutcome: null,
        });
      if (!response.headersSent && !response.destroyed) response.writeHead(502).end();
      else response.destroy();
    } finally {
      response.removeListener('close', disconnected);
      active -= 1;
    }
  });
  server.headersTimeout = 5000;
  server.requestTimeout = 10000;
  server.keepAliveTimeout = 1000;

  const control = net.createServer(socket => {
    let chunks = [], count = 0;
    socket.setTimeout(5000, () => socket.destroy());
    socket.on('data', bytes => {
      count += bytes.length;
      if (count > CONTROL_LIMIT) { socket.destroy(); return; }
      chunks.push(bytes);
      const raw = Buffer.concat(chunks, count);
      if (!raw.includes(10)) return;
      socket.pause();
      try {
        const request = JSON.parse(raw.toString());
        if (!raw.equals(Buffer.from(JSON.stringify(request) + '\n'))) throw new Error('control_canonical');
        let result;
        if (exact(request, ['version', 'kind', 'selection']) && request.version === 1
            && request.kind === 'arm' && !hold && request.selection.originHost === configuration.originHost) {
          const directory = path.join(root, 'hold');
          fs.mkdirSync(directory, { mode: 0o700 });
          hold = module.stalePlacementHold(request.selection, directory);
          result = hold.status();
        } else if (exact(request, ['version', 'kind']) && request.version === 1
            && request.kind === 'status') {
          result = hold ? hold.status() : { version: 1, state: 'unarmed' };
        } else if (exact(request, ['version', 'kind']) && request.version === 1
            && request.kind === 'transport-status') {
          result = transportStatus();
        } else if (exact(request, ['version', 'kind', 'requestSha256']) && request.version === 1
            && request.kind === 'release' && hold) {
          result = hold.release(request.requestSha256);
        } else if (exact(request, ['version', 'kind']) && request.version === 1
            && request.kind === 'close') {
          hold?.close();
          result = hold ? hold.status() : { version: 1, state: 'unarmed' };
        } else throw new Error('control_selection');
        socket.end(JSON.stringify({ version: 1, status: 'observed', result }) + '\n');
      } catch {
        socket.end(JSON.stringify({ version: 1, status: 'refused' }) + '\n');
      }
    });
  });
  const socketFile = path.join(root, 'control.sock');
  await new Promise((resolve, reject) => {
    control.once('error', reject);
    control.listen(socketFile, () => { fs.chmodSync(socketFile, 0o600); resolve(); });
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(configuration.listenPort, '127.0.0.1', resolve);
    });
  } catch (error) { control.close(); throw error; }
  retain(root, 'ready.json', { version: 1, pid: process.pid,
    port: server.address().port, socketFile, scope: 'fixture_metadata_transport_only' });

  return { server, control, close() {
    shuttingDown = true;
    hold?.close();
    server.close();
    server.closeAllConnections();
    control.close();
  } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.umask(0o077);
  if (process.argv.length !== 3) throw new Error('listener_requires_configuration_file');
  const configuration = JSON.parse(boundedFile(process.argv[2], CONTROL_LIMIT));
  const running = await startListener(configuration);
  process.on('SIGTERM', () => running.close());
  process.on('SIGINT', () => running.close());
}
