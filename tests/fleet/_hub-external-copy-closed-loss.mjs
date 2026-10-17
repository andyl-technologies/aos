// One-shot metadata reply loss after the selected shared Core authenticators.
// Envelope verification is not a current SQL or provider-settlement verdict.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, lstat, chmod, readFile } from 'node:fs/promises';
import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createServer as createSocketServer } from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, isAbsolute } from 'node:path';

const PATH = '/_internal/storage/external-copy/v1';
const SIGNATURE = 'x-aos-storage-work-signature';
const MAX_BODY = 65536;
const MAX_CONTROL = 32768;
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const hash = value => createHash('sha256').update(value).digest('hex');

function closed(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) {
    throw new Error('closed-loss fields differ');
  }
}

async function privateRead(path, maximum) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat();
    if (!before.isFile() || before.uid !== process.getuid() || (before.mode & 0o077) !== 0
        || before.size > maximum) throw new Error('private source differs');
    const bytes = await file.readFile();
    const after = await file.stat();
    if (bytes.length !== before.size || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs']
        .some(key => before[key] !== after[key])) throw new Error('private source changed');
    return bytes;
  } finally {
    await file.close();
  }
}

async function retain(root, name, bytes) {
  const path = join(root, name);
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
    | constants.O_NOFOLLOW, 0o600);
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
  return { file: path, sha256: hash(bytes), byteSize: String(bytes.length) };
}

async function bounded(stream, maximum) {
  const blocks = [];
  let count = 0;
  for await (const block of stream) {
    count += block.length;
    if (count > maximum) throw new Error('metadata body oversized');
    blocks.push(block);
  }
  return Buffer.concat(blocks, count);
}

async function executable(path, expected) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat();
    if (!before.isFile() || !(before.mode & 0o111) || before.size > 2 * 1024 * 1024 * 1024) {
      throw new Error('selected executable differs');
    }
    const digest = createHash('sha256');
    const block = Buffer.alloc(65536);
    let counted = 0;
    for (;;) {
      const { bytesRead } = await file.read(block, 0, block.length, null);
      if (bytesRead === 0) break;
      counted += bytesRead;
      if (counted > before.size) throw new Error('selected executable grew');
      digest.update(block.subarray(0, bytesRead));
    }
    const after = await file.stat();
    if (counted !== before.size || digest.digest('hex') !== expected
        || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) {
      throw new Error('selected executable changed');
    }
  } finally {
    await file.close();
  }
}

async function verify(config, selectionFile, ceiling) {
  await executable(config.codecFile, config.codecSha256);
  const result = await new Promise((resolve, reject) => {
    const child = spawn(config.codecFile, ['copy-closed-reply', selectionFile],
      { stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
    const stdout = [];
    let size = 0;
    let stderrBytes = 0;
    const timer = setTimeout(() => child.kill('SIGKILL'), Math.max(1,
      Math.min(10000, ceiling - Date.now())));
    child.stdout.on('data', bytes => {
      size += bytes.length;
      if (size > 16384) child.kill('SIGKILL');
      else stdout.push(bytes);
    });
    child.stderr.on('data', bytes => {
      stderrBytes += bytes.length;
      if (stderrBytes > 16384) child.kill('SIGKILL');
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (code !== 0 || signal || size > 16384 || stderrBytes > 16384) {
        reject(new Error('selected codec refused'));
      } else resolve(Buffer.concat(stdout));
    });
  });
  await executable(config.codecFile, config.codecSha256);
  return result;
}

export async function createCopyClosedLoss(config, ports = { listen: 4678, upstream: 4675, upstreamTls: true },
                                         configurationSha256 = null) {
  closed(config, ['version', 'root', 'deploymentId', 'sourceDigest', 'codecFile',
    'codecSha256', 'codecSourceSha256', 'keyFile', 'keySha256']);
  if (config.version !== 1 || !isAbsolute(config.root) || !isAbsolute(config.codecFile)
      || !isAbsolute(config.keyFile) || !config.deploymentId || config.deploymentId.length > 255
      || [config.sourceDigest, config.codecSha256, config.codecSourceSha256, config.keySha256]
        .some(value => !hex(value))) throw new Error('initial selection differs');
  for (const port of [ports.listen, ports.upstream]) {
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('listener port differs');
  }
  if (typeof ports.upstreamTls !== 'boolean') throw new Error('upstream transport differs');
  const sendUpstream = (options, callback) => ports.upstreamTls
    ? httpsRequest({ ...options, servername: 'localhost', rejectUnauthorized: true }, callback)
    : httpRequest(options, callback);
  const root = await lstat(config.root);
  if (!root.isDirectory() || root.isSymbolicLink() || root.uid !== process.getuid()
      || (root.mode & 0o077) !== 0) throw new Error('control root differs');
  await executable(config.codecFile, config.codecSha256);
  const initialKey = await privateRead(config.keyFile, 64);
  if (initialKey.length !== 64 || !/^[0-9a-f]{64}$/.test(initialKey.toString())
      || hash(initialKey) !== config.keySha256) throw new Error('literal key differs');
  let arm = null;
  let active = false;
  let consumed = false;
  let attempts = 0;
  let observation = null;
  let terminal = null;
  const sockets = new Set();

  const server = createServer(async (incoming, outgoing) => {
    // Unarmed and unrelated traffic retains its ordinary streaming behavior.
    if (!arm || consumed || active || Date.now() >= arm.lossUntilUnixMillis
        || incoming.method !== 'POST' || incoming.url !== PATH) {
      const forwarded = sendUpstream({ host: '127.0.0.1', port: ports.upstream,
        method: incoming.method, path: incoming.url, headers: incoming.headers }, response => {
        response.on('error', () => outgoing.destroy());
        outgoing.writeHead(response.statusCode, response.headers);
        response.pipe(outgoing);
      });
      forwarded.on('error', () => outgoing.destroy());
      incoming.on('error', () => forwarded.destroy());
      incoming.pipe(forwarded);
      outgoing.once('close', () => forwarded.destroy());
      return;
    }
    active = true;
    attempts += 1;
    const attempt = attempts;
    let upstream = null;
    const timer = setTimeout(() => {
      consumed = true;
      terminal = 'unknown_selection_timeout';
      upstream?.destroy();
      outgoing.destroy();
    }, Math.max(1, arm.lossUntilUnixMillis - Date.now()));
    try {
      if (attempt > 64) throw new Error('Closed selection attempts exceeded');
      const request = await bounded(incoming, MAX_BODY);
      const response = await new Promise((resolve, reject) => {
        const sent = sendUpstream({ host: '127.0.0.1', port: ports.upstream,
          method: incoming.method, path: incoming.url, headers: incoming.headers }, resolve);
        upstream = sent;
        sent.once('error', reject);
        sent.end(request);
      });
      const reply = await bounded(response, MAX_BODY);
      let candidate = false;
      try {
        candidate = JSON.parse(request).control === 'advance'
          && JSON.parse(reply).progress?.phase === 'closed';
      } catch {}
      if (response.statusCode === 200 && candidate) {
        const directory = 'attempt-' + String(attempt).padStart(3, '0');
        const requestRef = await retain(config.root, directory + '-request.json', request);
        const replyRef = await retain(config.root, directory + '-reply.json', reply);
        const key = await privateRead(config.keyFile, 64);
        if (hash(key) !== config.keySha256) throw new Error('installed key changed');
        const selection = { version: 1, sourceDigest: config.sourceDigest,
          deploymentId: config.deploymentId, expectedOriginalSha256: arm.originalSha256,
          key: { file: config.keyFile, sha256: config.keySha256, byteSize: '64' },
          request: requestRef, reply: replyRef, requestSignature: incoming.headers[SIGNATURE],
          replySignature: response.headers[SIGNATURE] };
        const selected = await retain(config.root, directory + '-selection.json',
          Buffer.from(JSON.stringify(selection)));
        try {
          const bytes = await verify(config, selected.file, arm.lossUntilUnixMillis);
          const verified = JSON.parse(bytes);
          closed(verified, ['version', 'scope', 'sourceDigest', 'codecSourceSha256',
            'originalSha256', 'requestSha256', 'requestBytes', 'replySha256', 'replyBytes',
            'observedAt', 'phase']);
          if (verified.version !== 1 || verified.scope !== 'authenticated_copy_closed_envelope_only'
              || verified.phase !== 'closed' || verified.sourceDigest !== config.sourceDigest
              || verified.codecSourceSha256 !== config.codecSourceSha256
              || verified.originalSha256 !== arm.originalSha256
              || verified.requestSha256 !== requestRef.sha256 || verified.requestBytes !== requestRef.byteSize
              || verified.replySha256 !== replyRef.sha256 || verified.replyBytes !== replyRef.byteSize
              || !Number.isSafeInteger(verified.observedAt) || Date.now() >= arm.lossUntilUnixMillis) {
            throw new Error('Closed verification correlation differs');
          }
          const receipt = await retain(config.root, directory + '-verification.json', bytes);
          if (outgoing.destroyed) {
            consumed = true;
            terminal = 'unknown_downstream_already_closed';
            return;
          }
          const retained = { request: requestRef, reply: replyRef, selection: selected,
            verification: receipt, captureId: arm.captureId, originalSha256: arm.originalSha256 };
          consumed = true;
          outgoing.destroy();
          try {
            const loss = await retain(config.root, directory + '-loss.json', Buffer.from(JSON.stringify({
              version: 1, ...retained, downstreamDestroyInvoked: true,
              nativeObservedLoss: null, providerSettlement: null, observedAt: Date.now() })));
            observation = { ...retained, loss };
            terminal = 'authenticated_closed_downstream_destroyed';
          } catch {
            terminal = 'unknown_loss_receipt_failure';
          }
          return;
        } catch {
          // Refusal never creates a replacement reply or a successful loss claim.
          await retain(config.root, directory + '-refusal.json', Buffer.from(JSON.stringify({
            version: 1, kind: 'envelope_verification_refused', observedAt: Date.now() })));
        }
      }
      outgoing.writeHead(response.statusCode, response.headers);
      outgoing.end(reply);
    } catch {
      consumed = true;
      terminal = 'unknown_transport_failure';
      outgoing.destroy();
    } finally {
      clearTimeout(timer);
      active = false;
    }
  });
  server.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise(resolve => server.listen(ports.listen, '127.0.0.1', resolve));

  async function command(value) {
    if (value?.kind === 'arm') {
      closed(value, ['version', 'kind', 'captureId', 'originalSha256', 'lossUntilUnixMillis']);
      if (value.version !== 1 || arm || !/^[0-9a-f]{32}$/.test(value.captureId)
          || !hex(value.originalSha256) || !Number.isSafeInteger(value.lossUntilUnixMillis)
          || value.lossUntilUnixMillis <= Date.now() || value.lossUntilUnixMillis > Date.now() + 35000) {
        throw new Error('one-use Closed selection refused');
      }
      arm = { ...value };
      return { version: 1, status: 'armed' };
    }
    closed(value, ['version', 'kind']);
    if (value.version !== 1 || value.kind !== 'state') throw new Error('unsupported control');
    return { version: 1, armed: arm !== null, active, consumed, attempts, observation, terminal,
      providerSettlement: null, nativeObservedLoss: null };
  }

  const controlSocket = join(config.root, 'control.sock');
  const control = createSocketServer(socket => {
    let chunks = [], size = 0;
    const timer = setTimeout(() => socket.destroy(), 5000);
    socket.once('close', () => clearTimeout(timer));
    socket.on('data', async block => {
      size += block.length;
      if (size > MAX_CONTROL) return socket.destroy();
      chunks.push(block);
      if (!block.includes(10)) return;
      socket.pause();
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString());
        socket.end(JSON.stringify(await command(value)) + '\n');
      } catch { socket.end('{"version":1,"status":"refused"}\n'); }
    });
    socket.on('error', () => socket.destroy());
  });
  await new Promise(resolve => control.listen(controlSocket, resolve));
  await chmod(controlSocket, 0o600);
  const stat = (await readFile('/proc/self/stat', 'utf8')).split(') ').at(-1).trim().split(/\s+/);
  const ready = { version: 1, scope: 'copy_closed_reply_loss_listener', pid: process.pid,
    startTicks: stat[19], ownerUid: process.getuid(),
    configurationSha256: configurationSha256 ?? hash(Buffer.from(JSON.stringify(config))),
    executableSha256: hash(await readFile(process.execPath)),
    commandLine: (await readFile('/proc/self/cmdline')).toString('base64'),
    environment: (await readFile('/proc/self/environ')).toString('base64'),
    listenAddress: '127.0.0.1:' + server.address().port,
    upstreamAddress: '127.0.0.1:' + ports.upstream,
    upstreamScheme: ports.upstreamTls ? 'https' : 'http',
    tlsServerName: ports.upstreamTls ? 'localhost' : null,
    listenerSourceSha256: hash(await readFile(fileURLToPath(import.meta.url))),
    controlSocket, bodyBytesMaximum: String(MAX_BODY), attemptsMaximum: 64 };
  await retain(config.root, 'ready.json', Buffer.from(JSON.stringify(ready)));
  return { ready, command, async close() {
    for (const socket of sockets) socket.destroy();
    await Promise.all([new Promise(resolve => server.close(resolve)),
      new Promise(resolve => control.close(resolve))]);
  } };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4 || process.argv[2] !== '--config') throw new Error('expected --config');
  const bytes = await privateRead(process.argv[3], 16384);
  const listener = await createCopyClosedLoss(JSON.parse(bytes), undefined, hash(bytes));
  process.once('SIGTERM', async () => { await listener.close(); process.exit(0); });
}
