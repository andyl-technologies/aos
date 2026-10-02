// One retained OCI projection original can be delivered to a separately observed
// same-source Worker. This fixture preserves bytes and never authenticates them.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const ROUTE = '/_internal/storage/oci-document-projection';
const BODY_LIMIT = 16384;
const REPLY_LIMIT = 4 * 1024 * 1024 + 65536;
const MAX_ACTIVE = 128;
const MAX_ROWS = 204704;
const MAX_BYTES = 512 * 1024 * 1024;
const CONFIG = ['version', 'root', 'listenPort', 'upstreamAPort', 'upstreamBPort', 'originHost'];
const SELECT = ['version', 'capture_id', 'placement_prefix', 'document_digest',
  'protected_profile_digest', 'source_digest', 'script_version'];
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join('\0') === [...fields].sort().join('\0');
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

function privateRoot(root) {
  const stat = fs.lstatSync(root);
  if (!path.isAbsolute(root) || !stat.isDirectory() || stat.uid !== process.getuid()
      || stat.mode & 0o077) throw new Error('profile_hold_root_custody');
}

function retain(root, name, bytes) {
  const fd = fs.openSync(path.join(root, name),
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const parent = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}

async function bodyBytes(request, bound) {
  const declared = request.headers['content-length'];
  if (!/^(0|[1-9][0-9]*)$/.test(declared ?? '') || Number(declared) > bound
      || request.headers['transfer-encoding'] !== undefined) throw new Error('profile_hold_framing');
  const chunks = [];
  let size = 0;
  const timer = setTimeout(() => request.destroy(new Error('profile_hold_body_deadline')), 5000);
  try {
    for await (const chunk of request) {
      size += chunk.length;
      if (size > Number(declared) || size > bound) throw new Error('profile_hold_body_bound');
      chunks.push(chunk);
    }
    if (size !== Number(declared)) throw new Error('profile_hold_body_length');
    return Buffer.concat(chunks, size);
  } finally { clearTimeout(timer); }
}

/** Starts a fixed projection transport and an owner-private Unix control socket. */
export async function startListener(configuration) {
  if (!exact(configuration, CONFIG) || configuration.version !== 1
      || configuration.originHost !== 'localhost:4643'
      || [configuration.listenPort, configuration.upstreamAPort, configuration.upstreamBPort]
        .some(port => !Number.isInteger(port) || port < 0 || port > 65535)) {
    throw new Error('profile_hold_configuration');
  }
  privateRoot(configuration.root);
  const root = configuration.root;
  let selectedResponse = null;
  let selection = null, held = null, phase = 'unarmed', active = 0, sequence = 0;
  let rows = 0, bytes = 0, overflow = false, closed = false;
  let releaseHeld = null, rejectHeld = null, holdTimer = null;

  function write(name, value, raw = false) {
    const body = raw ? value : Buffer.from(JSON.stringify(value) + '\n');
    if (overflow || rows >= MAX_ROWS || bytes + body.length > MAX_BYTES) {
      overflow = true;
      throw new Error('profile_hold_evidence_overflow');
    }
    retain(root, name, body);
    rows += 1; bytes += body.length;
  }

  function status() {
    return { version: 1, state: phase, original: held, response: selectedResponse, active, requests: sequence,
      retainedRows: rows, retainedBytes: bytes, overflow,
      maximumActiveRequests: MAX_ACTIVE, maximumRetainedRows: MAX_ROWS,
      maximumRetainedBytes: MAX_BYTES, scope: 'preserved_projection_transport_only' };
  }

  function abandon(reason) {
    if (phase !== 'held') return;
    phase = 'unknown';
    clearTimeout(holdTimer);
    try { write('hold-unknown.json', { version: 1, reason, observedAt: String(Date.now()) }); }
    finally { rejectHeld(new Error(reason)); }
  }

  function matches(request, body) {
    if (phase !== 'armed' || !selection) return null;
    const value = JSON.parse(body);
    const signature = request.headers['x-aos-oci-projection-signature'];
    if (value.version !== 1 || value.source !== undefined || !value.admission
        || value.key !== selection.placement_prefix + '/' + value.admission.staging_object_key
        || value.admission.placement_prefix !== selection.placement_prefix
        || !value.key?.startsWith(selection.placement_prefix + '/')
        || value.descriptor?.digest !== selection.document_digest
        || value.protected_profile_digest !== selection.protected_profile_digest
        || value.issuer?.source_digest !== selection.source_digest
        || value.issuer?.script_version !== selection.script_version
        || !digest(value.nonce) || typeof signature !== 'string' || signature.length > 256
        || !Number.isSafeInteger(value.issued_at) || !Number.isSafeInteger(value.expires_at)
        || !Number.isSafeInteger(value.clock_uncertainty_seconds)
        || value.clock_uncertainty_seconds < 1 || value.clock_uncertainty_seconds >= 30
        || value.expires_at - value.issued_at < 1 || value.expires_at - value.issued_at > 30
        || Date.now() + value.clock_uncertainty_seconds * 1000 >= value.expires_at * 1000) return null;
    return value;
  }

  const server = http.createServer(async (request, response) => {
    if (closed || request.method !== 'POST' || request.url !== ROUTE
        || request.headers.host !== configuration.originHost) {
      response.writeHead(404).end(); return;
    }
    const id = ++sequence;
    if (active >= MAX_ACTIVE || overflow) { response.writeHead(503).end(); return; }
    active += 1;
    let upstream = null, selected = false, terminal = false, timer = null;
    const disconnect = () => {
      if (selected && !terminal) abandon('original_caller_closed');
      upstream?.destroy();
    };
    response.on('close', disconnect);
    try {
      const body = await bodyBytes(request, BODY_LIMIT);
      const wire = JSON.parse(body);
      if (!Number.isSafeInteger(wire.expires_at) || !Number.isSafeInteger(wire.issued_at)
          || !Number.isSafeInteger(wire.clock_uncertainty_seconds)
          || wire.clock_uncertainty_seconds < 1 || wire.clock_uncertainty_seconds >= 30
          || wire.expires_at - wire.issued_at < 1 || wire.expires_at - wire.issued_at > 30) {
        throw new Error('profile_transport_original_deadline');
      }
      const originalCutoff = (wire.expires_at - wire.clock_uncertainty_seconds) * 1000;
      const headers = request.rawHeaders.slice();
      if (Buffer.byteLength(JSON.stringify(headers)) > 32768) throw new Error('profile_hold_headers_bound');
      const lookup = matches(request, body);
      let port = configuration.upstreamAPort;
      if (lookup) {
        selected = true; phase = 'held';
        held = { requestSha256: hash(body), requestBytes: String(body.length),
          signatureSha256: hash(Buffer.from(request.headers['x-aos-oci-projection-signature'])),
          nonce: lookup.nonce, key: lookup.key, documentDigest: lookup.descriptor.digest,
          expiresAt: lookup.expires_at, uncertaintySeconds: lookup.clock_uncertainty_seconds,
          originalFile: path.join(root, 'original.body'), headersFile: path.join(root, 'original.headers.json') };
        write('original.body', body, true); write('original.headers.json', headers);
        write('hold-entry.json', { ...status(), observedAt: String(Date.now()) });
        await new Promise((resolve, reject) => {
          releaseHeld = resolve; rejectHeld = reject;
          holdTimer = setTimeout(() => abandon('original_deadline'),
            (lookup.expires_at - lookup.clock_uncertainty_seconds) * 1000 - Date.now());
        });
        port = configuration.upstreamBPort;
      }
      if (response.destroyed || closed) throw new Error('profile_hold_caller_closed');
      const cutoff = Math.min(originalCutoff, Date.now() + 30000);
      if (Date.now() >= cutoff) throw new Error('profile_hold_original_expired');
      write(`dispatch-${id}.json`, { version: 1, originalSha256: hash(body), byteSize: String(body.length),
        upstreamPort: port, selected, rawHeaders: headers, observedAt: String(Date.now()) });
      await new Promise((resolve, reject) => {
        upstream = http.request({ hostname: '127.0.0.1', port, method: request.method,
          path: request.url, headers }, received => {
          const sha = crypto.createHash('sha256'); let count = 0;
          const selectedChunks = [];
          response.writeHead(received.statusCode, received.rawHeaders);
          received.on('data', chunk => {
            count += chunk.length; sha.update(chunk);
            if (count > REPLY_LIMIT) upstream.destroy(new Error('profile_hold_reply_bound'));
            else if (selected) selectedChunks.push(chunk);
          });
          received.on('error', reject);
          received.on('end', () => {
            try {
              if (count > REPLY_LIMIT) throw new Error('profile_hold_reply_bound');
              const bodyFile = selected ? path.join(root, 'selected-response.body') : null;
              if (selected) write('selected-response.body', Buffer.concat(selectedChunks, count), true);
              const receipt = { version: 1, selected, status: received.statusCode,
              bodySha256: sha.digest('hex'), byteSize: String(count), rawHeaders: received.rawHeaders,
              observedAt: String(Date.now()), bodyFile };
              write(`response-${id}.json`, receipt);
              if (selected) selectedResponse = receipt;
              resolve(); } catch (error) { reject(error); }
          });
          received.pipe(response);
        });
        timer = setTimeout(() => upstream.destroy(new Error('profile_hold_response_deadline')), cutoff - Date.now());
        upstream.on('error', reject); upstream.end(body);
      });
      terminal = true;
      if (selected) { phase = 'terminal'; write('hold-terminal.json', status()); }
    } catch (error) {
      if (selected) { abandon(String(error.message)); if (phase === 'released') phase = 'unknown'; }
      if (!overflow) write(`unknown-${id}.json`, { version: 1, selected, reason: String(error.message), observedAt: String(Date.now()) });
      if (!response.headersSent && !response.destroyed) response.writeHead(502).end(); else response.destroy();
    } finally {
      clearTimeout(timer); response.removeListener('close', disconnect); active -= 1;
    }
  });
  server.headersTimeout = 5000; server.requestTimeout = 10000;
  const socketFile = path.join(root, 'control.sock');
  const control = net.createServer(socket => {
    let data = Buffer.alloc(0);
    socket.setTimeout(5000, () => socket.destroy());
    socket.on('data', chunk => {
      data = Buffer.concat([data, chunk]);
      if (data.length > 16384) { socket.destroy(); return; }
      if (!data.includes(10)) return;
      socket.pause();
      try {
        const command = JSON.parse(data);
        if (!data.equals(Buffer.from(JSON.stringify(command) + '\n'))) throw new Error('profile_control_canonical');
        if (exact(command, ['version', 'kind', 'selection']) && command.version === 1
            && command.kind === 'arm' && phase === 'unarmed' && exact(command.selection, SELECT)) {
          const selected = command.selection;
          if (selected.version !== 1 || !/^[a-f0-9]{32}$/.test(selected.capture_id)
              || !/^sha256:[a-f0-9]{64}$/.test(selected.document_digest)
              || !digest(selected.source_digest) || !digest(selected.protected_profile_digest)
              || typeof selected.script_version !== 'string' || selected.script_version.length > 256
              || typeof selected.placement_prefix !== 'string' || selected.placement_prefix.length > 512
              || !selected.placement_prefix.split('/').every(p => p && p !== '.' && p !== '..')) {
            throw new Error('profile_control_selection');
          }
          selection = selected; phase = 'armed'; write('selection.json', selected);
        } else if (exact(command, ['version', 'kind', 'requestSha256', 'nonce']) && command.version === 1
            && command.kind === 'release' && phase === 'held' && command.requestSha256 === held.requestSha256
            && command.nonce === held.nonce && Date.now() < (held.expiresAt - held.uncertaintySeconds) * 1000) {
          phase = 'released'; clearTimeout(holdTimer); write('release.json', { ...command, observedAt: String(Date.now()) }); releaseHeld();
        } else if (!(exact(command, ['version', 'kind']) && command.version === 1 && command.kind === 'status')) {
          throw new Error('profile_control_transition');
        }
        socket.end(JSON.stringify(status()) + '\n');
      } catch { socket.end(JSON.stringify({ version: 1, state: 'control_refused' }) + '\n'); }
    });
  });
  await new Promise((resolve, reject) => control.once('error', reject).listen(socketFile, resolve));
  fs.chmodSync(socketFile, 0o600);
  await new Promise((resolve, reject) => server.once('error', reject).listen(configuration.listenPort, '127.0.0.1', resolve));
  write('listener-ready.json', { version: 1, pid: process.pid, listenPort: server.address().port, socketFile });
  return { server, control, status, close: async () => {
    closed = true; abandon('listener_closed');
    await Promise.all([new Promise(resolve => server.close(resolve)), new Promise(resolve => control.close(resolve))]);
  } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 3) throw new Error('profile_listener_arguments');
  const stat = fs.lstatSync(process.argv[2]);
  if (!stat.isFile() || stat.uid !== process.getuid() || stat.mode & 0o077 || stat.size > 16384) {
    throw new Error('profile_listener_configuration_custody');
  }
  await startListener(JSON.parse(fs.readFileSync(process.argv[2])));
}
