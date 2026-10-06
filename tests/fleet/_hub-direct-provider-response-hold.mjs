// Confined response ownership between the fleet TLS proxy and actual Garage.
// Calibration and holding do not verify caller authority or create S3 objects.
import { createHash } from 'node:crypto';
import { createServer, request as upstreamRequest } from 'node:http';
import { createServer as controlServer } from 'node:net';
import { constants, promises as fs } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BODY_BOUND = 65536;
const HEADER_BOUND = 16384;
const CONTROL_BOUND = 16384;
const HEX = /^[0-9a-f]{64}$/;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value));
const requireFact = (condition, message) => { if (!condition) throw new Error(message); };
const closed = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');

function parseClosedJson(bytes) {
  const text = bytes.toString('utf8');
  let position = 0;
  const whitespace = () => { while (/\s/.test(text[position] ?? '') && position < text.length) position++; };
  function string() {
    const start = position++;
    while (position < text.length) {
      if (text[position++] === '"') return JSON.parse(text.slice(start, position));
      if (text[position - 1] === '\\') position++;
    }
    throw new Error('unterminated JSON string');
  }
  function value(depth) {
    requireFact(depth < 16, 'control JSON nesting exceeds bound');
    whitespace();
    if (text[position] === '"') { string(); return; }
    if (text[position] === '{') {
      position++;
      whitespace();
      const names = new Set();
      if (text[position] === '}') { position++; return; }
      while (true) {
        whitespace();
        requireFact(text[position] === '"', 'JSON object key is not a string');
        const name = string();
        requireFact(!names.has(name), 'duplicate control field');
        names.add(name);
        whitespace();
        requireFact(text[position++] === ':', 'JSON key separator differs');
        value(depth + 1);
        whitespace();
        if (text[position++] === '}') return;
        requireFact(text[position - 1] === ',', 'JSON object separator differs');
      }
    }
    if (text[position] === '[') {
      position++;
      whitespace();
      if (text[position] === ']') { position++; return; }
      while (true) {
        value(depth + 1);
        whitespace();
        if (text[position++] === ']') return;
        requireFact(text[position - 1] === ',', 'JSON array separator differs');
      }
    }
    const primitive = text.slice(position).match(/^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/);
    requireFact(primitive, 'JSON value differs');
    position += primitive[0].length;
  }
  value(0);
  whitespace();
  requireFact(position === text.length, 'trailing control data');
  return JSON.parse(text);
}

function strongEtag(value) {
  return typeof value === 'string' && /^"[!\x23-\x7e]{1,256}"$/.test(value);
}

function header(headers, name) {
  const values = [];
  for (let index = 0; index < headers.length; index += 2) {
    if (headers[index].toLowerCase() === name) values.push(headers[index + 1]);
  }
  requireFact(values.length <= 1, `duplicate selected ${name} header`);
  return values[0] ?? null;
}

const SIGNING_QUERY_FIELDS = new Set(['X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date',
  'X-Amz-Expires', 'X-Amz-SignedHeaders', 'X-Amz-Signature', 'X-Amz-Security-Token']);

function objectTarget(raw) {
  requireFact(typeof raw === 'string' && raw.length <= 8192, 'signed target exceeds bound');
  const separator = raw.indexOf('?');
  if (separator < 0) return { target: raw, signing: new Map() };
  const path = raw.slice(0, separator);
  const retained = [];
  const signing = new Map();
  for (const item of raw.slice(separator + 1).split('&')) {
    const equals = item.indexOf('=');
    const rawName = equals < 0 ? item : item.slice(0, equals);
    const name = decodeURIComponent(rawName.replaceAll('+', ' '));
    if (!SIGNING_QUERY_FIELDS.has(name)) { retained.push(item); continue; }
    requireFact(name === rawName && equals >= 0 && !signing.has(name),
      'ambiguous or duplicate signing query');
    signing.set(name, decodeURIComponent(item.slice(equals + 1).replaceAll('+', ' ')));
  }
  return { target: path + (retained.length ? '?' + retained.join('&') : ''), signing };
}

function requestIdentity(request) {
  requireFact(request.method === 'GET', 'selected read is not GET');
  const host = header(request.rawHeaders, 'host');
  const etag = header(request.rawHeaders, 'if-match');
  const authorization = header(request.rawHeaders, 'authorization');
  const target = objectTarget(request.url);
  let signedHeaders;
  let credential;
  let signingMode;
  if (authorization !== null) {
    const signed = authorization.match(/^AWS4-HMAC-SHA256 Credential=([^ ,]+), SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$/);
    requireFact(signed && target.signing.size === 0
      && header(request.rawHeaders, 'x-amz-date') !== null
      && header(request.rawHeaders, 'x-amz-content-sha256') !== null,
    'selected header signature is missing or ambiguous');
    credential = signed[1];
    signedHeaders = signed[2].split(';');
    signingMode = 'headers';
  } else {
    const query = target.signing;
    requireFact(query.get('X-Amz-Algorithm') === 'AWS4-HMAC-SHA256'
      && /^[^ ,]{1,1024}$/.test(query.get('X-Amz-Credential') ?? '')
      && /^[0-9]{8}T[0-9]{6}Z$/.test(query.get('X-Amz-Date') ?? '')
      && /^(?:[1-9]|[12][0-9]|30)$/.test(query.get('X-Amz-Expires') ?? '')
      && /^[a-z0-9;-]+$/.test(query.get('X-Amz-SignedHeaders') ?? '')
      && HEX.test(query.get('X-Amz-Signature') ?? ''),
    'selected query signature differs from the actual bounded signer');
    credential = query.get('X-Amz-Credential');
    signedHeaders = query.get('X-Amz-SignedHeaders').split(';');
    signingMode = 'query';
  }
  requireFact(signedHeaders.includes('host') && signedHeaders.includes('if-match') && strongEtag(etag)
    && (header(request.rawHeaders, 'range') === null || signedHeaders.includes('range')),
  'selected original lacks signed strong If-Match');
  requireFact(header(request.rawHeaders, 'transfer-encoding') === null
    && [null, '0'].includes(header(request.rawHeaders, 'content-length')),
  'selected read framing or signing fields differ');
  return { method: 'GET', target: target.target, host, ifMatch: etag,
    range: header(request.rawHeaders, 'range'), signingMode, signingCredentialSha256: sha(credential) };
}

function validateSelection(value) {
  requireFact(closed(value, ['version', 'target', 'host', 'range']) && value.version === 1
    && typeof value.target === 'string' && value.target.startsWith('/')
    && !value.target.startsWith('//') && value.target.length <= 8192
    && !/[\x00-\x20\x7f#]/.test(value.target)
    && value.host === 's3.fleet.test'
    && (value.range === null || /^bytes=[0-9]+-[0-9]+$/.test(value.range)),
  'calibration selection differs from the confined fleet read');
  return { ...structuredClone(value), target: objectTarget(value.target).target };
}

function validateFirstSelection(value) {
  requireFact(closed(value, ['version', 'targetPrefix', 'host']) && value.version === 1
    && typeof value.targetPrefix === 'string' && value.targetPrefix.startsWith('/')
    && !value.targetPrefix.startsWith('//') && value.targetPrefix.endsWith('/')
    && value.targetPrefix.length <= 2048 && !/[\x00-\x20\x7f?#%]/.test(value.targetPrefix)
    && /^\/[A-Za-z0-9._/-]+\/$/.test(value.targetPrefix)
    && !value.targetPrefix.split('/').some(part => part === '.' || part === '..')
    && value.targetPrefix.split('/').includes('.aos-direct-qualification')
    && value.targetPrefix.endsWith('/.aos-direct-upload/')
    && value.host === 's3.fleet.test', 'first-response prefix selection differs');
  return structuredClone(value);
}

async function retain(root, name, bytes) {
  const path = `${root}/${name}`;
  const file = await fs.open(path, constants.O_WRONLY | constants.O_CREAT
    | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  return { path, sha256: sha(bytes), byteSize: String(bytes.length) };
}

async function privateRoot(root) {
  requireFact(root === resolve(root), 'response hold root is not absolute');
  const metadata = await fs.lstat(root);
  requireFact(metadata.isDirectory() && metadata.uid === process.getuid()
    && (metadata.mode & 0o777) === 0o700 && await fs.realpath(root) === root,
  'response hold root custody differs');
}

async function hashExecutable(path) {
  const file = await fs.open(path, constants.O_RDONLY);
  const digest = createHash('sha256');
  const block = Buffer.alloc(65536);
  let size = 0;
  try {
    while (true) {
      const { bytesRead } = await file.read(block, 0, block.length, null);
      if (bytesRead === 0) return digest.digest('hex');
      size += bytesRead;
      requireFact(size <= 512 * 1024 * 1024, 'listener executable exceeds custody bound');
      digest.update(block.subarray(0, bytesRead));
    }
  } finally { await file.close(); }
}

function listen(server, ...arguments_) {
  return new Promise((resolve_, reject) => {
    server.once('error', reject);
    server.listen(...arguments_, () => { server.off('error', reject); resolve_(); });
  });
}

/** Creates a bounded response owner; explicit ports are used only by local tests. */
export async function createResponseHold(root, ports = { listen: 3902, upstream: 3900 }, configurationSha256 = null) {
  await privateRoot(root);
  let selected = null;
  let calibrated = null;
  let arm = null;
  let calibrating = false;
  let attempted = false;
  let usedCalibration = false;
  let usedArm = false;
  let firstResponse = null;
  let candidates = 0;
  let events = 0;
  let observationsComplete = true;
  const sockets = new Set();
  const pending = new Set();

  // Queue rendezvous owns a separate one-shot selection. It must not consume
  // the later small-body calibration or verification-timeout selection.
  let queuePause = null;

  function endQueuePause(reason) {
    if (!queuePause || ['released', 'cutoff', 'disconnected', 'refused'].includes(queuePause.state)) return;
    queuePause.state = reason;
    queuePause.endedAtUnixMillis = Date.now();
    queuePause.cancel?.();
  }

  async function pauseQueueRead(response, reply, identity) {
    const selection = queuePause;
    selection.state = 'receiving_prefix';
    selection.cancel = () => { reply.destroy(); response.destroy(); };
    const disconnected = () => endQueuePause('disconnected');
    response.once('close', disconnected);
    reply.once('error', disconnected);
    reply.once('aborted', disconnected);
    try {
      requireFact(reply.statusCode === 200
        && header(reply.rawHeaders, 'etag') === identity.ifMatch
        && header(reply.rawHeaders, 'content-length') === selection.arm.expectedSourceBytes
        && header(reply.rawHeaders, 'transfer-encoding') === null,
      'queue response incarnation or full length differs');

      // Read only the prefix while the upstream remains paused. Node applies
      // socket backpressure; the application never accumulates the full object.
      const blocks = [];
      let size = 0;
      await new Promise((resolve_, reject) => {
        const cleanup = () => {
          reply.off('readable', readable);
          reply.off('end', ended);
          reply.off('error', reject_);
          reply.off('close', ended);
        };
        const reject_ = error => { cleanup(); reject(error); };
        const ended = () => reject_(new Error('queue read ended before bounded prefix selection'));
        const readable = () => {
          while (size < BODY_BOUND) {
            const block = reply.read(BODY_BOUND - size);
            if (block === null) break;
            blocks.push(block);
            size += block.length;
          }
          if (size === BODY_BOUND) { cleanup(); resolve_(); }
        };
        reply.on('readable', readable);
        reply.once('end', ended);
        reply.once('close', ended);
        reply.once('error', reject_);
        readable();
      });
      const prefix = Buffer.concat(blocks);
      requireFact(selection.state === 'receiving_prefix' && !reply.readableEnded
        && !reply.complete
        && sha(prefix) === selection.arm.expectedPrefixSha256,
      'queue source prefix differs or response already completed');
      const prefixFile = await retain(root, 'queue-prefix.private', prefix);
      selection.receipt = { version: 1, identity,
        owner: { pid: ready.pid, startTicks: ready.startTicks, ownerUid: ready.ownerUid,
          configurationSha256: ready.configurationSha256, listenerSourceSha256: ready.listenerSourceSha256,
          listenAddress: ready.listenAddress, upstreamAddress: ready.upstreamAddress },
        selectionContextSha256: selection.arm.selectionContextSha256,
        sourceSha256: selection.arm.expectedSourceSha256,
        sourceBytes: selection.arm.expectedSourceBytes, prefixFile,
        selectedAtUnixMillis: selection.selectedAtUnixMillis,
        heldAtUnixMillis: Date.now(), cutoffUnixMillis: selection.selectedAtUnixMillis + selection.arm.pauseMillis,
        upstreamComplete: false, downstreamOfferedBytes: '0', remoteDrain: null };
      selection.receiptFile = await retain(root, 'queue-held.json', encode(selection.receipt));
      requireFact(selection.state === 'receiving_prefix', 'queue pause ended during retention');
      selection.state = 'held';
      await new Promise(resolve_ => {
        if (response.destroyed) return resolve_();
        response.once('close', resolve_);
      });
    } catch {
      endQueuePause('refused');
      reply.destroy();
      response.destroy();
    } finally {
      response.off('close', disconnected);
      reply.off('error', disconnected);
      reply.off('aborted', disconnected);
      selection.cancel = null;
    }
  }

  async function event(kind, facts = {}) {
    if (events >= 32) {
      if (observationsComplete) {
        observationsComplete = false;
        await retain(root, 'observation-incomplete.json', encode({ version: 1, reason: 'event_bound_exceeded' }));
      }
      return;
    }
    const row = { version: 1, kind, sequence: events++, unixMillis: String(Date.now()), ...facts };
    await retain(root, `event-${String(row.sequence).padStart(3, '0')}.json`, encode(row));
  }

  function matches(request, selection) {
    return selection && request.method === 'GET' && objectTarget(request.url).target === selection.target
      && header(request.rawHeaders, 'host') === selection.host
      && header(request.rawHeaders, 'range') === selection.range;
  }

  async function holdResponse(response, receiptFile, selectionFacts) {
    let fixtureClosed = false;
    const alreadyClosed = response.closed || response.destroyed;
    let closeCause = alreadyClosed ? 'downstream' : null;
    let timer = null;
    let observedClose;
    let closeListener;
    const closeObserved = new Promise(resolve_ => {
      observedClose = resolve_;
      closeListener = () => {
        closeCause = fixtureClosed ? 'fixture_ceiling' : 'downstream';
        if (timer) clearTimeout(timer);
        resolve_();
      };
      // Subscribe before persistence: a visible held-event file does not mean
      // its fsync has finished, and the peer can close during that await.
      if (alreadyClosed) resolve_();
      else response.once('close', closeListener);
    });
    timer = alreadyClosed ? null : setTimeout(() => {
      fixtureClosed = true;
      closeCause = 'fixture_ceiling';
      event('hold_deadline_reached', { downstreamOfferedBytes: '0', remoteDrain: null })
        .finally(() => { response.destroy(); observedClose(); });
    }, Math.max(1, arm.holdUntilUnixMillis - Date.now()));
    try {
      await event('response_held', { receiptFile, ...selectionFacts,
        holdUntilUnixMillis: String(arm.holdUntilUnixMillis), downstreamOfferedBytes: '0',
        downstreamClosedBeforeHeld: alreadyClosed, remoteDrain: null });
      // This deadline is a fixture ceiling. The actual original's earlier
      // cutoff and signed terminal remain independent caller evidence.
      await closeObserved;
      await event('downstream_closed', { downstreamOfferedBytes: '0', remoteDrain: null,
        closeCause });
    } finally {
      if (timer) clearTimeout(timer);
      response.off('close', closeListener);
    }
  }

  async function firstSelectedResponse(response, upstream, identity, requestFile, candidate) {
    const etag = header(upstream.rawHeaders, 'etag');
    const versionId = header(upstream.rawHeaders, 'x-amz-version-id');
    const length = header(upstream.rawHeaders, 'content-length');
    const eligible = upstream.statusCode === 200 && strongEtag(etag) && etag === identity.ifMatch
      && length === arm.expectedSourceBodyBytes
      && (versionId === null || (versionId.length <= 1024 && !/[\x00-\x20\x7f]/.test(versionId)));
    if (!eligible) {
      await event('first_response_not_selected', { candidate, reason: 'status_incarnation_or_size', requestFile });
      response.writeHead(upstream.statusCode, upstream.rawHeaders);
      await new Promise((resolve_, reject) => {
        upstream.once('error', reject);
        upstream.once('end', resolve_);
        upstream.pipe(response);
      });
      return;
    }

    const blocks = [];
    let size = 0;
    for await (const block of upstream) {
      size += block.length;
      requireFact(size <= BODY_BOUND, 'selected upstream body exceeds 64 KiB');
      blocks.push(block);
    }
    requireFact(upstream.complete && String(size) === length, 'first actual response is incomplete');
    const bytes = Buffer.concat(blocks, size);
    const bodyFile = await retain(root, `first-${candidate}-upstream-body.private`, bytes);
    const headersFile = await retain(root, `first-${candidate}-upstream-headers.private`, encode(upstream.rawHeaders));
    const facts = { status: upstream.statusCode, etag, versionId, byteSize: String(size), sha256: sha(bytes),
      contentRange: header(upstream.rawHeaders, 'content-range') };
    const receipt = { version: 1, scope: 'actual_garage_response_observation', identity, response: facts,
      requestFile, headersFile, bodyFile, upstreamComplete: true,
      authenticationScope: 'actual upstream response; caller must independently join original and Garage authorization' };
    const receiptFile = await retain(root, `first-${candidate}-receipt.private.json`, encode(receipt));
    await event('first_upstream_complete', { candidate, receiptFile });
    if (facts.sha256 !== arm.expectedSourceBodySha256 || attempted || Date.now() >= arm.holdUntilUnixMillis) {
      response.writeHead(upstream.statusCode, upstream.rawHeaders);
      response.end(bytes);
      await event('first_response_not_selected', { candidate, receiptFile, reason: 'source_or_fixture_ceiling',
        offeredBodyBytes: String(size) });
      return;
    }

    attempted = true;
    firstResponse = receiptFile;
    await holdResponse(response, receiptFile, { selectionContextSha256: arm.selectionContextSha256,
      expectedSourceBodySha256: arm.expectedSourceBodySha256, expectedSourceBodyBytes: arm.expectedSourceBodyBytes });
  }

  async function selectedResponse(request, response, upstream, kind, identity, requestFile) {
    requireFact(Buffer.byteLength(JSON.stringify(upstream.rawHeaders)) <= HEADER_BOUND,
      'actual upstream headers exceed the selected bound');
    const etag = header(upstream.rawHeaders, 'etag');
    const versionId = header(upstream.rawHeaders, 'x-amz-version-id');
    requireFact([200, 206].includes(upstream.statusCode) && strongEtag(etag)
      && etag === identity.ifMatch
      && (versionId === null || (versionId.length <= 1024 && !/[\x00-\x20\x7f]/.test(versionId))),
    'actual Garage status or incarnation differs');
    const blocks = [];
    let size = 0;
    for await (const block of upstream) {
      size += block.length;
      requireFact(size <= BODY_BOUND, 'selected upstream body exceeds 64 KiB');
      blocks.push(block);
    }
    requireFact(upstream.complete, 'selected upstream response is incomplete');
    requireFact(size > 0, 'selected calibration body is empty');
    const bytes = Buffer.concat(blocks, size);
    const length = header(upstream.rawHeaders, 'content-length');
    requireFact(length === null || (/^(0|[1-9][0-9]*)$/.test(length) && BigInt(length) === BigInt(size)),
      'actual upstream body framing differs');
    const bodyFile = await retain(root, `${kind}-upstream-body.private`, bytes);
    const headersFile = await retain(root, `${kind}-upstream-headers.private`, encode(upstream.rawHeaders));
    const facts = { status: upstream.statusCode, etag, versionId, byteSize: String(size), sha256: sha(bytes),
      contentRange: header(upstream.rawHeaders, 'content-range') };
    const receipt = { version: 1, scope: 'actual_garage_response_observation', identity, response: facts,
      requestFile, headersFile, bodyFile, upstreamComplete: true,
      authenticationScope: 'forwarded actual signed request; caller must independently join Garage authorization and source facts' };
    const receiptFile = await retain(root, `${kind}-receipt.private.json`, encode(receipt));
    await event(`${kind}_upstream_complete`, { receiptFile, downstreamOfferedBytes: '0' });
    if (kind === 'calibration') {
      calibrated = { receipt, receiptFile };
      calibrating = false;
      response.writeHead(upstream.statusCode, upstream.rawHeaders);
      response.end(bytes);
      await event('calibration_forwarded', { offeredBodyBytes: String(size) });
      return;
    }
    requireFact(JSON.stringify(facts) === JSON.stringify(calibrated.receipt.response)
      && JSON.stringify(identity) === JSON.stringify(calibrated.receipt.identity),
    'held current incarnation or response bytes differ from actual calibration');
    requireFact(Date.now() < arm.holdUntilUnixMillis, 'fixture hold ceiling passed before real response completion');
    await holdResponse(response, receiptFile, { calibrationSha256: arm.calibrationSha256,
      calibrationContextSha256: arm.calibrationContextSha256 });
  }

  function handle(request, response) {
    const task = (async () => {
      let kind = null;
      let identity = null;
      let requestFile = null;
      let candidate = null;
      try {
        const firstMode = arm?.kind === 'arm_first_response';
        let firstSelected = false;
        if (firstMode && !attempted && !calibrating && observationsComplete && candidates < 8
          && Date.now() < arm.holdUntilUnixMillis && request.method === 'GET') {
          try {
            firstSelected = objectTarget(request.url).target.startsWith(selected.targetPrefix)
              && header(request.rawHeaders, 'host') === selected.host
              && header(request.rawHeaders, 'range') === null;
          } catch {
            firstSelected = false;
          }
        }
        let queueSelected = false;
        if (queuePause?.state === 'armed' && Date.now() < queuePause.arm.selectionDeadlineUnixMillis
          && request.method === 'GET') {
          try {
            queueSelected = objectTarget(request.url).target.startsWith(queuePause.arm.selection.targetPrefix)
              && header(request.rawHeaders, 'host') === queuePause.arm.selection.host
              && header(request.rawHeaders, 'range') === null;
          } catch {
            queueSelected = false;
          }
        }
        if (queueSelected) {
          kind = 'queue';
          // Reserve before opening the upstream; no second GET can become
          // another selected delivery while the prefix is read.
          queuePause.state = 'selected';
          queuePause.selectedAtUnixMillis = Date.now();
          requireFact(Buffer.byteLength(JSON.stringify(request.rawHeaders)) <= HEADER_BOUND,
            'queue request headers exceed bound');
          identity = requestIdentity(request);
        } else if (firstSelected) {
          // A prefix is only an observation selector. An invalid signing form
          // passes through without becoming a held candidate.
          try {
            requireFact(Buffer.byteLength(JSON.stringify(request.rawHeaders)) <= HEADER_BOUND,
              'selected original headers exceed bound');
            identity = requestIdentity(request);
          } catch {
            identity = null;
          }
          if (identity) {
            kind = 'first';
            candidate = candidates++;
            calibrating = true;
            requestFile = await retain(root, `first-${candidate}-request.private.json`, encode({
              method: request.method, target: request.url, rawHeaders: request.rawHeaders }));
            await event('first_request_received', { candidate, requestFile });
          }
        } else if (!firstMode && matches(request, selected)) {
          kind = arm ? 'hold' : 'calibration';
          requireFact(!calibrating && !attempted, 'selected calibration/read was replayed');
          requireFact(kind !== 'calibration' || !calibrated, 'calibration read was replayed');
          if (arm) {
            attempted = true;
            requireFact(Date.now() < arm.holdUntilUnixMillis, 'selected fixture hold ceiling expired');
          } else calibrating = true;
          requireFact(Buffer.byteLength(JSON.stringify(request.rawHeaders)) <= HEADER_BOUND,
            'selected original headers exceed bound');
          identity = requestIdentity(request);
          requestFile = await retain(root, `${kind}-request.private.json`, encode({
            method: request.method, target: request.url, rawHeaders: request.rawHeaders }));
          if (arm) requireFact(JSON.stringify(identity) === JSON.stringify(calibrated.receipt.identity),
            'fresh signed request differs from calibrated selection');
          await event(`${kind}_request_received`, { requestFile });
        }
        const upstream = upstreamRequest({ hostname: '127.0.0.1', port: ports.upstream,
          method: request.method, path: request.url, headers: request.rawHeaders,
          setHost: false, maxHeaderSize: HEADER_BOUND, agent: false });
        const cutoff = kind === 'queue' ? setTimeout(() => endQueuePause('cutoff'),
          Math.max(1, queuePause.selectedAtUnixMillis + queuePause.arm.pauseMillis - Date.now()))
          : kind && kind !== 'first' ? setTimeout(() => upstream.destroy(new Error('selected upstream deadline expired')),
            Math.max(1, (arm?.holdUntilUnixMillis ?? Date.now() + 30000) - Date.now())) : null;
        if (kind === 'queue') queuePause.cancel = () => { upstream.destroy(); response.destroy(); };
        upstream.once('error', error => response.destroy(error));
        response.once('close', () => upstream.destroy());
        try {
          await new Promise((resolve_, reject) => {
          upstream.once('error', reject);
          upstream.once('response', reply => {
            reply.once('end', () => { if (cutoff) clearTimeout(cutoff); });
            if (kind === 'queue') {
              pauseQueueRead(response, reply, identity).then(resolve_, reject);
            } else if (kind === 'first') {
              firstSelectedResponse(response, reply, identity, requestFile, candidate)
                .then(resolve_, error => { reply.destroy(); reject(error); });
            } else if (kind) {
              selectedResponse(request, response, reply, kind, identity, requestFile)
                .then(resolve_, error => { reply.destroy(); reject(error); });
            } else {
              response.writeHead(reply.statusCode, reply.rawHeaders);
              reply.once('error', reject);
              reply.once('end', resolve_);
              reply.pipe(response);
            }
          });
          request.once('aborted', () => upstream.destroy());
          request.pipe(upstream);
          });
        } finally {
          if (cutoff) clearTimeout(cutoff);
        }
      } catch (error) {
        if (kind === 'queue') endQueuePause('refused');
        else if (kind) await event('selected_refused', { phase: kind, reason: error.message,
          downstreamOfferedBytes: '0', remoteDrain: null });
        response.destroy();
      } finally {
        if (kind === 'calibration' || kind === 'first') calibrating = false;
      }
    })();
    pending.add(task);
    task.finally(() => pending.delete(task));
  }

  async function command(value) {
    if (closed(value, ['version', 'kind']) && value.version === 1 && value.kind === 'queue_state') {
      if (queuePause?.state === 'armed' && Date.now() >= queuePause.arm.selectionDeadlineUnixMillis) {
        endQueuePause('cutoff');
      }
      return { version: 1, state: queuePause?.state ?? 'absent',
        receipt: queuePause?.receipt ?? null, receiptFile: queuePause?.receiptFile ?? null,
        endedAtUnixMillis: queuePause?.endedAtUnixMillis ?? null };
    }
    if (closed(value, ['version', 'kind']) && value.version === 1 && value.kind === 'queue_release') {
      endQueuePause('released');
      return { version: 1, status: 'released' };
    }
    if (value?.kind === 'arm_queue_read') {
      requireFact(closed(value, ['version', 'kind', 'selection', 'expectedSourceSha256',
        'expectedSourceBytes', 'expectedPrefixSha256', 'selectionContextSha256',
        'selectionDeadlineUnixMillis', 'pauseMillis']) && value.version === 1 && queuePause === null
        && HEX.test(value.expectedSourceSha256) && HEX.test(value.expectedPrefixSha256)
        && HEX.test(value.selectionContextSha256)
        && typeof value.expectedSourceBytes === 'string' && /^[1-9][0-9]{0,9}$/.test(value.expectedSourceBytes)
        && Number(value.expectedSourceBytes) > BODY_BOUND && Number(value.expectedSourceBytes) <= 2147483648
        && Number.isSafeInteger(value.selectionDeadlineUnixMillis)
        && value.selectionDeadlineUnixMillis > Date.now()
        && value.selectionDeadlineUnixMillis - Date.now() <= 1200000
        && Number.isSafeInteger(value.pauseMillis) && value.pauseMillis > 0 && value.pauseMillis <= 35000,
      'queue read arm differs from bounded source selection');
      validateFirstSelection(value.selection);
      requireFact(value.selection.targetPrefix.split('/').slice(1, -1).every(Boolean),
        'queue prefix contains an empty component');
      queuePause = { arm: structuredClone(value), state: 'armed', receipt: null, receiptFile: null };
      return { version: 1, status: 'armed' };
    }
    if (closed(value, ['version', 'kind']) && value.version === 1 && value.kind === 'state') {
      return { version: 1, calibrated: calibrated?.receiptFile ?? null, firstResponse,
        armed: arm !== null, attempted, observationsComplete, scope: 'observation_only_no_authorization' };
    }
    if (value?.kind === 'arm_first_response') {
      requireFact(closed(value, ['version', 'kind', 'selection', 'expectedSourceBodySha256',
        'expectedSourceBodyBytes', 'selectionContextSha256', 'holdUntilUnixMillis']) && value.version === 1
        && observationsComplete && !usedCalibration && !usedArm
        && HEX.test(value.expectedSourceBodySha256) && HEX.test(value.selectionContextSha256)
        && typeof value.expectedSourceBodyBytes === 'string' && /^[1-9][0-9]{0,4}$/.test(value.expectedSourceBodyBytes)
        && Number(value.expectedSourceBodyBytes) <= BODY_BOUND
        && Number.isSafeInteger(value.holdUntilUnixMillis) && value.holdUntilUnixMillis > Date.now()
        && value.holdUntilUnixMillis - Date.now() <= 35000, 'first-response arm differs');
      selected = validateFirstSelection(value.selection);
      arm = structuredClone(value);
      usedArm = true;
      await event('first_response_armed', { arm });
      return { version: 1, status: 'armed' };
    }
    if (closed(value, ['version', 'kind', 'selection']) && value.version === 1 && value.kind === 'calibrate') {
      requireFact(!usedCalibration && !arm, 'calibration selection already used');
      selected = validateSelection(value.selection);
      usedCalibration = true;
      await event('calibration_selected', { selection: selected });
      return { version: 1, status: 'selected' };
    }
    requireFact(closed(value, ['version', 'kind', 'calibrationSha256', 'expectedSourceBodySha256',
      'calibrationContextSha256', 'holdUntilUnixMillis']) && value.version === 1 && value.kind === 'arm',
    'unsupported response hold control');
    requireFact(observationsComplete && !usedArm && calibrated && !calibrating && HEX.test(value.calibrationContextSha256)
      && value.calibrationSha256 === calibrated.receiptFile.sha256
      && value.expectedSourceBodySha256 === calibrated.receipt.response.sha256
      && Number.isSafeInteger(value.holdUntilUnixMillis) && value.holdUntilUnixMillis > Date.now()
      && value.holdUntilUnixMillis - Date.now() <= 35000, 'arm differs from actual calibration/source/fixture ceiling');
    arm = structuredClone(value);
    usedArm = true;
    await event('armed', { arm });
    return { version: 1, status: 'armed' };
  }

  const server = createServer({ maxHeaderSize: HEADER_BOUND }, handle);
  server.requestTimeout = 35000;
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  const control = controlServer({ allowHalfOpen: true }, socket => {
    const chunks = [];
    let size = 0;
    socket.setTimeout(2000, () => socket.destroy());
    socket.on('data', block => { size += block.length; if (size > CONTROL_BOUND) socket.destroy(); else chunks.push(block); });
    socket.on('end', () => {
      if (size > CONTROL_BOUND) return;
      Promise.resolve().then(() => command(parseClosedJson(Buffer.concat(chunks))))
        .then(value => socket.end(encode(value)), () => socket.end(encode({ version: 1, status: 'refused' })));
    });
    socket.on('error', () => {});
  });
  await listen(server, ports.listen, '127.0.0.1');
  await listen(control, `${root}/control.sock`);
  await fs.chmod(`${root}/control.sock`, 0o600);
  const processStat = (await fs.readFile('/proc/self/stat', 'utf8')).split(') ').at(-1).trim().split(/\s+/);
  const commandLine = await retain(root, 'command-line.private', await fs.readFile('/proc/self/cmdline'));
  const environment = await retain(root, 'environment.private', await fs.readFile('/proc/self/environ'));
  const ready = { version: 1, scope: 'garage_response_hold_listener', pid: process.pid,
    startTicks: processStat[19], ownerUid: process.getuid(), configurationSha256,
    executableSha256: await hashExecutable('/proc/self/exe'), commandLine, environment,
    listenAddress: `127.0.0.1:${server.address().port}`, upstreamAddress: `127.0.0.1:${ports.upstream}`,
    listenerSourceSha256: sha(await fs.readFile(fileURLToPath(import.meta.url))),
    controlSocket: `${root}/control.sock`, bodyBound: String(BODY_BOUND) };
  await retain(root, 'ready.json', encode(ready));
  return { command, ready, close: async () => {
    for (const socket of sockets) socket.destroy();
    await Promise.allSettled([...pending]);
    await Promise.all([new Promise(resolve_ => server.close(resolve_)), new Promise(resolve_ => control.close(resolve_))]);
  } };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  requireFact(process.argv.length === 4 && process.argv[2] === '--config', 'use --config privateConfigPath');
  const configPath = resolve(process.argv[3]);
  const file = await fs.open(configPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let config;
  let configurationBytes;
  try {
    const metadata = await file.stat();
    requireFact(metadata.isFile() && metadata.uid === process.getuid() && metadata.nlink === 1
      && (metadata.mode & 0o777) === 0o600 && metadata.size <= CONTROL_BOUND, 'configuration custody differs');
    configurationBytes = await file.readFile();
    const after = await file.stat();
    requireFact(metadata.size === after.size && metadata.mtimeMs === after.mtimeMs
      && metadata.ctimeMs === after.ctimeMs && configurationBytes.length === metadata.size,
    'configuration changed during observation');
    config = parseClosedJson(configurationBytes);
  } finally { await file.close(); }
  requireFact(closed(config, ['version', 'root']) && config.version === 1
    && typeof config.root === 'string' && dirname(config.root) !== config.root, 'configuration shape differs');
  const listener = await createResponseHold(config.root, undefined, sha(configurationBytes));
  for (const name of ['SIGTERM', 'SIGINT']) process.once(name, () => listener.close().then(() => process.exit(0)));
}
