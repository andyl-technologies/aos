// Retain one real provider response before losing its caller acknowledgement.
// This owner supplies transport facts, never a journal or permission verdict.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, realpath, stat } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { performance } from 'node:perf_hooks';

const MAX_BYTES = 64 * 1024;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

function closed(value, names) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== [...names].sort().join(',')) {
    throw new Error('staged loss fields differ');
  }
}

function xmlText(value) {
  if (/&(?!amp;|lt;|gt;|quot;|apos;)/.test(value)) throw new Error('unsupported XML entity');
  return value.replace(/&(amp|lt|gt|quot|apos);/g,
    (_, name) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" })[name]);
}

/** Checks a complete, bounded actual S3 result; HTTP status alone is insufficient. */
export function providerPositive(kind, status, bytes, expected) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_BYTES) throw new Error('provider reply bound differs');
  closed(expected, ['bucket', 'key', 'uploadId']);
  if (kind === 'abort') {
    if (status !== 204 || bytes.length !== 0 || !expected.uploadId) throw new Error('Abort is not positive');
    return { kind, uploadId: expected.uploadId };
  }
  if (!['create', 'source_complete', 'destination_complete'].includes(kind) || status !== 200) {
    throw new Error('provider response is not an admitted positive');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
  const root = kind === 'create' ? 'InitiateMultipartUploadResult' : 'CompleteMultipartUploadResult';
  const matched = text.match(new RegExp(`^(?:<\\?xml version="1\\.0"(?: encoding="UTF-8")?\\?>\\s*)?`
    + `<${root}(?: xmlns="http://s3.amazonaws.com/doc/2006-03-01/")?>([\\s\\S]*)</${root}>$`));
  if (!matched) throw new Error('closed provider XML differs');
  const fields = {};
  let remainder = matched[1];
  const field = /^\s*<(Bucket|Key|UploadId|Location|ETag)>([^<]*)<\/\1>/;
  while (remainder.trim()) {
    const item = remainder.match(field);
    if (!item || Object.hasOwn(fields, item[1])) throw new Error('provider result is ambiguous');
    fields[item[1]] = xmlText(item[2]);
    remainder = remainder.slice(item[0].length);
  }
  const names = kind === 'create' ? ['Bucket', 'Key', 'UploadId'] : ['Bucket', 'Key', 'Location', 'ETag'];
  if (Object.keys(fields).sort().join(',') !== names.sort().join(',')
      || fields.Bucket !== expected.bucket || fields.Key !== expected.key) {
    throw new Error('provider result selects another object');
  }
  if (kind === 'create') {
    if (!fields.UploadId || fields.UploadId.length > 4096 || /[\x00-\x1f\x7f]/.test(fields.UploadId)) {
      throw new Error('actual upload ID is absent or excessive');
    }
  } else if (!/^"[^"\x00-\x1f\x7f]{1,256}"$/.test(fields.ETag) || !expected.uploadId) {
    throw new Error('actual Complete identity is absent');
  }
  return { kind, ...fields };
}

async function privateRoot(root) {
  if (await realpath(root) !== root) throw new Error('loss root is not canonical');
  const info = await stat(root);
  if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o700) {
    throw new Error('loss root custody differs');
  }
}

async function retain(root, name, bytes) {
  if (bytes.length > MAX_BYTES) throw new Error('retained loss metadata exceeds bound');
  const file = `${root}/${name}`;
  const owner = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
    | constants.O_NOFOLLOW, 0o600);
  try {
    await owner.writeFile(bytes);
    await owner.sync();
  } finally {
    await owner.close();
  }
  return { file, sha256: sha(bytes), byteSize: String(bytes.length) };
}

async function originalBytes(reference) {
  closed(reference, ['file', 'sha256', 'byteSize']);
  if (!digest(reference.sha256) || typeof reference.byteSize !== 'string' || !/^[1-9][0-9]*$/.test(reference.byteSize)
      || Number(reference.byteSize) > MAX_BYTES || await realpath(reference.file) !== reference.file) {
    throw new Error('loss original reference differs');
  }
  const file = await open(reference.file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat();
    if (!before.isFile() || before.uid !== process.getuid() || (before.mode & 0o777) !== 0o600
        || before.nlink !== 1 || before.size > MAX_BYTES) throw new Error('loss original custody differs');
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let count = 0;
    while (count < buffer.length) {
      const { bytesRead } = await file.read(buffer, count, buffer.length - count, count);
      if (bytesRead === 0) break;
      count += bytesRead;
    }
    if (count > MAX_BYTES) throw new Error('loss original exceeds its retained bound');
    const bytes = buffer.subarray(0, count);
    const after = await file.stat();
    if (String(bytes.length) !== reference.byteSize || sha(bytes) !== reference.sha256
        || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) {
      throw new Error('loss original changed during read');
    }
    return bytes;
  } finally {
    await file.close();
  }
}

/** Retains bounded complete HTTP EOF only while the original cutoff is live. */
export async function readBoundedStagedStream(stream, remaining) {
  const chunks = [];
  let count = 0;
  const timer = setTimeout(() => stream.destroy(new Error('original loss deadline elapsed')), remaining());
  try {
    for await (const chunk of stream) {
      count += chunk.length;
      if (count > MAX_BYTES || remaining() <= 0) throw new Error('loss stream exceeds original bound');
      chunks.push(chunk);
    }
    if (!stream.complete || remaining() <= 0) {
      throw new Error('loss stream did not reach eligible complete HTTP EOF');
    }
    return Buffer.concat(chunks, count);
  } finally {
    clearTimeout(timer);
  }
}

/** Creates one selected mutation handler for an existing owned listener.
 *
 * The caller installs the fixed route before startup and supplies the exact
 * provider request emitted for its prepared original. This handler does not
 * start a server, admit a provider, sign a request, or retry an effect.
 */
export async function createStagedLoss(selection, root, upstreamPort) {
  closed(selection, ['version', 'kind', 'originalSha256', 'originalReference', 'method', 'target', 'host',
    'requestSha256', 'requestBytes', 'rawHeadersSha256', 'cutoffUnixMs', 'expected']);
  if (selection.version !== 1 || !['create', 'source_complete', 'destination_complete', 'abort'].includes(selection.kind)
      || ![selection.originalSha256, selection.requestSha256, selection.rawHeadersSha256].every(digest)
      || selection.method !== (selection.kind === 'abort' ? 'DELETE' : 'POST')
      || typeof selection.target !== 'string' || !selection.target.startsWith('/')
      || /[\x00-\x20\x7f#]/.test(selection.target) || selection.target.length > 16384
      || typeof selection.host !== 'string' || !/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/.test(selection.host)
      || selection.host.length > 255 || typeof selection.requestBytes !== 'string'
      || !/^(0|[1-9][0-9]*)$/.test(selection.requestBytes) || Number(selection.requestBytes) > MAX_BYTES
      || !Number.isSafeInteger(selection.cutoffUnixMs) || selection.cutoffUnixMs <= Date.now()
      || selection.cutoffUnixMs - Date.now() > 30000
      || !Number.isInteger(upstreamPort) || upstreamPort < 1024 || upstreamPort > 65535) {
    throw new Error('loss selection differs from its bounded original');
  }
  closed(selection.expected, ['bucket', 'key', 'uploadId']);
  const target = new URL(selection.target, 'http://localhost');
  if (selection.target.startsWith('//') || typeof selection.expected.bucket !== 'string'
      || typeof selection.expected.key !== 'string'
      || (selection.kind === 'create' ? selection.expected.uploadId !== null
        || target.searchParams.getAll('uploads').length !== 1 || target.searchParams.get('uploads') !== ''
        || target.searchParams.has('uploadId')
        : typeof selection.expected.uploadId !== 'string' || !selection.expected.uploadId
        || target.searchParams.getAll('uploadId').length !== 1
        || target.searchParams.get('uploadId') !== selection.expected.uploadId || target.searchParams.has('uploads'))) {
    throw new Error('provider mutation query differs from actual upload identity');
  }
  await privateRoot(root);
  const original = await originalBytes(selection.originalReference);
  if (sha(original) !== selection.originalSha256) throw new Error('loss selects another original');
  await retain(root, 'original.private.json', original);
  await retain(root, 'selection.private.json', Buffer.from(JSON.stringify(selection)));
  const selected = structuredClone(selection);
  const monotonicCutoff = performance.now() + selected.cutoffUnixMs - Date.now();
  const remaining = () => Math.max(0, Math.min(selected.cutoffUnixMs - Date.now(), monotonicCutoff - performance.now()));
  let used = false;

  return async function loseSelectedReply(request, response) {
    // A rejected selection never reaches the provider and consumes this arm.
    if (used) throw new Error('selected loss handler already consumed');
    used = true;
    let upstream;
    let upstreamReply;
    let headerTimer;
    let dropping = false;
    let primary;
    let evidence = { version: 1, originalSha256: selected.originalSha256,
      request: null, reply: null, headers: null, providerResult: null,
      upstreamEndInvocations: 0, providerDispatches: null, downstreamDestroyInvoked: false, outcome: 'unknown',
      journalPersistence: null, providerSettlement: null };
    const callerClosed = () => {
      if (!dropping) {
        const error = new Error('selected caller ended before positive loss');
        upstreamReply?.destroy(error);
        upstream?.destroy(error);
        request.destroy(error);
      }
    };
    response.on('close', callerClosed);
    try {
      if (remaining() <= 0 || request.method !== selected.method || request.url !== selected.target
          || request.headers.host !== selected.host
          || sha(Buffer.from(JSON.stringify(request.rawHeaders))) !== selected.rawHeadersSha256) {
        throw new Error('actual provider request differs from selected original');
      }
      const body = await readBoundedStagedStream(request, remaining);
      if (sha(body) !== selected.requestSha256 || String(body.length) !== selected.requestBytes) {
        throw new Error('actual provider request body differs');
      }
      evidence.request = await retain(root, 'request.private.bin', body);
      await retain(root, 'request-headers.private.json', Buffer.from(JSON.stringify(request.rawHeaders)));
      // Fsync may consume the remaining window even for an empty body. A zero
      // timeout schedules cancellation; it cannot substitute for this fence.
      if (remaining() <= 0) throw new Error('original expired before upstream dispatch');
      upstreamReply = await new Promise((resolve, reject) => {
        upstream = httpRequest({ hostname: '127.0.0.1', port: upstreamPort,
          method: request.method, path: request.url, headers: request.rawHeaders }, resolve);
        upstream.on('error', reject);
        headerTimer = setTimeout(() => upstream.destroy(new Error('original response deadline elapsed')), remaining());
        upstream.setTimeout(remaining(), () => upstream.destroy(new Error('provider original expired')));
        if (remaining() <= 0) {
          upstream.destroy();
          reject(new Error('original expired before upstream end'));
          return;
        }
        evidence.upstreamEndInvocations = 1;
        upstream.end(body);
      });
      clearTimeout(headerTimer);
      const reply = await readBoundedStagedStream(upstreamReply, remaining);
      evidence.reply = await retain(root, 'reply.private.bin', reply);
      evidence.headers = await retain(root, 'reply-headers.private.json', Buffer.from(JSON.stringify(upstreamReply.rawHeaders)));
      evidence.providerResult = providerPositive(selected.kind, upstreamReply.statusCode, reply, selected.expected);
      evidence.status = upstreamReply.statusCode;
      // Persist the actual success observation before losing its acknowledgement.
      await retain(root, 'positive.private.json', Buffer.from(JSON.stringify(evidence)));
      if (remaining() <= 0) throw new Error('positive arrived after original cutoff');
      dropping = true;
      response.destroy();
      evidence.downstreamDestroyInvoked = true;
      evidence.outcome = 'provider_positive_caller_reply_lost';
    } catch (error) {
      primary = error;
      throw error;
    } finally {
      clearTimeout(headerTimer);
      response.off('close', callerClosed);
      upstreamReply?.destroy();
      upstream?.destroy();
      if (!response.destroyed) response.destroy();
      try {
        await retain(root, 'terminal.private.json', Buffer.from(JSON.stringify(evidence)));
      } catch (error) {
        if (!primary) throw error;
        primary.addNote = 'loss evidence retention failed; outcome remains unknown';
      }
    }
    return evidence;
  };
}
