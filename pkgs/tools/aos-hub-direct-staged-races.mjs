// Production Direct controls and exact original signed-part closure observations.
// This fixture does not establish independent provider start, drain or settlement.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { pathToFileURL } from 'node:url';
import vm from 'node:vm';

export const PART_BYTES = 8 * 1024 * 1024;
const CONTROL_PATH = '/aos.hub.v1.DirectUploadService/';
const DIGEST = /^[0-9a-f]{64}$/;
const PLACEMENT_FIELDS = ['placementId', 'placementFingerprint', 'placementResourceVersion',
  'writeSpecVersion', 'bindingId', 'bindingResourceVersion', 'bindingWriteRevision',
  'profileFingerprint', 'privatePolicyDigest', 'checksumAlgorithm'];

export function record(value, fields) {
  assert(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...fields].sort());
  return Object.fromEntries(fields.map(field => [field, value[field]]));
}

export function sha(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function identity(runId, scope, phase) {
  return sha(Buffer.from(JSON.stringify([runId, scope, phase])));
}

function integer(value, positive = false) {
  assert.equal(typeof value, 'string');
  assert(/^(0|[1-9][0-9]*)$/.test(value));
  const parsed = BigInt(value);
  assert(parsed <= 0x7fffffffffffffffn && (!positive || parsed > 0n));
  return parsed;
}

function strongEtag(value) {
  assert.equal(typeof value, 'string');
  assert(/^"[^"\\<>&\x00-\x1f\x7f]+"$/.test(value));
  return value;
}

function u32(value) {
  assert(Number.isInteger(value) && value >= 0 && value <= 0xffffffff);
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function u64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(integer(value));
  return bytes;
}

function text(value) {
  assert.equal(typeof value, 'string');
  const bytes = Buffer.from(value);
  return Buffer.concat([u32(bytes.length), bytes]);
}

function placementBytes(value) {
  const placement = record(value, PLACEMENT_FIELDS);
  const counters = ['placementId', 'placementResourceVersion', 'writeSpecVersion',
    'bindingId', 'bindingResourceVersion', 'bindingWriteRevision'];
  const digests = ['placementFingerprint', 'profileFingerprint', 'privatePolicyDigest'];
  for (const key of counters) integer(placement[key], true);
  for (const key of digests) assert(DIGEST.test(placement[key]));
  assert(['md5', 'sha256'].includes(placement.checksumAlgorithm));
  return Buffer.concat([...counters.map(key => u64(placement[key])),
    ...digests.map(key => text(placement[key])),
    Buffer.from([placement.checksumAlgorithm === 'md5' ? 1 : 2])]);
}

const PROFILE_FIELDS = [...PLACEMENT_FIELDS.filter(field => field !== 'placementFingerprint'), 'providerOrigin'];

function opaqueIdentity(value) {
  assert(typeof value === 'string' && Buffer.byteLength(value) > 0 && Buffer.byteLength(value) <= 255);
  assert(value.trim() === value && !/[\x00-\x1f\x7f-\x9f]/u.test(value));
  return value;
}

function uploadTarget(value) {
  // Preserve exact values in the production DTO declaration order so the
  // independently selected Core codec can round-trip the retained Begin body.
  if (value.kind === 'publication_object') return record(value, ['kind', 'publicationId', 'surfaceObjectId', 'path']);
  if (value.kind === 'cache_object') return record(value, ['kind', 'cacheId', 'path']);
  const target = record(value, ['kind', 'uploadId']);
  assert.equal(target.kind, 'oci_blob');
  return target;
}

function capabilitiesTarget(target) {
  if (target.kind === 'publication_object') {
    record(target, ['kind', 'publicationId', 'surfaceObjectId', 'path']);
    opaqueIdentity(target.publicationId);
    integer(target.surfaceObjectId, true);
    return { kind: 'publication', publicationId: target.publicationId };
  }
  record(target, ['kind', 'cacheId', 'path']);
  assert.equal(target.kind, 'cache_object');
  opaqueIdentity(target.cacheId);
  return { kind: 'cache', cacheId: target.cacheId };
}

export function checkedCapabilities(value, targets, providerOrigin, nowUnixMs) {
  const capabilities = record(value, ['target', 'deploymentId', 'principalId', 'version', 'capability',
    'transferMode', 'configGeneration', 'validUntil', 'maximumControlBytes', 'maximumBatchItems',
    'maximumBatchParts', 'minimumObjectBytes', 'maximumObjectBytes', 'minimumPartBytes', 'maximumPartBytes', 'profiles']);
  assert.equal(capabilities.version, 1);
  assert.equal(capabilities.capability, 'aos.direct.multipart.v1');
  assert.equal(capabilities.transferMode, 'direct_required');
  opaqueIdentity(capabilities.deploymentId);
  assert(DIGEST.test(capabilities.principalId));
  integer(capabilities.configGeneration, true);
  integer(capabilities.validUntil, true);
  if (nowUnixMs !== null) assert(BigInt(Math.floor(nowUnixMs / 1000)) < BigInt(capabilities.validUntil));
  for (const [field, maximum] of [['maximumControlBytes', 256 * 1024], ['maximumBatchItems', 64], ['maximumBatchParts', 64]]) {
    assert(Number.isInteger(capabilities[field]) && capabilities[field] > 0 && capabilities[field] <= maximum);
  }
  const minimumObject = integer(capabilities.minimumObjectBytes);
  const maximumObject = integer(capabilities.maximumObjectBytes, true);
  const minimumPart = integer(capabilities.minimumPartBytes, true);
  const maximumPart = integer(capabilities.maximumPartBytes, true);
  assert(minimumObject <= BigInt(PART_BYTES) && BigInt(PART_BYTES) <= maximumObject && maximumObject <= 16n * 1024n ** 3n);
  assert(minimumPart >= 5n * 1024n ** 2n && minimumPart <= BigInt(PART_BYTES)
    && BigInt(PART_BYTES) <= maximumPart && maximumPart <= 64n * 1024n ** 2n);
  assert(Array.isArray(capabilities.profiles) && capabilities.profiles.length === 1);
  const profile = record(capabilities.profiles[0], PROFILE_FIELDS);
  assert.equal(profile.providerOrigin, providerOrigin);
  const url = new URL(profile.providerOrigin);
  assert(url.protocol === 'https:' && !url.username && !url.password && url.pathname === '/'
    && !url.search && !url.hash && url.origin === profile.providerOrigin);
  for (const field of ['placementId', 'placementResourceVersion', 'writeSpecVersion',
    'bindingId', 'bindingResourceVersion', 'bindingWriteRevision']) integer(profile[field], true);
  assert(DIGEST.test(profile.profileFingerprint) && DIGEST.test(profile.privatePolicyDigest));
  assert(['md5', 'sha256'].includes(profile.checksumAlgorithm));
  for (const selected of Object.values(targets)) {
    record(selected, ['target', 'finalReadUrl']);
    assert.deepEqual(capabilities.target, capabilitiesTarget(selected.target));
  }
  return capabilities;
}

export function capabilityPlacement(placement, capabilities) {
  placementBytes(placement);
  const profile = capabilities.profiles[0];
  for (const field of PLACEMENT_FIELDS.filter(field => field !== 'placementFingerprint')) {
    assert.deepEqual(placement[field], profile[field]);
  }
  return record(placement, PLACEMENT_FIELDS);
}

// Exact binary projection in Proto direct_upload/validation.rs. Its independent
// production golden vector is checked in the companion test, not derived here.
export function intentFingerprint(intent) {
  record(intent, ['version', 'clientOperationId', 'target', 'expectedSha256', 'byteSize',
    'partSize', 'dependencyPhase', 'transferMode']);
  assert.equal(intent.version, 1);
  assert(DIGEST.test(intent.clientOperationId) && DIGEST.test(intent.expectedSha256));
  const target = intent.target;
  let targetBytes;
  if (target.kind === 'cache_object') {
    record(target, ['kind', 'cacheId', 'path']);
    targetBytes = Buffer.concat([Buffer.from([1]), text(target.cacheId), text(target.path)]);
  } else if (target.kind === 'publication_object') {
    record(target, ['kind', 'publicationId', 'surfaceObjectId', 'path']);
    integer(target.surfaceObjectId, true);
    targetBytes = Buffer.concat([Buffer.from([2]), text(target.publicationId),
      u64(target.surfaceObjectId), text(target.path)]);
  } else {
    record(target, ['kind', 'uploadId']);
    assert.equal(target.kind, 'oci_blob');
    targetBytes = Buffer.concat([Buffer.from([3]), text(target.uploadId)]);
  }
  const phase = { content: 1, leaf_metadata: 2, visibility: 3 }[intent.dependencyPhase];
  assert(phase);
  assert.equal(intent.transferMode, 'direct_required');
  return sha(Buffer.concat([Buffer.from('aos.direct-upload.intent.v1\0'), u32(1),
    text(intent.clientOperationId), targetBytes, text(intent.expectedSha256),
    u64(intent.byteSize), u64(intent.partSize), Buffer.from([phase, 1])]));
}

export function manifestDigest(intent, placement, members) {
  const count = Number((integer(intent.byteSize) + integer(intent.partSize, true) - 1n)
    / integer(intent.partSize, true));
  assert.equal(members.length, count);
  const fields = [Buffer.from('aos.direct-upload.manifest.v1\0'), text(intentFingerprint(intent)),
    placementBytes(placement), u32(count)];
  members.forEach((member, index) => {
    record(member, ['part', 'etag']);
    const part = record(member.part, ['partNumber', 'offset', 'byteSize', 'sha256', 'checksum']);
    const checksum = record(part.checksum, ['algorithm', 'value']);
    const offset = BigInt(index) * integer(intent.partSize, true);
    const size = integer(intent.byteSize) - offset;
    assert.equal(part.partNumber, index + 1);
    assert.equal(integer(part.offset), offset);
    assert.equal(integer(part.byteSize), size < integer(intent.partSize) ? size : integer(intent.partSize));
    assert(DIGEST.test(part.sha256));
    assert.equal(checksum.algorithm, placement.checksumAlgorithm);
    assert.equal(Buffer.from(checksum.value, 'base64').toString('base64'), checksum.value);
    assert.equal(Buffer.from(checksum.value, 'base64').length, checksum.algorithm === 'md5' ? 16 : 32);
    fields.push(u32(part.partNumber), u64(part.offset), u64(part.byteSize), text(part.sha256),
      Buffer.from([checksum.algorithm === 'md5' ? 1 : 2]), text(checksum.value), text(strongEtag(member.etag)));
  });
  return sha(Buffer.concat(fields));
}

export function deterministicPayload(scope, phase) {
  const block = crypto.createHash('sha256').update(`aos.staged-race.v1:${scope}:${phase}`).digest();
  const payload = Buffer.alloc(PART_BYTES);
  for (let offset = 0; offset < payload.length; offset += block.length) block.copy(payload, offset);
  return payload;
}

async function privateBytes(file, maximum) {
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    assert(before.isFile() && before.uid === BigInt(process.getuid()) && before.nlink === 1n);
    assert.equal(before.mode & 0o777n, 0o600n);
    assert(before.size <= BigInt(maximum));
    // Allocate only the selected bound even if a retained input grows after stat.
    const buffer = Buffer.alloc(maximum + 1);
    let used = 0;
    while (used < buffer.length) {
      const { bytesRead } = await handle.read(buffer, used, buffer.length - used, used);
      if (bytesRead === 0) break;
      used += bytesRead;
    }
    const bytes = buffer.subarray(0, used);
    const after = await handle.stat({ bigint: true });
    assert.equal(BigInt(bytes.length), before.size);
    assert.equal(after.nlink, 1n);
    assert.equal(after.size, before.size);
    assert.equal(after.mtimeNs, before.mtimeNs);
    assert.equal(after.ctimeNs, before.ctimeNs);
    assert.equal(after.ino, before.ino);
    assert.equal(after.dev, before.dev);
    return bytes;
  } finally {
    await handle.close();
  }
}

export async function publishPrivate(root, name, bytes) {
  assert(path.basename(name) === name && name !== '.' && name !== '..');
  const temporary = path.join(root, `.${name}.${crypto.randomUUID()}.publication`);
  const final = path.join(root, name);
  const handle = await fs.open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  let linked = false;
  try {
    // Linking never replaces an earlier original. The final link becomes
    // durable while readers still see the temporary second link as pending.
    await fs.link(temporary, final);
    linked = true;
    const directory = await fs.open(root, 'r');
    try {
      await directory.sync();
      await fs.unlink(temporary);
      await directory.sync();
    } finally {
      await directory.close();
    }
  } finally {
    // A failed directory sync leaves the linked image pending, not accepted.
    if (!linked) await fs.unlink(temporary);
  }
  return { file: name, bytes: String(bytes.length), sha256: sha(bytes) };
}

export async function publicationBytes(file, maximum, validate) {
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    assert(before.isFile() && before.uid === BigInt(process.getuid()));
    assert(before.nlink === 1n || before.nlink === 2n);
    assert.equal(before.mode & 0o777n, 0o600n);
    assert(before.size <= BigInt(maximum));
    const buffer = Buffer.alloc(maximum + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const bytes = buffer.subarray(0, bytesRead);
    const after = await handle.stat({ bigint: true });
    assert.equal(BigInt(bytes.length), before.size);
    for (const field of ['ino', 'dev', 'size', 'mtimeNs']) assert.equal(after[field], before[field]);
    if (before.nlink === 1n) {
      assert.equal(after.nlink, 1n);
      assert.equal(after.ctimeNs, before.ctimeNs);
    } else {
      assert(after.nlink === 2n || after.nlink === 1n);
      if (after.nlink === 2n) assert.equal(after.ctimeNs, before.ctimeNs);
    }
    validate(bytes);
    return before.nlink === 2n ? null : bytes;
  } finally {
    await handle.close();
  }
}

async function selectedSource(reference) {
  record(reference, ['file', 'sha256']);
  const bytes = await fs.readFile(reference.file);
  assert(bytes.length <= 1024 * 1024);
  assert(DIGEST.test(reference.sha256) && sha(bytes) === reference.sha256);
  return bytes.toString('utf8');
}

async function reportHelper(reference) {
  const source = await selectedSource(reference);
  const start = source.indexOf('function reportRecord(');
  const end = source.indexOf('\nasync function upload(', start);
  assert(start >= 0 && end > start && source.indexOf('function reportRecord(', start + 1) < 0);
  const context = vm.createContext({ canonicalHash: value => sha(Buffer.from(JSON.stringify(value))) });
  vm.runInContext(`${source.slice(start, end)}\nthis.buildReport = reportObservation;`, context, { timeout: 1000 });
  return (object, grant, etag) => JSON.parse(JSON.stringify(context.buildReport(object, grant, etag)));
}

export function originalStatuses(response, session, intent, placement) {
  assert(Array.isArray(response.sessions) && response.sessions.length <= 1);
  for (const status of response.sessions) {
    assert.deepEqual(record(status.session, ['sessionId', 'logicalFingerprint']), session);
    assert.deepEqual(status.intent, intent);
    assert.deepEqual(status.placements, [placement]);
    integer(status.resourceVersion, true);
  }
  return response.sessions;
}

function acknowledgedReply(status, raw, operationId) {
  assert.equal(status, 200);
  const parsed = JSON.parse(raw);
  assert(Buffer.from(JSON.stringify(parsed)).equals(raw));
  const value = record(parsed, ['operationId', 'sessions', 'grants', 'errors']);
  assert.equal(value.operationId, operationId);
  assert.deepEqual(value.errors, []);
  assert(Array.isArray(value.grants));
  return value;
}

function knownCompleteStatus(value, session, intent, placement, pendingOnly = false) {
  assert.deepEqual(value.grants, []);
  const statuses = originalStatuses(value, session, intent, placement);
  assert.equal(statuses.length, 1);
  record(statuses[0], ['session', 'resourceVersion', 'intent', 'placements', 'state',
    'parts', 'nextCursor', 'outstandingGrants']);
  assert.deepEqual(statuses[0].parts, []);
  assert.equal(statuses[0].nextCursor, null);
  assert.equal(statuses[0].outstandingGrants, true);
  const allowed = pendingOnly ? ['completing_staging', 'staged_verified']
    : ['completing_staging', 'staged_verified', 'committed'];
  assert(allowed.includes(statuses[0].state));
  return statuses[0];
}

async function retainedImage(root, reference, maximum) {
  record(reference, ['file', 'bytes', 'sha256']);
  assert(path.basename(reference.file) === reference.file && !['.', '..'].includes(reference.file));
  return privateReference({ file: path.join(root, reference.file), sha256: reference.sha256,
    byteSize: reference.bytes }, maximum);
}

async function acceptedOriginal(selection, accepted) {
  const raw = await privateReference(accepted.prepared, 65536);
  const prepared = record(JSON.parse(raw), ['version', 'state', 'method', 'controlPath', 'runId', 'scope',
    'cutoffUnixMs', 'clock', 'session', 'intent', 'status', 'placement', 'expectedResourceVersion',
    'sourceSha256', 'actorWhoami', 'runtimePins', 'refs']);
  assert.equal(prepared.version, 1);
  assert.equal(prepared.state, 'prepared_unsent');
  assert.equal(prepared.method, 'CompleteBatch');
  assert.equal(prepared.controlPath, CONTROL_PATH + 'CompleteBatch');
  record(prepared.clock, ['bootId', 'cutoffUptimeMs']);
  assert(/^[0-9a-f-]{36}$/.test(prepared.clock.bootId)
    && Number.isSafeInteger(prepared.clock.cutoffUptimeMs) && prepared.clock.cutoffUptimeMs > 0);
  for (const field of ['runId', 'scope', 'cutoffUnixMs']) assert.deepEqual(prepared[field], selection[field]);
  for (const field of ['actorWhoami', 'runtimePins']) {
    assert.deepEqual(prepared[field], selection.preComplete[field]);
    await privateReference(prepared[field], 16384);
  }
  const originalRoot = path.dirname(accepted.prepared.file);
  assert.equal(await fs.realpath(originalRoot), originalRoot);
  const directory = await fs.stat(originalRoot);
  assert(directory.isDirectory() && directory.uid === process.getuid() && (directory.mode & 0o777) === 0o700);
  assert.equal(path.basename(accepted.prepared.file), 'pre-complete-prepared.json');
  const discovered = Object.hasOwn(selection, 'capabilities');
  record(prepared.refs, ['selectionValues', 'source', 'beginBody', 'beginReply', 'reportReply',
    'completeBody', 'pendingReceipt', ...(discovered ? ['capabilities'] : [])]);
  const images = {};
  for (const [field, reference] of Object.entries(prepared.refs)) {
    images[field] = await retainedImage(originalRoot, reference, field === 'source' ? PART_BYTES : 512 * 1024);
  }
  assert.deepEqual(JSON.parse(images.selectionValues), selection);
  assert.equal(images.source.length, PART_BYTES);
  assert.equal(sha(images.source), prepared.sourceSha256);
  assert.equal(prepared.intent.expectedSha256, prepared.sourceSha256);
  intentFingerprint(prepared.intent);
  assert.deepEqual(prepared.intent.target, selection.targets.complete.target);
  placementBytes(prepared.placement);
  if (discovered) {
    assert(images.capabilities.equals(await privateReference(selection.capabilities, 256 * 1024)));
    capabilityPlacement(prepared.placement, checkedCapabilities(JSON.parse(images.capabilities),
      selection.targets, selection.providerOrigin, null));
  } else assert.deepEqual(prepared.placement, selection.placement);
  const begin = record(JSON.parse(images.beginBody), ['operationId', 'items']);
  assert.deepEqual(begin.items, [prepared.intent]);
  const initial = acknowledgedReply(200, images.beginReply, begin.operationId);
  assert.deepEqual(initial.grants, []);
  const beginStatuses = originalStatuses(initial, prepared.session, prepared.intent, prepared.placement);
  assert.equal(beginStatuses.length, 1);
  assert.equal(beginStatuses[0].state, 'creating');
  const reportValue = JSON.parse(images.reportReply);
  assert(DIGEST.test(reportValue.operationId));
  const report = acknowledgedReply(200, images.reportReply, reportValue.operationId);
  assert.deepEqual(report.grants, []);
  assert.deepEqual(originalStatuses(report, prepared.session, prepared.intent, prepared.placement), [prepared.status]);
  const status = originalStatuses({ sessions: [prepared.status] }, prepared.session, prepared.intent, prepared.placement)[0];
  assert.equal(status.state, 'creating');
  assert.equal(status.resourceVersion, prepared.expectedResourceVersion);
  const complete = record(JSON.parse(images.completeBody), ['operationId', 'items']);
  assert(Buffer.from(JSON.stringify(complete)).equals(images.completeBody));
  assert.equal(complete.items.length, 1);
  const item = record(complete.items[0], ['session', 'operationId', 'expectedResourceVersion', 'manifests']);
  assert.deepEqual(item.session, prepared.session);
  assert.equal(item.expectedResourceVersion, prepared.expectedResourceVersion);
  assert.equal(item.manifests.length, 1);
  const manifest = record(item.manifests[0], ['placement', 'manifestDigest', 'partCount']);
  assert.deepEqual(manifest.placement, prepared.placement);
  assert(DIGEST.test(manifest.manifestDigest) && manifest.partCount === 1);
  const pending = record(JSON.parse(images.pendingReceipt), ['method', 'request', 'cutoffUnixMs']);
  assert.deepEqual(pending, { method: 'CompleteBatch', request: prepared.refs.completeBody, cutoffUnixMs: prepared.cutoffUnixMs });
  const continuation = checkedContinuation(prepared, raw,
    JSON.parse(await privateBytes(path.join(originalRoot, 'pre-complete-continuation.json'), 65536)));
  for (const field of ['admissionObservation', 'wrapperObservation']) await privateReference(continuation[field], 65536);
  const responseRaw = await privateReference(accepted.firstResponse, 65536);
  const prefix = prepared.refs.completeBody.file.replace(/-request\.json$/, '');
  assert.equal(accepted.firstResponse.file, path.join(originalRoot, `${prefix}-response.json`));
  const marker = record(JSON.parse(await privateBytes(path.join(originalRoot, `${prefix}-dispatch-started.json`), 65536)),
    ['request', 'pending', 'cutoffUnixMs', 'callIndex']);
  assert.deepEqual(marker, { request: prepared.refs.completeBody, pending: prepared.refs.pendingReceipt,
    cutoffUnixMs: prepared.cutoffUnixMs, callIndex: 1 });
  const responseImage = record(JSON.parse(responseRaw), ['status', 'request', 'reply']);
  assert.deepEqual(responseImage.request, prepared.refs.completeBody);
  assert.equal(responseImage.reply.file, `${prefix}-reply.json`);
  const firstReply = acknowledgedReply(responseImage.status,
    await retainedImage(originalRoot, responseImage.reply, 256 * 1024), complete.operationId);
  knownCompleteStatus(firstReply, prepared.session, prepared.intent, prepared.placement, true);
  return { prepared, originalRoot, complete: { raw: images.completeBody, value: complete }, firstReply, responseImage };
}

export function checkedContinuation(prepared, preparedRaw, continuation) {
  record(continuation, ['version', 'preparedSha256', 'completeBodySha256', 'runId', 'scope',
    'session', 'placement', 'expectedResourceVersion', 'sourceSha256', 'cutoffUnixMs',
    'actorWhoami', 'runtimePins', 'admissionObservation', 'wrapperObservation']);
  assert.equal(continuation.version, 1);
  assert.equal(continuation.preparedSha256, sha(preparedRaw));
  assert.equal(continuation.completeBodySha256, prepared.refs.completeBody.sha256);
  for (const field of ['runId', 'scope', 'session', 'placement', 'expectedResourceVersion',
    'sourceSha256', 'cutoffUnixMs', 'actorWhoami', 'runtimePins']) {
    assert.deepEqual(continuation[field], prepared[field]);
  }
  for (const field of ['admissionObservation', 'wrapperObservation']) {
    const reference = record(continuation[field], ['file', 'sha256', 'byteSize']);
    assert(DIGEST.test(reference.sha256));
    assert(integer(reference.byteSize, true) <= 65536n);
  }
  return continuation;
}

async function privateReference(reference, maximum) {
  record(reference, ['file', 'sha256', 'byteSize']);
  const bytes = await privateBytes(reference.file, maximum);
  assert.equal(String(bytes.length), reference.byteSize);
  assert.equal(sha(bytes), reference.sha256);
  return bytes;
}

export function terminalDenial(response) {
  // Closed multipart denial only. Authentication/signature/expiry errors and
  // empty or untyped 404s cannot witness capability closure.
  if (response.status !== 404 || !response.eof || response.bytes > 16384
    || response.bytes !== response.body.length) return false;
  let body;
  try {
    body = new TextDecoder('utf-8', { fatal: true }).decode(response.body);
  } catch {
    return false;
  }
  const root = body.match(/^\s*(?:<\?xml[^>]*\?>\s*)?<Error(?: xmlns="[^"]*")?>([\s\S]*)<\/Error>\s*$/);
  if (!root) return false;
  const fields = [...root[1].matchAll(/<(Code|Message|Resource|RequestId|HostId)>([^<]*)<\/\1>/g)];
  const consumed = root[1].replace(/<(Code|Message|Resource|RequestId|HostId)>([^<]*)<\/\1>/g, '');
  if (consumed.trim() || new Set(fields.map(field => field[1])).size !== fields.length) return false;
  if (fields.some(field => /&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9a-fA-F]+;)/.test(field[2]))) return false;
  return fields.filter(field => field[1] === 'Code' && field[2] === 'NoSuchUpload').length === 1;
}

function boundedRemaining(cutoff) {
  const remaining = cutoff - Date.now();
  assert(remaining > 0 && remaining <= 180000);
  return remaining;
}

export async function run(selection, output) {
  return ownedRun(selection, output, null);
}

export async function continueAcknowledged(selection, accepted, output) {
  record(accepted, ['version', 'prepared', 'firstResponse']);
  assert.equal(accepted.version, 1);
  return ownedRun(selection, output, accepted);
}

async function ownedRun(selection, output, accepted) {
  const owner = new AbortController();
  let timer;
  try {
    return await runOwned(selection, output, owner, value => { timer = value; }, accepted);
  } finally {
    owner.abort();
    clearTimeout(timer);
  }
}

async function runOwned(selection, output, owner, registerTimer, accepted) {
  const handoff = Object.hasOwn(selection, 'preComplete');
  assert(!accepted || handoff);
  const discovered = Object.hasOwn(selection, 'capabilities');
  record(selection, ['version', 'runId', 'scope', 'origin', 'tokenFile', 'providerOrigin',
    'providerPathPrefix', 'cutoffUnixMs', discovered ? 'capabilities' : 'placement', 'targets', 'reportHelperSource', 'protoSources',
    ...(handoff ? ['preComplete'] : [])]);
  if (handoff) {
    record(selection.preComplete, ['actorWhoami', 'runtimePins']);
    await privateReference(selection.preComplete.actorWhoami, 16384);
    await privateReference(selection.preComplete.runtimePins, 16384);
  }
  assert.equal(selection.version, 1);
  assert(DIGEST.test(selection.runId));
  assert(['managed_r2', 'external_s3'].includes(selection.scope));
  const origin = new URL(selection.origin);
  const provider = new URL(selection.providerOrigin);
  for (const url of [origin, provider]) {
    assert(url.protocol === 'https:' && !url.username && !url.password && url.pathname === '/'
      && !url.search && !url.hash);
  }
  assert(selection.providerPathPrefix.startsWith('/') && !selection.providerPathPrefix.includes('?'));
  if (!discovered) placementBytes(selection.placement);
  record(selection.targets, handoff ? ['complete'] : ['complete', 'abort']);
  if (discovered) assert.equal(selection.providerOrigin, provider.origin);
  const capabilityRaw = discovered ? await privateReference(selection.capabilities, 256 * 1024) : null;
  const capabilities = discovered ? checkedCapabilities(JSON.parse(capabilityRaw), selection.targets, provider.origin, accepted ? null : Date.now()) : null;
  const targetIdentities = Object.values(selection.targets).map(target => JSON.stringify(target.target));
  if (!handoff) assert.notEqual(targetIdentities[0], targetIdentities[1]);
  assert(!selection.providerPathPrefix.includes('..') && !selection.providerPathPrefix.includes('#'));
  for (const reference of selection.protoSources) await selectedSource(reference);
  assert.equal(selection.protoSources.length, 3);
  const buildReport = await reportHelper(selection.reportHelperSource);
  const token = (await privateBytes(selection.tokenFile, 16384)).toString('utf8').trim();
  assert(token.length > 0 && !/[\r\n]/.test(token));
  const cutoff = selection.cutoffUnixMs;
  assert(Number.isSafeInteger(cutoff));
  let remaining = boundedRemaining(cutoff);
  const bootId = (await fs.readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
  const clock = { bootId, cutoffUptimeMs: Math.floor(os.uptime() * 1000) + boundedRemaining(cutoff) };
  let original;
  if (accepted) {
    original = await acceptedOriginal(selection, accepted);
    assert.equal(original.prepared.clock.bootId, bootId);
    clock.cutoffUptimeMs = original.prepared.clock.cutoffUptimeMs;
    remaining = Math.min(remaining, clock.cutoffUptimeMs - Math.floor(os.uptime() * 1000));
    assert(remaining > 0);
  }
  remaining = Math.min(boundedRemaining(cutoff), clock.cutoffUptimeMs - Math.floor(os.uptime() * 1000));
  assert(remaining > 0);
  registerTimer(setTimeout(() => owner.abort(), remaining));
  const signal = owner.signal;
  const parent = path.dirname(path.resolve(output));
  assert.equal(await fs.realpath(parent), parent);
  const parentStat = await fs.stat(parent);
  assert(parentStat.uid === process.getuid() && (parentStat.mode & 0o777) === 0o700);
  await fs.mkdir(output, { mode: 0o700 });
  let sequence = 0;
  const results = [];
  let lastControl;

  async function retain(name, bytes) {
    const file = await fs.open(path.join(output, name), 'wx', 0o600);
    try {
      await file.writeFile(bytes);
      await file.sync();
    } finally {
      await file.close();
    }
    const directory = await fs.open(output, 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
    return { file: name, bytes: String(bytes.length), sha256: sha(bytes) };
  }

  const selectionValues = await retain('selected-values.json', Buffer.from(JSON.stringify(selection)));
  const capabilityImage = discovered ? await retain('capabilities-reply.json', capabilityRaw) : null;

  async function prepareControl(method, body) {
    const raw = Buffer.from(JSON.stringify(body));
    assert(raw.length <= (discovered ? capabilities.maximumControlBytes : 256 * 1024));
    const prefix = `${String(++sequence).padStart(3, '0')}-${method}`;
    const request = await retain(`${prefix}-request.json`, raw);
    const pending = await retain(`${prefix}-pending.json`, Buffer.from(JSON.stringify({ method, request, cutoffUnixMs: cutoff })));
    return { method, body, prefix, raw, request, pending };
  }

  async function dispatchControl(prepared, callIndex = 1) {
    const { method, body, prefix, raw, request, pending } = prepared;
    const originalRoot = prepared.originalRoot ?? output;
    if (!prepared.pinned) {
      const saved = await privateBytes(path.join(originalRoot, request.file), 512 * 1024);
      assert(saved.equals(raw) && sha(saved) === request.sha256);
    }
    const pendingBytes = await privateBytes(path.join(originalRoot, pending.file), 65536);
    assert.equal(sha(pendingBytes), pending.sha256);
    assert.equal(String(pendingBytes.length), pending.bytes);
    assert(!signal.aborted && Date.now() < cutoff && Math.floor(os.uptime() * 1000) < clock.cutoffUptimeMs);
    const callPrefix = callIndex === 1 ? prefix : `${prefix}-phase-${callIndex}`;
    await retain(`${callPrefix}-dispatch-started.json`, Buffer.from(JSON.stringify({ request, pending,
      cutoffUnixMs: cutoff, callIndex })));
    // Durable publication may consume the remaining window. Recheck immediately
    // before Fetch; the earlier fence cannot authorize a later dispatch.
    assert(!signal.aborted && Date.now() < cutoff && Math.floor(os.uptime() * 1000) < clock.cutoffUptimeMs);
    const response = await fetch(new URL(CONTROL_PATH + method, origin), {
      method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: raw, signal, redirect: 'error',
    });
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      assert(size <= (discovered ? capabilities.maximumControlBytes : 256 * 1024));
      chunks.push(Buffer.from(chunk));
    }
    const bytes = Buffer.concat(chunks);
    const reply = await retain(`${callPrefix}-reply.json`, bytes);
    const responseImage = await retain(`${callPrefix}-response.json`,
      Buffer.from(JSON.stringify({ status: response.status, request, reply })));
    // Only a fully consumed, closed, unambiguous successful reply can authorize
    // the next phase. A lost reply stops progression, even if a server acted.
    const value = acknowledgedReply(response.status, bytes, body.operationId);
    lastControl = { method, request, reply, response: responseImage, callIndex,
      requestRoot: originalRoot, imageRoot: output };
    return value;
  }

  function completeCall(value, session, intent, placement) {
    const absolute = (reference, root) => ({
      file: path.isAbsolute(reference.file) ? reference.file : path.join(root, reference.file),
      bytes: reference.bytes ?? reference.byteSize, sha256: reference.sha256,
    });
    return { callIndex: lastControl.callIndex, method: lastControl.method,
      request: absolute(lastControl.request, lastControl.requestRoot),
      reply: absolute(lastControl.reply, lastControl.imageRoot),
      response: absolute(lastControl.response, lastControl.imageRoot),
      states: originalStatuses(value, session, intent, placement).map(status => status.state) };
  }

  async function progressComplete(pending, first, session, intent, placement, initialCall) {
    let value = first;
    let callIndex = initialCall;
    const calls = [completeCall(value, session, intent, placement)];
    while (true) {
      const status = knownCompleteStatus(value, session, intent, placement);
      if (status.state === 'committed') return { status, calls };
      assert(!signal.aborted && Date.now() < cutoff);
      await new Promise(resolve => setTimeout(resolve, 250));
      value = await dispatchControl(pending, ++callIndex);
      calls.push(completeCall(value, session, intent, placement));
    }
  }

  async function control(method, body) {
    return dispatchControl(await prepareControl(method, body));
  }

  async function continuePrepared(prepared) {
    const raw = Buffer.from(JSON.stringify(prepared));
    await publishPrivate(output, 'pre-complete-prepared.json', raw);
    const continuationFile = path.join(output, 'pre-complete-continuation.json');
    let continuation;
    while (!continuation) {
      assert(!signal.aborted && Date.now() < cutoff);
      try {
        const bytes = await publicationBytes(continuationFile, 65536,
          value => checkedContinuation(prepared, raw, JSON.parse(value)));
        if (bytes) continuation = checkedContinuation(prepared, raw, JSON.parse(bytes));
        else await new Promise(resolve => setTimeout(resolve, 25));
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        await new Promise(resolve => setTimeout(resolve, 25));
      }
    }
    for (const field of ['actorWhoami', 'runtimePins', 'admissionObservation', 'wrapperObservation']) {
      await privateReference(continuation[field], 65536);
    }
    if (discovered) {
      assert((await privateReference(selection.capabilities, 256 * 1024)).equals(capabilityRaw));
      const image = await privateBytes(path.join(output, capabilityImage.file), 256 * 1024);
      assert(image.equals(capabilityRaw));
    }
    const source = await privateBytes(path.join(output, prepared.refs.source.file), PART_BYTES);
    assert.equal(sha(source), prepared.sourceSha256);
    return continuation;
  }

  async function part(grant, payload, hold = false) {
    assert(!signal.aborted && Date.now() < cutoff && Math.floor(os.uptime() * 1000) < clock.cutoffUptimeMs);
    assert(Date.now() < Number(integer(grant.expiresAt, true)) * 1000);
    const url = new URL(grant.url);
    assert.equal(url.origin, provider.origin);
    assert(url.pathname.startsWith(selection.providerPathPrefix));
    assert.equal(url.searchParams.get('partNumber'), '1');
    assert.equal(url.hash, '');
    assert(!url.username && !url.password);
    assert(url.searchParams.get('uploadId') && url.searchParams.get('X-Amz-Signature'));
    const headers = {};
    assert.equal(grant.requiredHeaders.length, 2);
    for (const header of grant.requiredHeaders) {
      record(header, ['name', 'value']);
      assert(!/^(authorization|cookie|host)$/i.test(header.name));
      assert(!Object.hasOwn(headers, header.name.toLowerCase()));
      headers[header.name.toLowerCase()] = header.value;
    }
    const checksumHeader = grant.part.checksum.algorithm === 'md5' ? 'content-md5' : 'x-amz-checksum-sha256';
    assert.equal(headers[checksumHeader], grant.part.checksum.value);
    assert.equal(headers['content-length'], String(payload.length));
    assert.deepEqual(Object.keys(headers).sort(), ['content-length', checksumHeader].sort());
    let release;
    const held = new Promise(resolve => { release = resolve; });
    let offeredBytes = 0;
    const offeredHash = crypto.createHash('sha256');
    let resolveOffered;
    const offered = new Promise(resolve => { resolveOffered = resolve; });
    const dispatchUnixMs = Date.now();
    const responsePromise = new Promise((resolve, reject) => {
      const request = https.request(url, { method: 'PUT', headers, signal }, response => {
        const chunks = [];
        let bytes = 0;
        response.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > 16384) response.destroy(new Error('bounded provider response exceeded'));
          else chunks.push(chunk);
        });
        response.on('error', reject);
        response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks),
          bytes, eof: response.complete, receivedUnixMs: Date.now(), etag: response.headers.etag ?? null }));
      });
      request.on('error', reject);
      // Observe offered client bytes only. This callback is not a provider-start receipt.
      (async () => {
        for (let offset = 0; offset < payload.length; offset += 65536) {
          const chunk = payload.subarray(offset, offset + 65536);
          offeredBytes += chunk.length;
          offeredHash.update(chunk);
          const ready = request.write(chunk);
          if (!ready) await once(request, 'drain', { signal });
          if (offset === 0) {
            resolveOffered();
            if (hold) await held;
          }
        }
        request.end();
      })().catch(error => request.destroy(error));
    });
    responsePromise.catch(() => {});
    await Promise.race([offered, responsePromise.then(() => { throw new Error('early provider response'); })]);
    return { release, response: responsePromise, observation: () => ({ offeredBytes: String(offeredBytes),
      offeredSha256: offeredHash.copy().digest('hex'), dispatchUnixMs, offeredEof: offeredBytes === payload.length,
      providerStartWitness: null }) };
  }

  if (accepted) {
    const { prepared, complete, firstReply, responseImage, originalRoot } = original;
    await retain('accepted-original-selection.json', Buffer.from(JSON.stringify(accepted)));
    // Consuming this original is create-only across processes. A crash after
    // this marker cannot authorize another fresh continuation process.
    await publishPrivate(originalRoot, 'accepted-complete-continuation-started.json',
      Buffer.from(JSON.stringify({ accepted, cutoffUnixMs: cutoff })));
    const pending = { method: 'CompleteBatch', body: complete.value, raw: complete.raw,
      prefix: prepared.refs.completeBody.file.replace(/-request\.json$/, ''),
      request: prepared.refs.completeBody, pending: prepared.refs.pendingReceipt,
      originalRoot, pinned: true };
    lastControl = { method: 'CompleteBatch', request: pending.request,
      reply: responseImage.reply, response: accepted.firstResponse, callIndex: 1,
      requestRoot: originalRoot, imageRoot: originalRoot };
    const progressed = await progressComplete(pending, firstReply, prepared.session,
      prepared.intent, prepared.placement, 1);
    const result = { version: 1, runId: selection.runId, scope: selection.scope, cutoffUnixMs: cutoff,
      mode: 'accepted_original_continuation', status: 'incomplete', acceptedOriginal: accepted,
      results: [{ phase: 'complete', session: prepared.session, placement: prepared.placement,
        sourceSha256: prepared.sourceSha256, terminalState: progressed.status.state,
        completeBodySha256: pending.request.sha256, completeCalls: progressed.calls,
        raceQualification: null, cleanupSettlement: null }],
      publicationCommit: 'not_invoked', missing: ['authenticated_control_and_current_source_joins',
        'provider_settlement_and_resource_tail'] };
    await retain('result.json', Buffer.from(JSON.stringify(result)));
    return result;
  }

  for (const phase of handoff ? ['complete'] : ['complete', 'abort']) {
    const selected = record(selection.targets[phase], ['target', 'finalReadUrl']);
    const payload = deterministicPayload(selection.scope, phase);
    const operation = suffix => identity(selection.runId, selection.scope, `${phase}:${suffix}`);
    const intent = { version: 1, clientOperationId: operation('begin-item'), target: uploadTarget(selected.target),
      expectedSha256: sha(payload), byteSize: String(PART_BYTES), partSize: String(PART_BYTES),
      dependencyPhase: 'content', transferMode: 'direct_required' };
    const source = await retain(`${phase}-source.bin`, payload);
    if (discovered) checkedCapabilities(capabilities, selection.targets, provider.origin, Date.now());
    const admission = await control('BeginBatch', { operationId: operation('begin-batch'), items: [intent] });
    const beginReply = lastControl.reply;
    const beginBody = lastControl.request;
    assert.equal(admission.sessions.length, 1);
    assert.deepEqual(admission.grants, []);
    let status = admission.sessions[0];
    assert.deepEqual(status.intent, intent);
    // Public status is the Native logical session; the physical journal's
    // Active transition is not echoed by BeginBatch.
    assert.equal(status.state, 'creating');
    assert(Array.isArray(status.placements) && status.placements.length === 1);
    const placement = discovered
      ? capabilityPlacement(status.placements[0], capabilities) : record(selection.placement, PLACEMENT_FIELDS);
    assert.deepEqual(status.placements, [placement]);
    const session = record(status.session, ['sessionId', 'logicalFingerprint']);
    opaqueIdentity(session.sessionId);
    // The full admission fingerprint includes private actor/placement/expiry
    // fields. Preserve the actual public value for independent Core validation.
    assert(DIGEST.test(session.logicalFingerprint));
    originalStatuses(admission, session, intent, placement);
    if (discovered) {
      assert((await privateReference(selection.capabilities, 256 * 1024)).equals(capabilityRaw));
      checkedCapabilities(capabilities, selection.targets, provider.origin, Date.now());
    }
    const checksum = crypto.createHash(placement.checksumAlgorithm).update(payload).digest('base64');
    const declaration = { partNumber: 1, offset: '0', byteSize: String(PART_BYTES), sha256: sha(payload),
      checksum: { algorithm: placement.checksumAlgorithm, value: checksum } };
    const granted = await control('GrantPartsBatch', { operationId: operation('grant-batch'), items: [{ session,
      placement, operationId: operation('grant-item'), part: declaration }] });
    assert.equal(granted.grants.length, 1);
    originalStatuses(granted, session, intent, placement);
    const grant = record(granted.grants[0], ['sessionId', 'logicalFingerprint', 'placement', 'grantId',
      'grantRevision', 'part', 'method', 'url', 'requiredHeaders', 'expiresAt']);
    assert.equal(grant.method, 'PUT');
    assert(DIGEST.test(grant.grantId));
    integer(grant.grantRevision, true);
    assert.equal(grant.sessionId, session.sessionId);
    assert.equal(grant.logicalFingerprint, session.logicalFingerprint);
    assert.deepEqual(grant.placement, placement);
    assert.deepEqual(grant.part, declaration);
    const first = await part(grant, payload);
    const positive = await first.response;
    assert.equal(positive.status, 200);
    assert(positive.eof);
    await retain(`${phase}-positive-provider-body.bin`, positive.body);
    strongEtag(positive.etag);
    const reported = await control('ReportPartsBatch', { operationId: operation('report-batch'),
      items: [buildReport(intent.clientOperationId, grant, positive.etag)] });
    const reportReply = lastControl.reply;
    const statuses = originalStatuses(reported, session, intent, placement);
    assert.equal(statuses.length, 1);
    status = statuses[0];
    assert.deepEqual(status.intent, intent);
    assert.deepEqual(status.placements, [placement]);
    integer(status.resourceVersion, true);
    if (handoff) {
      assert.equal(statuses.length, 1);
      assert.equal(status.state, 'creating');
      const close = { session, operationId: operation('close-item'), expectedResourceVersion: status.resourceVersion,
        manifests: [{ placement,
          manifestDigest: manifestDigest(intent, placement, [{ part: declaration, etag: positive.etag }]),
          partCount: 1 }] };
      const pending = await prepareControl('CompleteBatch', { operationId: operation('close-batch'), items: [close] });
      const prepared = { version: 1, state: 'prepared_unsent', method: 'CompleteBatch', controlPath: CONTROL_PATH + 'CompleteBatch',
        runId: selection.runId, scope: selection.scope, cutoffUnixMs: cutoff, clock, session, intent, status,
        placement, expectedResourceVersion: status.resourceVersion, sourceSha256: intent.expectedSha256,
        actorWhoami: selection.preComplete.actorWhoami, runtimePins: selection.preComplete.runtimePins,
        refs: { selectionValues, source, beginBody, beginReply, reportReply, completeBody: pending.request, pendingReceipt: pending.pending,
          ...(discovered ? { capabilities: capabilityImage } : {}) } };
      const continuation = await continuePrepared(prepared);
      const closed = await dispatchControl(pending);
      assert.deepEqual(closed.grants, []);
      const terminalStatuses = originalStatuses(closed, session, intent, placement);
      assert.equal(terminalStatuses.length, 1);
      results.push({ phase, session, sourceSha256: intent.expectedSha256, placement,
        preparedCompleteSha256: pending.request.sha256, firstCompleteResponse: lastControl.response, firstCompleteCallIndex: 1, observedStates: terminalStatuses.map(value => value.state),
        admissionObservation: continuation.admissionObservation, wrapperObservation: continuation.wrapperObservation,
        raceQualification: null, cleanupSettlement: null });
      await retain('complete-handoff-observations.json', Buffer.from(JSON.stringify(results.at(-1))));
      continue;
    }
    const racing = await part(grant, payload, true);
    let closeReply;
    let closeOriginal;
    try {
      const close = { session, operationId: operation('close-item'), expectedResourceVersion: status.resourceVersion };
      if (phase === 'complete') close.manifests = [{ placement,
        manifestDigest: manifestDigest(intent, placement, [{ part: declaration, etag: positive.etag }]),
        partCount: 1 }];
      closeOriginal = await prepareControl(phase === 'complete' ? 'CompleteBatch' : 'Abort',
        { operationId: operation('close-batch'), items: [close] });
      closeReply = await dispatchControl(closeOriginal);
    } catch (error) {
      owner.abort();
      throw error;
    } finally {
      racing.release();
    }
    const raceResponse = await racing.response.catch(() => null);
    const raceObservation = racing.observation();
    if (raceResponse) await retain(`${phase}-racing-provider-body.bin`, raceResponse.body);
    const terminal = phase === 'complete' ? 'committed' : 'aborted';
    assert.deepEqual(closeReply.grants, []);
    let states = originalStatuses(closeReply, session, intent, placement);
    assert.equal(states.length, 1);
    let completeCalls = null;
    if (phase === 'complete') {
      const progressed = await progressComplete(closeOriginal, closeReply, session, intent, placement, 1);
      states = [progressed.status];
      completeCalls = progressed.calls;
    }
    while (states.length !== 1 || states[0].state !== terminal) {
      assert(!signal.aborted && Date.now() < cutoff);
      assert(!states.some(value => ['blocked_unknown', 'cleanup_pending'].includes(value.state)));
      await new Promise(resolve => setTimeout(resolve, 250));
      const polled = await control('StatusBatch', { operationId: operation(`status-${sequence}`),
        items: [{ session, after: null, maximumParts: 1 }] });
      states = originalStatuses(polled, session, intent, placement);
    }
    const late = await part(grant, payload);
    const lateResponse = await late.response;
    await retain(`${phase}-late-provider-body.bin`, lateResponse.body);
    let finalRead = null;
    if (phase === 'complete' && selected.finalReadUrl !== null) {
      const readUrl = new URL(selected.finalReadUrl);
      assert.equal(readUrl.origin, origin.origin);
      const response = await fetch(readUrl, { headers: { authorization: `Bearer ${token}` }, signal, redirect: 'error' });
      const hash = crypto.createHash('sha256');
      let bytes = 0;
      for await (const chunk of response.body) {
        bytes += chunk.length;
        assert(bytes <= PART_BYTES);
        hash.update(chunk);
      }
      finalRead = { status: response.status, bytes: String(bytes), sha256: hash.digest('hex'), eof: true };
      assert.equal(response.status, 200);
      assert.equal(bytes, PART_BYTES);
      assert.equal(finalRead.sha256, intent.expectedSha256);
    }
    results.push({ phase, session, sourceSha256: intent.expectedSha256, placement,
      grantId: grant.grantId, grantRevision: grant.grantRevision, grantExpiresAt: grant.expiresAt,
      grantUrlSha256: sha(Buffer.from(grant.url)), completeCalls, positiveEtag: positive.etag, positiveReply: { bytes: String(positive.bytes), sha256: sha(positive.body), eof: positive.eof }, terminalState: states[0].state,
      racing: { ...raceObservation, status: raceResponse?.status ?? null,
        eof: raceResponse?.eof ?? false, replyBytes: raceResponse ? String(raceResponse.bytes) : null,
        replySha256: raceResponse ? sha(raceResponse.body) : null, deniedNoSuchUpload: raceResponse ? terminalDenial(raceResponse) : null,
        unexpiredAtObservedReply: raceResponse ? raceResponse.receivedUnixMs < Number(grant.expiresAt) * 1000 : null },
      late: { ...late.observation(), status: lateResponse.status, eof: lateResponse.eof,
        replyBytes: String(lateResponse.bytes), replySha256: sha(lateResponse.body),
        deniedNoSuchUpload: terminalDenial(lateResponse),
        unexpiredAtObservedReply: lateResponse.receivedUnixMs < Number(grant.expiresAt) * 1000 }, finalRead,
      raceQualification: null, cleanupSettlement: null });
    await retain(`${phase}-observations.json`, Buffer.from(JSON.stringify(results.at(-1))));
  }
  const result = { version: 1, sourcePins: { proto: selection.protoSources, reportHelper: selection.reportHelperSource }, runId: selection.runId, scope: selection.scope, cutoffUnixMs: cutoff,
    results, mode: handoff ? 'pre_complete_handoff' : 'signed_closure_races', status: 'incomplete', missing: ['independent_provider_start', 'authenticated_control_and_current_source_joins',
      'provider_settlement_and_resource_tail'] };
  await retain('result.json', Buffer.from(JSON.stringify(result)));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const continuing = process.argv.length === 6 && process.argv[4] === '--continue-accepted';
    assert(process.argv.length === 4 || continuing);
    const selection = JSON.parse(await privateBytes(process.argv[2], 65536));
    if (continuing) {
      const accepted = JSON.parse(await privateBytes(process.argv[5], 65536));
      await continueAcknowledged(selection, accepted, process.argv[3]);
    } else await run(selection, process.argv[3]);
    console.log(JSON.stringify({ status: 'incomplete', resultFile: path.join(process.argv[3], 'result.json') }));
    process.exitCode = 2;
  } catch {
    console.error('staged closure observations unavailable; retain original private files; do not retry mutations');
    process.exitCode = 1;
  }
}
