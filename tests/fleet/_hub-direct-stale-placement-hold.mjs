// One fixture request may wait before the real authenticated Worker dispatch.
// This adapter preserves bytes; it does not authenticate or mint a plan.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const PLAN_LIMIT = 64 * 1024;
const ROUTE = '/_internal/storage/v1/execute';
const CONTEXT = [
  'deployment_id', 'placement_id', 'placement_resource_version',
  'binding_id', 'binding_resource_version', 'binding_kind', 'placement_prefix',
];
const REQUIRED = [
  'version', 'plan_id', 'issued_at', 'expires_at', 'operation', ...CONTEXT,
];
const OPTIONAL = ['binding_snapshot_revision', 'credential_references'];

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function exactFields(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...fields].sort().join('\0');
}

function privateDirectory(directory) {
  const observed = fs.lstatSync(directory);
  if (!path.isAbsolute(directory) || !observed.isDirectory()
      || observed.uid !== process.getuid() || (observed.mode & 0o077) !== 0) {
    throw new Error('hold_directory_custody');
  }
}

function retain(directory, name, bytes) {
  const descriptor = fs.openSync(path.join(directory, name),
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW, 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  const parent = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    fs.fsyncSync(parent);
  } finally {
    fs.closeSync(parent);
  }
}

/** Creates a confined barrier for one exact placement's info/refs plan. */
export function stalePlacementHold(selection, directory) {
  if (!exactFields(selection, ['version', 'originHost', ...CONTEXT])
      || selection.version !== 1 || typeof selection.originHost !== 'string'
      || selection.originHost.length > 253 || !/^[a-z0-9.-]+$/.test(selection.originHost)
      || Buffer.byteLength(JSON.stringify(selection)) > PLAN_LIMIT
      || !['deployment_r2', 's3', 'r2'].includes(selection.binding_kind)
      || typeof selection.deployment_id !== 'string' || !selection.deployment_id
      || Buffer.byteLength(selection.deployment_id) > 255
      || selection.deployment_id.trim() !== selection.deployment_id
      || /[\x00-\x1f\x7f]/.test(selection.deployment_id)
      || typeof selection.placement_prefix !== 'string'
      || CONTEXT.filter(name => name.endsWith('_id') || name.endsWith('_version'))
        .filter(name => name !== 'deployment_id')
        .some(name => !Number.isSafeInteger(selection[name]) || selection[name] <= 0)) {
    throw new Error('hold_selection_shape');
  }
  privateDirectory(directory);
  retain(directory, 'selection.json', Buffer.from(JSON.stringify(selection)));

  let state = 'unused';
  let selected = null;
  let timer = null;
  let complete = null;
  let refuse = null;

  function expire() {
    if (state !== 'held') return;
    state = 'expired';
    retain(directory, 'expired.json', Buffer.from(JSON.stringify(status())));
    refuse(new Error('hold_original_expired'));
  }

  function status() {
    return {
      version: 1, state,
      requestSha256: selected?.requestSha256 ?? null,
      signatureSha256: selected?.signatureSha256 ?? null,
      planIdSha256: selected?.planIdSha256 ?? null,
      bodyBytes: selected?.bodyBytes ?? null,
      expiresAtUnixSeconds: selected?.expiresAtUnixSeconds ?? null,
      observedAtUnixMillis: String(Date.now()),
    };
  }

  async function beforeDispatch(request, body) {
    if (request.method !== 'POST' || request.url !== ROUTE) return false;
    if (!Buffer.isBuffer(body) || !body.length || body.length > PLAN_LIMIT) return false;
    let plan;
    try {
      plan = JSON.parse(body.toString('utf8'));
    } catch {
      return false;
    }
    if (plan === null || typeof plan !== 'object'
        || !CONTEXT.every(name => plan[name] === selection[name])
        || !exactFields(plan.operation, ['kind', 'path'])
        || plan.operation.kind !== 'inspect_metadata' || plan.operation.path !== 'info/refs') {
      return false;
    }
    // The ordinary Rust serializer emits this canonical spelling. Reject
    // duplicate fields or a changed representation; forward the original Buffer.
    if (!body.equals(Buffer.from(JSON.stringify(plan)))
        || REQUIRED.some(name => !Object.hasOwn(plan, name))
        || Object.keys(plan).some(name => ![...REQUIRED, ...OPTIONAL].includes(name))
        || plan.version !== 1 || typeof plan.plan_id !== 'string' || !plan.plan_id
        || !Number.isSafeInteger(plan.issued_at) || !Number.isSafeInteger(plan.expires_at)
        || plan.expires_at <= plan.issued_at || plan.expires_at - plan.issued_at > 30
        || Date.now() < plan.issued_at * 1000 || Date.now() >= plan.expires_at * 1000) {
      throw new Error('hold_plan_shape_or_time');
    }
    const headers = request.headers;
    const transportBefore = JSON.stringify({
      method: request.method, route: request.url, headers,
    });
    if (headers.host !== selection.originHost
        || headers['content-type'] !== 'application/json'
        || headers['content-length'] !== String(body.length)
        || headers['transfer-encoding'] !== undefined
        || !/^[0-9a-f]{64}$/.test(headers['x-aos-storage-work-signature'])) {
      throw new Error('hold_transport_shape');
    }
    if (state !== 'unused') throw new Error('hold_original_already_selected');

    selected = {
      requestSha256: sha256(body),
      signatureSha256: sha256(Buffer.from(headers['x-aos-storage-work-signature'])),
      planIdSha256: sha256(Buffer.from(plan.plan_id)),
      bodyBytes: String(body.length), expiresAtUnixSeconds: String(plan.expires_at),
    };
    retain(directory, 'original-request.json', body);
    retain(directory, 'original-transport.json', Buffer.from(JSON.stringify({
      method: request.method, route: request.url, host: headers.host,
      contentType: headers['content-type'], contentLength: headers['content-length'],
      signature: headers['x-aos-storage-work-signature'],
    })));
    state = 'held';
    retain(directory, 'held.json', Buffer.from(JSON.stringify(status())));

    const waiting = new Promise((resolve, reject) => {
      complete = resolve;
      refuse = reject;
    });
    timer = setTimeout(expire, plan.expires_at * 1000 - Date.now());
    await waiting;
    if (sha256(body) !== selected.requestSha256
        || JSON.stringify({ method: request.method, route: request.url, headers: request.headers })
          !== transportBefore) {
      throw new Error('hold_original_changed_before_dispatch');
    }
    return true;
  }

  function release(requestSha256) {
    if (state !== 'held' || requestSha256 !== selected.requestSha256) {
      throw new Error('hold_release_original_mismatch');
    }
    if (Date.now() >= Number(selected.expiresAtUnixSeconds) * 1000) {
      expire();
      throw new Error('hold_original_expired');
    }
    state = 'released';
    clearTimeout(timer);
    retain(directory, 'released.json', Buffer.from(JSON.stringify(status())));
    complete();
    return status();
  }

  function close() {
    if (state !== 'held') return;
    state = 'closed_unknown';
    clearTimeout(timer);
    retain(directory, 'closed-unknown.json', Buffer.from(JSON.stringify(status())));
    refuse(new Error('hold_closed_without_dispatch'));
  }

  return { beforeDispatch, status, release, close };
}
