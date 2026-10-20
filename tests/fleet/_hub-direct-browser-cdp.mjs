/**
 * Bounded real-browser observations of the existing AOS management UI.
 *
 * This external browser client grants no authority. Hosted execution requires an
 * existing owner window and actual input files. No raw CDP traffic, credentials,
 * delegated URL queries or request/response bodies are retained.
 */
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CHROME = '/nix/store/bkyw2141s7972xqf6qrd1dnbj6z2jmkd-google-chrome-154.0.8037.57/share/google/chrome/chrome';
const CHROME_SHA = '8cee39073dd1af4d503ee36aa02782fe71b8d9c9f7655c6c0eb9f97f6369b6f9';
const AOS_NODE = '/nix/store/3gjq7k2jpwizjwaynhpdgwl5p4mf7lrz-nodejs-22.22.3/bin/node';
const MAX_FILE = 32 * 1024 * 1024;
const MAX_EVENTS = 4096;
const MAX_REPORT = 2 * 1024 * 1024;
const CLEANUP_RESERVE_MILLIS = 15000;
const CASES = ['login', 'private_page', 'cache_read', 'cache_pause_resume', 'cache_abort_new_run', 'registry_publication', 'logout'];
const WHO_AM_I = '/aos.hub.v1.IdentityService/WhoAmI';

export class BrowserRefusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function requireFact(condition, code) {
  if (!condition) throw new BrowserRefusal(code);
}

function closed(value, fields) {
  requireFact(value && typeof value === 'object' && !Array.isArray(value), 'closed_object');
  requireFact(Object.keys(value).every(key => fields.includes(key)), 'unknown_field');
}

export function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function safeUrl(raw) {
  try {
    const url = new URL(raw);
    return { origin: url.origin, pathSha256: digest(url.pathname), queryPresent: url.search !== '', fragmentPresent: url.hash !== '' };
  } catch {
    return { invalid: true };
  }
}

export function safeHeaders(headers = {}) {
  const result = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (lower === 'etag') result.etagSha256 = digest(String(value));
    if (lower === 'content-length' && /^(0|[1-9][0-9]{0,10})$/.test(String(value))) result.contentLength = String(value);
    if (lower === 'access-control-allow-origin') result.corsOrigin = String(value) === '*' ? '*' : safeUrl(String(value)).origin ?? null;
    if (lower === 'access-control-expose-headers') result.exposesEtag = String(value).split(',').some(field => field.trim().toLowerCase() === 'etag');
  }
  return result;
}

export function safeNetworkEvent(method, event) {
  const id = digest(String(event.requestId ?? ''));
  if (method === 'Network.requestWillBeSent') {
    return { kind: 'request', id, method: /^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$/.test(event.request?.method) ? event.request.method : 'other', url: safeUrl(event.request?.url), redirect: event.redirectResponse ? { status: event.redirectResponse.status, url: safeUrl(event.redirectResponse.url) } : null, timestamp: event.timestamp };
  }
  if (method === 'Network.responseReceived') {
    return { kind: 'response', id, url: safeUrl(event.response?.url), status: event.response?.status, headers: safeHeaders(event.response?.headers), fromDiskCache: event.response?.fromDiskCache === true, fromServiceWorker: event.response?.fromServiceWorker === true, timestamp: event.timestamp };
  }
  if (method === 'Network.loadingFinished') return { kind: 'finished', id, encodedDataLength: event.encodedDataLength, timestamp: event.timestamp };
  if (method === 'Network.loadingFailed') return { kind: 'failed', id, cancelled: event.canceled === true, corsFailure: event.corsErrorStatus !== undefined, timestamp: event.timestamp };
  return null;
}

/** Checks a finite selection without opening files or launching the browser. */
export function validateSelection(value, now = Date.now()) {
  closed(value, ['version', 'scope', 'runId', 'outputDirectory', 'deadlineUnixMillis', 'origin', 'window', 'credentialsFile', 'cases']);
  requireFact(value.version === 1 && ['hosted_aos_browser', 'local_browser_harness'].includes(value.scope), 'selection_scope');
  requireFact(/^[0-9a-f]{32}$/.test(value.runId), 'run_id');
  requireFact(value.outputDirectory === `/tmp/aos-direct-browser-run-${value.runId}`, 'private_output_path');
  requireFact(Number.isSafeInteger(value.deadlineUnixMillis) && value.deadlineUnixMillis > now && value.deadlineUnixMillis <= now + 600000, 'finite_deadline');
  const origin = new URL(value.origin);
  requireFact(origin.origin === value.origin && !origin.username && !origin.password, 'exact_origin');
  if (value.scope === 'hosted_aos_browser') {
    requireFact(origin.protocol === 'https:' && value.window, 'hosted_window');
    requireFact(Array.isArray(value.cases) && value.cases.length > 0 && value.cases.length <= 8, 'finite_cases');
    for (const selected of value.cases) validateCase(selected);
    requireFact(value.cases.filter(selected => selected.kind === 'login').length === 1 && value.cases[0].kind === 'login', 'single_initial_login');
    requireFact(typeof value.credentialsFile === 'string' && path.isAbsolute(value.credentialsFile), 'credentials_reference');
    validateReference(value.window, 4096);
  } else {
    requireFact(origin.protocol === 'http:' && origin.hostname === '127.0.0.1' && value.window === null && value.credentialsFile === null && Array.isArray(value.cases) && value.cases.length === 0, 'local_harness_scope');
  }
  return value;
}

function validateReference(reference, maximum = MAX_FILE) {
  closed(reference, ['file', 'sha256', 'byteSize']);
  requireFact(typeof reference.file === 'string' && path.isAbsolute(reference.file) && reference.file.startsWith('/tmp/'), 'file_path');
  requireFact(/^[0-9a-f]{64}$/.test(reference.sha256) && /^(0|[1-9][0-9]*)$/.test(reference.byteSize) && Number.isSafeInteger(Number(reference.byteSize)) && Number(reference.byteSize) <= maximum, 'file_reference');
}

function validateCase(selected) {
  requireFact(selected && CASES.includes(selected.kind), 'case_kind');
  const fields = {
    login: ['kind', 'privatePath'], private_page: ['kind', 'path'],
    logout: ['kind', 'privatePath'],
    cache_read: ['kind', 'path', 'expectedSha256', 'expectedBytes'],
    cache_pause_resume: ['kind', 'pagePath', 'objectPath', 'source', 'changedSource'],
    cache_abort_new_run: ['kind', 'pagePath', 'objectPath', 'source'],
    registry_publication: ['kind', 'pagePath', 'manifest', 'objects'],
  };
  closed(selected, fields[selected.kind]);
  for (const field of ['privatePath', 'pagePath', 'path']) if (fields[selected.kind].includes(field)) relativeRoute(selected[field]);
  if (selected.kind === 'cache_read') requireFact(/^[0-9a-f]{64}$/.test(selected.expectedSha256) && Number.isSafeInteger(selected.expectedBytes) && selected.expectedBytes >= 0 && selected.expectedBytes <= MAX_FILE, 'bounded_read_expectation');
  if (selected.source) validateReference(selected.source);
  if (selected.kind.startsWith('cache_') && selected.kind !== 'cache_read') requireFact(typeof selected.objectPath === 'string' && selected.objectPath.length <= 1024 && !selected.objectPath.includes('..') && !/[\\?#\x00-\x20]/.test(selected.objectPath), 'object_path');
  if (selected.kind === 'cache_abort_new_run') requireFact(Number(selected.source.byteSize) > 8 * 1024 * 1024, 'multipart_abort_fixture');
  if (selected.kind === 'cache_pause_resume') {
    validateReference(selected.changedSource);
    requireFact(Number(selected.source.byteSize) > 8 * 1024 * 1024 && selected.source.byteSize === selected.changedSource.byteSize && selected.source.sha256 !== selected.changedSource.sha256, 'multipart_changed_source_fixture');
  }
  if (selected.kind === 'registry_publication') {
    validateReference(selected.manifest, 65536);
    requireFact(Array.isArray(selected.objects) && selected.objects.length > 0 && selected.objects.length <= 4, 'bounded_publication_objects');
    const paths = new Set();
    for (const object of selected.objects) {
      closed(object, ['path', 'source']);
      requireFact(typeof object.path === 'string' && object.path.length > 0 && object.path.length <= 1024 && !paths.has(object.path), 'publication_object_path');
      paths.add(object.path);
      validateReference(object.source);
    }
  }
}

async function preflightInputs(selection) {
  if (selection.scope !== 'hosted_aos_browser') return;
  const bytes = await privateBytes(selection.credentialsFile, 4096);
  try {
    const credentials = JSON.parse(bytes);
    closed(credentials, ['email', 'password']);
    requireFact(typeof credentials.email === 'string' && credentials.email.length > 0 && credentials.email.length <= 254 && typeof credentials.password === 'string' && credentials.password.length > 0 && credentials.password.length <= 1024, 'opaque_credentials');
  } finally { bytes.fill(0); }
  for (const selected of selection.cases) {
    for (const field of ['source', 'changedSource']) if (selected[field]) await selectedFile(selected[field]);
    if (selected.manifest) {
      const declaration = JSON.parse(await selectedFile(selected.manifest, 65536));
      selectedManifestBegin(declaration);
      requireFact(declaration.objects.length === selected.objects.length, 'selected_inventory_count');
      for (const object of declaration.objects) {
        const selectedObject = selected.objects.filter(value => value.path === object.path);
        requireFact(selectedObject.length === 1 && selectedObject[0].source.sha256 === object.sha256 && selectedObject[0].source.byteSize === String(object.byteSize), 'selected_inventory_source');
      }
    }
    for (const object of selected.objects ?? []) await selectedFile(object.source);
  }
}

/** Derives only the selected finite declaration's canonical observation bytes. */
export function selectedManifestBegin(declaration) {
  closed(declaration, ['registry', 'generation', 'refsDigest', 'defaultCommit', 'parentPublicationId', 'objects']);
  const text = field => {
    const value = declaration[field] ?? '';
    requireFact(typeof value === 'string' && value.isWellFormed() && value.length <= 1024, 'manifest_field');
    return value;
  };
  requireFact(text('registry') !== '' && text('generation') !== '', 'explicit_manifest_owner');
  requireFact(Array.isArray(declaration.objects) && declaration.objects.length > 0 && declaration.objects.length <= 4, 'finite_manifest_inventory');
  const paths = new Set();
  const tuples = declaration.objects.map(object => {
    closed(object, ['path', 'sha256', 'byteSize', 'kind', 'mediaType']);
    requireFact(typeof object.path === 'string' && object.path.isWellFormed() && object.path.length > 0 && object.path.length <= 1024 && !paths.has(object.path), 'manifest_object_path');
    paths.add(object.path);
    requireFact(/^[0-9a-f]{64}$/.test(object.sha256) && /^(0|[1-9][0-9]*)$/.test(String(object.byteSize)) && Number.isSafeInteger(Number(object.byteSize)) && Number(object.byteSize) <= MAX_FILE, 'manifest_object_source');
    requireFact(['immutable', 'mutable_pointer'].includes(object.kind) && typeof (object.mediaType ?? '') === 'string' && (object.mediaType ?? '').isWellFormed() && Buffer.byteLength(object.mediaType ?? '') <= 255, 'manifest_object_metadata');
    return [object.path, object.sha256, Number(object.byteSize), object.kind, object.mediaType ?? ''];
  });
  // The existing Rust observer hashes sorted UTF-8 object tuples, not wire JSON.
  // Unique paths make path ordering sufficient for that lexicographic order.
  tuples.sort((left, right) => Buffer.compare(Buffer.from(left[0]), Buffer.from(right[0])));
  return {
    registry: text('registry'), generation: text('generation'),
    refsDigest: text('refsDigest'), defaultCommit: text('defaultCommit'),
    parentPublicationId: text('parentPublicationId'),
    manifestDigest: digest(JSON.stringify(tuples)), objectCount: tuples.length,
  };
}

/** Requires the complete selected declaration in an actual retained Begin. */
export function requireSelectedAdmission(rows, declaration) {
  const begin = selectedManifestBegin(declaration);
  const expected = {
    registrySha256: digest(begin.registry), generationSha256: digest(begin.generation),
    refsDigestSha256: digest(begin.refsDigest), defaultCommitSha256: digest(begin.defaultCommit),
    parentPublicationSha256: digest(begin.parentPublicationId),
    manifestDigest: begin.manifestDigest, objectCount: begin.objectCount,
  };
  const matching = rows.filter(row => row.kind === 'publication_admission' && row.publicationSha256 && row.begin && Object.entries(expected).every(([field, value]) => row.begin[field] === value));
  requireFact(matching.length === 1, 'selected_admission_declaration_mismatch');
  return matching;
}

async function privateDirectory(directory) {
  const info = await fs.lstat(directory);
  requireFact(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid() && (info.mode & 0o077) === 0, 'private_directory');
  let parent = path.dirname(directory);
  while (parent !== '/tmp' && parent !== '/') {
    const current = await fs.lstat(parent);
    requireFact(current.isDirectory() && !current.isSymbolicLink() && current.uid === process.getuid() && (current.mode & 0o022) === 0, 'directory_ancestor');
    parent = path.dirname(parent);
  }
  requireFact(parent === '/tmp', 'temporary_private_input');
}

async function privateBytes(file, maximum) {
  requireFact(path.isAbsolute(file), 'absolute_private_file');
  await privateDirectory(path.dirname(file));
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    requireFact(before.isFile() && before.uid === process.getuid() && (before.mode & 0o077) === 0 && before.size <= maximum, 'private_file_custody');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    requireFact(bytes.length === before.size && before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs, 'private_file_changed');
    return bytes;
  } finally {
    await handle.close();
  }
}

async function selectedFile(reference, maximum = MAX_FILE) {
  closed(reference, ['file', 'sha256', 'byteSize']);
  requireFact(/^[0-9a-f]{64}$/.test(reference.sha256) && /^(0|[1-9][0-9]*)$/.test(reference.byteSize), 'file_reference');
  const bytes = await privateBytes(reference.file, maximum);
  requireFact(bytes.length === Number(reference.byteSize) && digest(bytes) === reference.sha256, 'file_hash_or_size');
  return bytes;
}

async function executableIdentity(file) {
  const info = await fs.lstat(file);
  requireFact(info.isFile() && !info.isSymbolicLink() && (info.mode & 0o222) === 0 && (info.mode & 0o111) !== 0, 'immutable_executable');
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  const hash = createHash('sha256');
  try {
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
  } finally {
    await handle.close();
  }
  return { file, sha256: hash.digest('hex'), byteSize: String(info.size) };
}

export function parseProcessStat(raw) {
  const end = raw.lastIndexOf(')');
  requireFact(end > 0, 'process_stat');
  const fields = raw.slice(end + 2).trim().split(/\s+/);
  return { parentPid: Number(fields[1]), processGroup: Number(fields[2]), startTicks: fields[19] };
}

async function processPin(pid) {
  const root = `/proc/${pid}`;
  const before = parseProcessStat(await fs.readFile(`${root}/stat`, 'utf8'));
  const executable = await fs.readlink(`${root}/exe`);
  const owner = await fs.stat(root);
  const commandLine = await fs.readFile(`${root}/cmdline`);
  const namespaces = {};
  for (const name of ['mnt', 'net', 'pid', 'user']) namespaces[name] = await fs.readlink(`${root}/ns/${name}`);
  const after = parseProcessStat(await fs.readFile(`${root}/stat`, 'utf8'));
  for (const name of Object.keys(namespaces)) requireFact(await fs.readlink(`${root}/ns/${name}`) === namespaces[name], 'process_namespace_changed');
  requireFact(before.startTicks === after.startTicks && owner.uid === process.getuid(), 'process_identity_changed');
  return { pid, ...before, ownerUid: owner.uid, executable, namespaces, commandLineSha256: digest(commandLine), commandLineBytes: commandLine.length };
}

async function ownedGroup(pin) {
  const names = await fs.readdir('/proc');
  requireFact(names.length <= 65536, 'process_inventory_bound');
  const members = [];
  for (const name of names.filter(value => /^[1-9][0-9]*$/.test(value))) {
    try {
      const stat = parseProcessStat(await fs.readFile(`/proc/${name}/stat`, 'utf8'));
      if (stat.processGroup !== pin.processGroup) continue;
      const current = await processPin(Number(name));
      requireFact(current.ownerUid === pin.ownerUid && BigInt(current.startTicks) >= BigInt(pin.startTicks), 'browser_group_custody');
      members.push(current);
      requireFact(members.length <= 128, 'browser_group_bound');
    } catch (error) {
      if (!['ENOENT', 'ESRCH'].includes(error.code)) throw error;
    }
  }
  return members;
}

/** Minimal CDP client with bounded messages and per-command deadlines. */
export class CdpClient {
  constructor(socket, deadline, observe = () => {}) {
    this.socket = socket;
    this.deadline = deadline;
    this.observe = observe;
    this.pending = new Map();
    this.nextId = 1;
    this.sessionId = undefined;
    socket.addEventListener('message', event => this.receive(event.data));
    socket.addEventListener('close', () => this.rejectPending('cdp_closed'));
    socket.addEventListener('error', () => this.rejectPending('cdp_error'));
  }

  receive(raw) {
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > MAX_REPORT) {
      this.rejectPending('cdp_message_bound');
      this.socket.close();
      return;
    }
    let message;
    try { message = JSON.parse(raw); } catch { this.rejectPending('cdp_json'); this.socket.close(); return; }
    if (message.id !== undefined) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new BrowserRefusal('cdp_command_refused'));
      else pending.resolve(message.result ?? {});
    } else if (message.sessionId === this.sessionId) {
      this.observe(message.method, message.params ?? {});
    }
  }

  rejectPending(code) {
    this.stopped = true;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new BrowserRefusal(code));
    }
    this.pending.clear();
  }

  call(method, params = {}, browser = false, maximumMillis = 10000) {
    requireFact(!this.stopped && Date.now() < this.deadline && this.pending.size < 16, 'cdp_deadline_or_inflight');
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new BrowserRefusal('cdp_timeout'));
      }, Math.min(maximumMillis, this.deadline - Date.now()));
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.socket.send(JSON.stringify({ id, method, params, ...(browser ? {} : { sessionId: this.sessionId }) }));
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new BrowserRefusal('cdp_send_failed'));
      }
    });
  }

  async evaluate(expression) {
    const reply = await this.call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    requireFact(!reply.exceptionDetails && reply.result?.subtype !== 'error', 'page_evaluation_failed');
    return reply.result?.value;
  }
}

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function waitFor(action, deadline, code) {
  while (Date.now() < deadline) {
    const result = await action();
    if (result) return result;
    await delay(50);
  }
  throw new BrowserRefusal(code);
}

async function connectSocket(url, deadline) {
  requireFact(url.startsWith('ws://127.0.0.1:'), 'loopback_cdp');
  const socket = new WebSocket(url);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.close(); reject(new BrowserRefusal('cdp_connect_timeout')); }, Math.min(10000, deadline - Date.now()));
    socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); reject(new BrowserRefusal('cdp_connect_failed')); }, { once: true });
  });
  return socket;
}

async function windowFence(selection) {
  requireFact(Date.now() < selection.deadlineUnixMillis, 'browser_deadline');
  if (selection.scope !== 'hosted_aos_browser') return;
  const bytes = await selectedFile(selection.window, 4096);
  const value = JSON.parse(bytes);
  closed(value, ['owner', 'startsAt', 'expiresAt']);
  requireFact(/^[0-9a-f]{32}$/.test(value.owner) && Number.isSafeInteger(value.startsAt) && Number.isSafeInteger(value.expiresAt) && value.expiresAt - value.startsAt === 2700, 'original_window');
  const latest = (value.startsAt + 1800) * 1000 - 60000;
  requireFact(Date.now() >= value.startsAt * 1000 && selection.deadlineUnixMillis <= latest && Date.now() < latest, 'cleanup_fence');
  try {
    await fs.lstat(path.join(path.dirname(selection.window.file), 'cleanup-started.json'));
    throw new BrowserRefusal('cleanup_already_started');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

async function jsonOutput(root, name, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  requireFact(bytes.length <= MAX_REPORT && /^[a-z0-9-]+\.json$/.test(name), 'artifact_bound');
  const handle = await fs.open(path.join(root, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(bytes); } finally { await handle.close(); }
  return { file: path.join(root, name), sha256: digest(bytes), byteSize: String(bytes.length) };
}

/** Creates one owned browser lifetime. Only the explicit callback runs actions. */
export async function withBrowser(selected, callback) {
  const selection = validateSelection(selected);
  const actionDeadline = selection.deadlineUnixMillis - CLEANUP_RESERVE_MILLIS;
  requireFact(actionDeadline > Date.now(), 'cleanup_budget_required');
  requireFact(process.execPath === AOS_NODE && process.versions.node === '22.22.3', 'selected_aos_node');
  await windowFence(selection);
  await preflightInputs(selection);
  const nodeIdentity = await executableIdentity(AOS_NODE);
  const identity = await executableIdentity(CHROME);
  requireFact(identity.sha256 === CHROME_SHA && identity.byteSize === '294236248', 'browser_executable_changed');
  await fs.mkdir(selection.outputDirectory, { mode: 0o700 });
  const root = selection.outputDirectory;
  for (const name of ['profile', 'data', 'config', 'cache', 'tmp']) await fs.mkdir(path.join(root, name), { mode: 0o700 });
  const argv = ['--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', `--user-data-dir=${root}/profile`, 'about:blank'];
  const childEnvironment = { PATH: path.dirname(process.execPath), LANG: 'C', LC_ALL: 'C', XDG_DATA_HOME: `${root}/data`, XDG_CONFIG_HOME: `${root}/config`, XDG_CACHE_HOME: `${root}/cache`, TMPDIR: `${root}/tmp` };
  // Preserve HOME when present, but never copy credentials/proxy variables.
  if (process.env.HOME !== undefined) childEnvironment.HOME = process.env.HOME;
  const report = { version: 1, scope: selection.scope, runId: selection.runId, selectionSha256: digest(JSON.stringify(selection)), windowReference: selection.window, node: nodeIdentity, nodeOpenSslVersion: process.versions.openssl, observer: await processPin(process.pid), executable: identity, argv, startedUnixMillis: Date.now(), actionDeadlineUnixMillis: actionDeadline, lifetimeDeadlineUnixMillis: selection.deadlineUnixMillis, cleanupReserveMillis: CLEANUP_RESERVE_MILLIS, events: [], cases: [], complete: false, nativeBulkBytes: null, remoteProviderSettlement: null };
  await jsonOutput(root, 'launch-intent.json', { ...report, cleanup: 'Browser.close, then owned live PID/group SIGTERM/SIGKILL only', deadlineUnixMillis: selection.deadlineUnixMillis });
  requireFact(Date.now() < actionDeadline, 'prelaunch_deadline');
  const child = spawn(CHROME, argv, { cwd: root, env: childEnvironment, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let exited = false;
  let exitCode = null;
  let outputBytes = 0;
  let overflow = false;
  child.on('error', () => { exited = true; });
  child.on('exit', code => { exited = true; exitCode = code; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => { outputBytes += bytes.length; if (outputBytes > 65536) overflow = true; });
  let client;
  let pin;
  let failure;
  const interrupt = () => {
    failure = 'owner_interrupted';
    if (client) { client.rejectPending(failure); client.socket.close(); }
  };
  process.on('SIGINT', interrupt);
  process.on('SIGTERM', interrupt);
  try {
    requireFact(Number.isInteger(child.pid), 'browser_spawn');
    pin = await waitFor(async () => {
      requireFact(!exited && !failure, 'browser_exited_or_interrupted_before_pin');
      try { const actual = await processPin(child.pid); return actual.executable === CHROME ? actual : null; } catch (error) { if (error.code !== 'ENOENT') throw error; return null; }
    }, Math.min(actionDeadline, Date.now() + 3000), 'browser_exec_timeout');
    requireFact(pin.executable === CHROME && pin.processGroup === child.pid, 'browser_launch_identity');
    requireFact(pin.namespaces.net === report.observer.namespaces.net, 'browser_loopback_namespace');
    report.process = pin;
    const active = await waitFor(async () => {
      requireFact(!exited && !overflow && !failure, 'browser_startup_or_output');
      try { return await fs.readFile(`${root}/profile/DevToolsActivePort`, 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; return null; }
    }, Math.min(actionDeadline, Date.now() + 15000), 'browser_ready_timeout');
    const [port, endpoint] = active.trim().split('\n');
    requireFact(/^[0-9]{1,5}$/.test(port) && Number(port) > 0 && Number(port) <= 65535 && /^\/devtools\/browser\/[a-zA-Z0-9-]+$/.test(endpoint), 'cdp_endpoint');
    client = new CdpClient(await connectSocket(`ws://127.0.0.1:${port}${endpoint}`, actionDeadline), actionDeadline, (method, event) => {
      const safe = safeNetworkEvent(method, event);
      if (safe) {
        if (report.events.length >= MAX_EVENTS) { overflow = true; client.rejectPending('event_bound'); client.socket.close(); }
        else report.events.push(safe);
      } else if (method === 'Runtime.exceptionThrown') report.pageExceptions = (report.pageExceptions ?? 0) + 1;
      else if (method === 'Runtime.consoleAPICalled' && event.type === 'error') report.consoleErrors = (report.consoleErrors ?? 0) + 1;
      else if (method === 'Page.loadEventFired') client.pageLoads = (client.pageLoads ?? 0) + 1;
    });
    const browser = await client.call('Browser.getVersion', {}, true);
    requireFact(browser.product === 'Chrome/154.0.8037.57', 'actual_browser_version');
    report.browserVersion = { product: browser.product, protocolVersion: browser.protocolVersion };
    const target = await client.call('Target.createTarget', { url: 'about:blank' }, true);
    const attached = await client.call('Target.attachToTarget', { targetId: target.targetId, flatten: true }, true);
    client.sessionId = attached.sessionId;
    await client.call('Page.enable');
    await client.call('Runtime.enable');
    await client.call('DOM.enable');
    await client.call('Network.enable', { maxTotalBufferSize: 1024 * 1024, maxResourceBufferSize: 65536, maxPostDataSize: 0 });
    requireFact(!failure, 'browser_interrupted');
    await callback({ client, selection: { ...selection, deadlineUnixMillis: actionDeadline }, report, fence: () => { requireFact(!failure && Date.now() < actionDeadline, 'browser_interrupted_or_action_deadline'); return windowFence(selection); } });
    await windowFence(selection);
    requireFact(!overflow && !report.pageExceptions, 'browser_incomplete_or_page_exception');
    report.complete = true;
  } catch (error) {
    failure = error instanceof BrowserRefusal ? error.code : 'browser_operation_failed';
    report.failure = failure;
  } finally {
    let members = [];
    if (pin) {
      try { members = await ownedGroup(pin); report.cleanupPins = members; }
      catch { report.cleanupRefused = true; }
    }
    if (client) {
      client.deadline = selection.deadlineUnixMillis - 1000;
      try { await client.call('Browser.close', {}, true, 1000); } catch { /* Exit may close CDP before its response. */ }
      client.rejectPending('browser_cleanup');
      client.socket.close();
    }
    await waitFor(() => exited, Math.min(Date.now() + 2000, selection.deadlineUnixMillis - 1000), 'graceful_close').catch(() => {});
    for (const signal of ['SIGTERM', 'SIGKILL']) {
      if (exited) break;
      try {
        const current = await processPin(child.pid);
        requireFact(pin && current.startTicks === pin.startTicks && current.ownerUid === pin.ownerUid && current.executable === pin.executable && current.processGroup === pin.processGroup, 'cleanup_process_changed');
        process.kill(-child.pid, signal);
        await waitFor(() => exited, Math.min(Date.now() + 2000, selection.deadlineUnixMillis - 1000), 'cleanup_timeout').catch(() => {});
      } catch { report.cleanupRefused = true; break; }
    }
    // After the main process exits, never signal its former group by number.
    // Any retained member is signalled only after its own PID/start/UID match.
    for (const member of members) {
      try {
        const current = await processPin(member.pid);
        requireFact(current.startTicks === member.startTicks && current.ownerUid === member.ownerUid && current.processGroup === member.processGroup, 'cleanup_member_changed');
        process.kill(member.pid, 'SIGKILL');
      } catch (error) { if (!['ENOENT', 'ESRCH'].includes(error.code)) report.cleanupRefused = true; }
    }
    if (pin) {
      try {
        await waitFor(async () => (await ownedGroup(pin)).length === 0, Math.min(Date.now() + 2000, selection.deadlineUnixMillis - 1000), 'browser_group_not_empty');
        report.ownedBrowserGroupEmpty = true;
      } catch { report.ownedBrowserGroupEmpty = false; }
    }
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    report.finishedUnixMillis = Date.now();
    report.lifetimeWithinDeadline = report.finishedUnixMillis <= selection.deadlineUnixMillis;
    report.browserExitCode = exitCode;
    report.browserExited = exited;
    report.browserOutputBytes = outputBytes;
    report.outputOverflow = overflow;
    report.detachedProcessDrain = null;
    report.complete = report.complete && report.lifetimeWithinDeadline && exited && report.ownedBrowserGroupEmpty === true && !overflow && !report.cleanupRefused && !failure;
    report.receipt = await jsonOutput(root, 'result.json', { ...report });
  }
  if (!report.complete) throw new BrowserRefusal(failure ?? 'browser_cleanup_incomplete');
  return report;
}

function relativeRoute(route) {
  requireFact(typeof route === 'string' && route.startsWith('/') && !route.startsWith('//') && !route.includes('?') && !route.includes('#') && !route.includes('\\'), 'relative_route');
  return route;
}

async function navigate(context, route) {
  await context.fence();
  const target = new URL(relativeRoute(route), context.selection.origin).href;
  const before = context.client.pageLoads ?? 0;
  const navigation = await context.client.call('Page.navigate', { url: target });
  requireFact(!navigation.errorText, 'navigation_failed');
  await waitFor(async () => (!navigation.loaderId || (context.client.pageLoads ?? 0) > before) && await context.client.evaluate(`location.href === ${JSON.stringify(target)} && document.readyState === 'complete'`), context.selection.deadlineUnixMillis, 'navigation_readiness');
}

async function reload(context) {
  await context.fence();
  const before = context.client.pageLoads ?? 0;
  await context.client.call('Page.reload', { ignoreCache: false });
  await waitFor(() => (context.client.pageLoads ?? 0) > before, context.selection.deadlineUnixMillis, 'reload_not_completed');
  await readyAos(context);
}

async function readyAos(context) {
  await waitFor(() => context.client.evaluate(`!!document.querySelector('meta[name="aos-session-csrf"]') && !!document.querySelector('meta[name="aos-app-version"]') && !!document.querySelector('.app-shell')`), context.selection.deadlineUnixMillis, 'aos_ui_readiness');
}

async function clickText(context, text) {
  await context.fence();
  const clicked = await context.client.evaluate(`(() => { const matches = [...document.querySelectorAll('button')].filter(button => button.textContent.trim() === ${JSON.stringify(text)}); if (matches.length !== 1 || matches[0].disabled) return false; matches[0].click(); return true; })()`);
  requireFact(clicked === true, 'actual_button_unavailable');
}

async function fill(context, selector, value) {
  await context.fence();
  const filled = await context.client.evaluate(`(() => { const nodes = document.querySelectorAll(${JSON.stringify(selector)}); if (nodes.length !== 1 || nodes[0].disabled) return false; const node = nodes[0]; const setter = Object.getOwnPropertyDescriptor(node.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype, 'value').set; setter.call(node, ${JSON.stringify(value)}); node.dispatchEvent(new Event('input', { bubbles: true })); node.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
  requireFact(filled === true, 'actual_input_unavailable');
}

async function selectFile(context, reference, cardPath = null) {
  await selectedFile(reference);
  await context.fence();
  const marker = `aos-browser-${randomBytes(12).toString('hex')}`;
  const marked = await context.client.evaluate(`(() => { let nodes = [...document.querySelectorAll('input[type="file"]')]; ${cardPath === null ? '' : `nodes = nodes.filter(node => [...node.closest('article.revision-card')?.querySelectorAll('strong') ?? []].some(value => value.textContent === ${JSON.stringify(cardPath)}));`} if (nodes.length !== 1 || nodes[0].disabled) return false; nodes[0].setAttribute('data-browser-selection', ${JSON.stringify(marker)}); return true; })()`);
  requireFact(marked === true, 'actual_file_input_unavailable');
  const document = await context.client.call('DOM.getDocument');
  const node = await context.client.call('DOM.querySelector', { nodeId: document.root.nodeId, selector: `[data-browser-selection="${marker}"]` });
  requireFact(node.nodeId > 0, 'file_input_node');
  await context.client.call('DOM.setFileInputFiles', { nodeId: node.nodeId, files: [reference.file] });
  await selectedFile(reference);
}

/** Reads only bounded summaries of the actual AOS IndexedDB checkpoint store. */
export async function summarizeCheckpoints(rows, hash) {
  if (!Array.isArray(rows) || rows.length > 128) throw new Error('checkpoint_bound');
  const parsed = rows.map(([key, raw]) => {
    if (typeof key !== 'string' || typeof raw !== 'string' || new TextEncoder().encode(raw).length > 65536) throw new Error('checkpoint_bound');
    return { key, raw, value: JSON.parse(raw) };
  });
  const heads = parsed.filter(row => row.value.intent && typeof row.value.scope === 'string' && typeof row.value.runNonce === 'string');
  return Promise.all(parsed.map(async ({ key, raw, value }) => {
    const base = { keySha256: await hash(key), recordSha256: await hash(raw), active: key.endsWith(':active'), retired: key.endsWith(':retired'), bytes: new TextEncoder().encode(raw).length };
    const original = head => JSON.stringify({ scope: head.scope, runNonce: head.runNonce, deploymentId: head.deploymentId, principalId: head.principalId, intent: head.intent });
    if (heads.some(row => row.key === key)) {
      const target = value.intent.target;
      return { ...base, kind: 'upload_head', originalSha256: await hash(original(value)), runSha256: await hash(value.runNonce), sourceSha256: value.intent.expectedSha256, sourceBytes: value.intent.byteSize, targetSha256: await hash(JSON.stringify(target)), targetKind: ['cache_object', 'publication_object', 'oci_blob'].includes(target?.kind) ? target.kind : null, targetPathSha256: typeof target?.path === 'string' ? await hash(target.path) : null, publicationSha256: typeof target?.publicationId === 'string' ? await hash(target.publicationId) : null, state: value.session?.state ?? null, sessionSha256: value.session?.session ? await hash(JSON.stringify(value.session.session)) : null };
    }
    if (/^publication-admission:[0-9a-f]{64}$/.test(key) && value.begin && typeof value.deployment === 'string' && typeof value.principal === 'string') {
      const begin = {
        registrySha256: await hash(value.begin.registry ?? ''),
        generationSha256: await hash(value.begin.generation ?? ''),
        refsDigestSha256: await hash(value.begin.refsDigest ?? ''),
        defaultCommitSha256: await hash(value.begin.defaultCommit ?? ''),
        parentPublicationSha256: await hash(value.begin.parentPublicationId ?? ''),
        manifestDigest: value.begin.manifestDigest ?? '', objectCount: value.begin.objectCount ?? 0,
      };
      return { ...base, kind: 'publication_admission', originalSha256: await hash(JSON.stringify({ deployment: value.deployment, principal: value.principal, begin: value.begin })), begin, publicationSha256: value.publicationId ? await hash(String(value.publicationId)) : null };
    }
    const owners = heads.filter(row => key.startsWith(`${row.value.scope}:${row.value.runNonce}:`) && !key.endsWith(':retired'));
    const owner = owners.length === 1 ? owners[0].value : null;
    return { ...base, kind: value.original ? 'upload_part' : 'other', originalSha256: owner ? await hash(original(owner)) : null, partNumber: value.original?.number ?? null, sourceSha256: value.original?.sha256 ?? null, receipt: value.receipt !== null && value.receipt !== undefined, serverObserved: value.serverObserved !== null && value.serverObserved !== undefined };
  }));
}

export async function checkpointSnapshot(context) {
  return context.client.evaluate(`(async () => {
    const hash = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map(byte => byte.toString(16).padStart(2, '0')).join('');
    const databases = await indexedDB.databases();
    if (!databases.some(value => value.name === 'aos-direct-upload-resume-v1')) return [];
    const database = await new Promise((resolve, reject) => { const request = indexedDB.open('aos-direct-upload-resume-v1'); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(new Error('checkpoint')); });
    try {
      const rows = await new Promise((resolve, reject) => { const transaction = database.transaction('records', 'readonly'); const result = []; const cursor = transaction.objectStore('records').openCursor(); cursor.onerror = () => reject(new Error('checkpoint')); cursor.onsuccess = () => { const current = cursor.result; if (!current) return; if (result.length >= 128 || typeof current.value !== 'string' || new TextEncoder().encode(current.value).length > 65536) { transaction.abort(); return; } result.push([String(current.key), current.value]); current.continue(); }; transaction.oncomplete = () => resolve(result); transaction.onabort = transaction.onerror = () => reject(new Error('checkpoint')); });
      return (${summarizeCheckpoints.toString()})(rows, hash);
    } finally { database.close(); }
  })()`);
}

function activeOriginal(snapshot, source, objectPath) {
  const rows = snapshot.filter(row => row.active && row.targetKind === 'cache_object' && row.targetPathSha256 === digest(objectPath) && row.sourceSha256 === source.sha256 && String(row.sourceBytes) === source.byteSize);
  requireFact(rows.length === 1, 'actual_original_ambiguous');
  return rows[0];
}

export function requireSameOriginal(before, after) {
  requireFact(before.originalSha256 === after.originalSha256 && before.runSha256 === after.runSha256 && before.sessionSha256 === after.sessionSha256 && before.sourceSha256 === after.sourceSha256 && before.sourceBytes === after.sourceBytes, 'original_changed');
}

/** Requires a new server session and unchanged positively aborted history. */
export function requireDistinctNewRun(initial, next, rows) {
  const old = rows.filter(row => row.kind === 'upload_head' && row.retired && row.originalSha256 === initial.originalSha256);
  requireFact(old.length === 1 && old[0].state === 'aborted', 'old_aborted_history_missing');
  requireSameOriginal(initial, old[0]);
  requireFact(next.runSha256 !== initial.runSha256 && next.originalSha256 !== initial.originalSha256 && next.sessionSha256 && next.sessionSha256 !== initial.sessionSha256 && next.targetSha256 === initial.targetSha256 && next.sourceSha256 === initial.sourceSha256 && next.sourceBytes === initial.sourceBytes, 'new_run_reused_original_or_session');
}

async function cacheStart(context, selected) {
  await navigate(context, selected.pagePath);
  await readyAos(context);
  await expandCache(context);
  await fill(context, 'input[placeholder="nar/<hash>.nar.zst or <store-hash>.narinfo"]', selected.objectPath);
  await selectFile(context, selected.source);
}

async function expandCache(context) {
  const expanded = await context.client.evaluate(`(() => { const matches = [...document.querySelectorAll('summary')].filter(node => node.textContent.trim() === 'Upload a cache object'); if (matches.length !== 1) return false; matches[0].parentElement.open = true; return true; })()`);
  requireFact(expanded, 'actual_cache_form_unavailable');
}

async function cachedHead(context, selected, predicate, original = null) {
  return waitFor(async () => {
    await context.fence();
    const rows = await checkpointSnapshot(context);
    const matching = rows.filter(row => (row.active || row.retired) && row.targetKind === 'cache_object' && row.targetPathSha256 === digest(selected.objectPath) && row.sourceSha256 === selected.source.sha256 && String(row.sourceBytes) === selected.source.byteSize && row.sessionSha256 && (!original || row.originalSha256 === original.originalSha256) && predicate(row, rows));
    if (matching.length !== 1) return null;
    return { head: matching[0], rows };
  }, context.selection.deadlineUnixMillis, 'actual_checkpoint_unavailable');
}

async function runCase(context, selected) {
  const { client } = context;
  await context.fence();
  const result = { kind: selected.kind, selectedCaseSha256: digest(JSON.stringify(selected)), startedUnixMillis: Date.now() };
  if (selected.kind === 'login') {
    closed(selected, ['kind', 'privatePath']);
    const bytes = await privateBytes(context.selection.credentialsFile, 4096);
    const credentials = JSON.parse(bytes);
    closed(credentials, ['email', 'password']);
    requireFact(typeof credentials.email === 'string' && credentials.email.length <= 254 && typeof credentials.password === 'string' && credentials.password.length > 0 && credentials.password.length <= 1024, 'opaque_credentials');
    await navigate(context, '/login');
    await fill(context, 'form[action="/login/password"] input[name="email"]', credentials.email);
    await fill(context, 'form[action="/login/password"] input[name="password"]', credentials.password);
    await clickText(context, 'sign in with password');
    credentials.email = '';
    credentials.password = '';
    bytes.fill(0);
    await waitFor(() => client.evaluate(`location.origin === ${JSON.stringify(context.selection.origin)} && location.pathname !== '/login' && document.readyState === 'complete'`), context.selection.deadlineUnixMillis, 'login_did_not_complete');
    await navigate(context, selected.privatePath);
    await readyAos(context);
    result.actualPrivateUiLoaded = true;
  } else if (selected.kind === 'private_page') {
    closed(selected, ['kind', 'path']);
    await navigate(context, selected.path);
    await readyAos(context);
    result.actualPrivateUiLoaded = true;
  } else if (selected.kind === 'cache_read') {
    closed(selected, ['kind', 'path', 'expectedSha256', 'expectedBytes']);
    requireFact(/^[0-9a-f]{64}$/.test(selected.expectedSha256) && Number.isSafeInteger(selected.expectedBytes) && selected.expectedBytes >= 0 && selected.expectedBytes <= MAX_FILE, 'bounded_read_expectation');
    const route = relativeRoute(selected.path);
    result.reads = [];
    for (let index = 0; index < 2; index++) {
      const read = await client.evaluate(`(async () => { const response = await fetch(${JSON.stringify(route)}, { credentials: 'same-origin', cache: 'default' }); const reader = response.body?.getReader(); if (!reader) throw new Error('read'); const chunks = []; let count = 0; for (;;) { const next = await reader.read(); if (next.done) break; count += next.value.byteLength; if (count > ${MAX_FILE}) { await reader.cancel(); throw new Error('bound'); } chunks.push(next.value); } const joined = new Uint8Array(count); let offset = 0; for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.length; } const sha256 = [...new Uint8Array(await crypto.subtle.digest('SHA-256', joined))].map(byte => byte.toString(16).padStart(2, '0')).join(''); const etag = response.headers.get('etag'); return { status: response.status, bytes: count, sha256, etagSha256: etag === null ? null : [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(etag)))].map(byte => byte.toString(16).padStart(2, '0')).join('') }; })()`);
      requireFact(read.status === 200 && read.sha256 === selected.expectedSha256 && read.bytes === selected.expectedBytes, 'actual_cache_read_mismatch');
      result.reads.push(read);
    }
    requireFact(result.reads[0].etagSha256 !== null && result.reads[0].etagSha256 === result.reads[1].etagSha256, 'actual_etag_missing_or_changed');
    result.cacheMechanism = 'Actual CDP cache flags retained separately; two matching reads alone do not prove a cache hit';
  } else if (selected.kind === 'cache_pause_resume') {
    closed(selected, ['kind', 'pagePath', 'objectPath', 'source', 'changedSource']);
    await selectedFile(selected.source);
    await selectedFile(selected.changedSource);
    requireFact(Number(selected.source.byteSize) > 8 * 1024 * 1024 && selected.source.byteSize === selected.changedSource.byteSize && selected.source.sha256 !== selected.changedSource.sha256, 'multipart_changed_source_fixture');
    await cacheStart(context, selected);
    const initial = await cachedHead(context, selected, (head, rows) => head.active && head.state === 'active' && rows.some(row => row.kind === 'upload_part' && row.originalSha256 === head.originalSha256 && row.serverObserved));
    await waitFor(() => client.evaluate(`[...document.querySelectorAll('button')].some(node => node.textContent.trim() === 'Pause transfer' && !node.disabled)`), context.selection.deadlineUnixMillis, 'pause_not_reached');
    await clickText(context, 'Pause transfer');
    await waitFor(() => client.evaluate(`[...document.querySelectorAll('button')].some(node => node.textContent.trim() === 'Check saved upload' && !node.disabled)`), context.selection.deadlineUnixMillis, 'pause_did_not_settle');
    const paused = await checkpointSnapshot(context);
    requireSameOriginal(initial.head, activeOriginal(paused, selected.source, selected.objectPath));
    await reload(context);
    await expandCache(context);
    await fill(context, 'input[placeholder="nar/<hash>.nar.zst or <store-hash>.narinfo"]', selected.objectPath);
    await clickText(context, 'Check saved upload');
    await waitFor(() => client.evaluate(`[...document.querySelectorAll('button')].some(node => node.textContent.trim() === 'Check saved upload' && !node.disabled)`), context.selection.deadlineUnixMillis, 'original_check_not_settled');
    const restarted = await checkpointSnapshot(context);
    requireSameOriginal(initial.head, activeOriginal(restarted, selected.source, selected.objectPath));
    await selectFile(context, selected.changedSource);
    await waitFor(() => client.evaluate(`[...document.querySelectorAll('.inline-error[role="alert"]')].some(node => node.textContent.includes('This path has a retained upload for another source or identity'))`), context.selection.deadlineUnixMillis, 'changed_source_not_refused');
    requireSameOriginal(initial.head, activeOriginal(await checkpointSnapshot(context), selected.source, selected.objectPath));
    await selectFile(context, selected.source);
    const completed = await cachedHead(context, selected, head => head.state === 'committed', initial.head);
    requireSameOriginal(initial.head, completed.head);
    result.checkpoints = { initial, paused, restarted, completed };
    result.changedSourceRefused = true;
  } else if (selected.kind === 'cache_abort_new_run') {
    closed(selected, ['kind', 'pagePath', 'objectPath', 'source']);
    await cacheStart(context, selected);
    const initial = await cachedHead(context, selected, head => head.active && head.state === 'active');
    await clickText(context, 'Stop original upload');
    const aborted = await cachedHead(context, selected, head => head.active && head.state === 'aborted', initial.head);
    requireSameOriginal(initial.head, aborted.head);
    await waitFor(() => client.evaluate(`[...document.querySelectorAll('button')].some(node => node.textContent.trim() === 'Start a new upload' && !node.disabled)`), context.selection.deadlineUnixMillis, 'retirement_not_available');
    await clickText(context, 'Start a new upload');
    const retired = await waitFor(async () => { const rows = await checkpointSnapshot(context); return !rows.some(row => row.keySha256 === initial.head.keySha256 && row.active) && rows.some(row => row.retired && row.originalSha256 === initial.head.originalSha256) ? rows : null; }, context.selection.deadlineUnixMillis, 'terminal_history_not_retained');
    await selectFile(context, selected.source);
    const next = await cachedHead(context, selected, head => head.active && head.state === 'active');
    requireDistinctNewRun(initial.head, next.head, next.rows);
    await clickText(context, 'Stop original upload');
    const nextAborted = await cachedHead(context, selected, head => head.active && head.state === 'aborted', next.head);
    requireSameOriginal(next.head, nextAborted.head);
    requireDistinctNewRun(initial.head, nextAborted.head, nextAborted.rows);
    result.checkpoints = { initial, aborted, retired, next, nextAborted };
    result.remoteProviderSettlement = null;
  } else if (selected.kind === 'registry_publication') {
    closed(selected, ['kind', 'pagePath', 'manifest', 'objects']);
    const manifest = await selectedFile(selected.manifest, 65536);
    requireFact(Array.isArray(selected.objects) && selected.objects.length > 0 && selected.objects.length <= 4, 'bounded_publication_objects');
    for (const object of selected.objects) { closed(object, ['path', 'source']); await selectedFile(object.source); }
    await navigate(context, selected.pagePath);
    await readyAos(context);
    const expanded = await client.evaluate(`(() => { const summaries = [...document.querySelectorAll('summary')].filter(node => node.textContent.trim() === 'Advanced: begin a publication from a manifest'); if (summaries.length !== 1) return false; summaries[0].parentElement.open = true; return true; })()`);
    requireFact(expanded, 'actual_manifest_form_unavailable');
    await fill(context, 'textarea', manifest.toString('utf8'));
    await clickText(context, 'Begin or resume publication');
    await waitFor(() => client.evaluate(`!!document.querySelector('article.revision-card input[type="file"]')`), context.selection.deadlineUnixMillis, 'actual_publication_not_loaded');
    const declaration = JSON.parse(manifest);
    const admission = rows => requireSelectedAdmission(rows, declaration);
    result.admissionCheckpoint = admission(await checkpointSnapshot(context));
    requireFact(result.admissionCheckpoint.length === 1, 'actual_admission_checkpoint_missing');
    await reload(context);
    // Re-submit the same retained metadata declaration through the actual UI.
    const resumedExpanded = await client.evaluate(`(() => { const summaries = [...document.querySelectorAll('summary')].filter(node => node.textContent.trim() === 'Advanced: begin a publication from a manifest'); if (summaries.length !== 1) return false; summaries[0].parentElement.open = true; return true; })()`);
    requireFact(resumedExpanded, 'actual_manifest_resume_form_unavailable');
    await fill(context, 'textarea', manifest.toString('utf8'));
    await clickText(context, 'Begin or resume publication');
    await waitFor(() => client.evaluate(`!!document.querySelector('article.revision-card input[type="file"]')`), context.selection.deadlineUnixMillis, 'actual_publication_resume_not_loaded');
    result.resumedAdmission = admission(await checkpointSnapshot(context));
    requireFact(result.resumedAdmission.length === 1 && result.resumedAdmission[0].originalSha256 === result.admissionCheckpoint[0].originalSha256 && result.resumedAdmission[0].publicationSha256 === result.admissionCheckpoint[0].publicationSha256, 'publication_original_changed');
    result.directObjects = [];
    for (const object of selected.objects) {
      await selectFile(context, object.source, object.path);
      await waitFor(() => client.evaluate(`(() => { const cards = [...document.querySelectorAll('article.revision-card')].filter(card => [...card.querySelectorAll('strong')].some(node => node.textContent === ${JSON.stringify(object.path)})); return cards.length === 1 && cards[0].textContent.includes('Verified on every required placement'); })()`), context.selection.deadlineUnixMillis, 'actual_publication_object_not_verified');
      const direct = (await checkpointSnapshot(context)).filter(row => row.kind === 'upload_head' && row.targetKind === 'publication_object' && row.publicationSha256 === result.admissionCheckpoint[0].publicationSha256 && row.targetPathSha256 === digest(object.path) && row.sourceSha256 === object.source.sha256 && String(row.sourceBytes) === object.source.byteSize && row.sessionSha256 && row.state === 'committed');
      requireFact(direct.length === 1, 'actual_publication_direct_original_missing');
      result.directObjects.push(direct[0]);
    }
    result.finalCheckpoint = await checkpointSnapshot(context);
    result.visibilityCommitted = false;
    result.scope = 'Actual original publication admission and declared object upload; no automatic visibility commit';
  } else if (selected.kind === 'logout') {
    closed(selected, ['kind', 'privatePath']);
    await navigate(context, '/logout');
    await clickText(context, 'log out');
    await waitFor(() => client.evaluate(`location.pathname === '/login'`), context.selection.deadlineUnixMillis, 'logout_did_not_complete');
    const before = client.pageLoads ?? 0;
    await client.call('Page.navigate', { url: new URL(relativeRoute(selected.privatePath), context.selection.origin).href });
    await waitFor(async () => (client.pageLoads ?? 0) > before && await client.evaluate(`location.origin === ${JSON.stringify(context.selection.origin)} && location.pathname === '/login' && document.readyState === 'complete'`), context.selection.deadlineUnixMillis, 'private_page_not_refused_after_logout');
    requireFact(context.report.events.some(row => row.kind === 'request' && row.url.origin === context.selection.origin && row.url.pathSha256 === digest(selected.privatePath)), 'private_page_request_not_observed');
    result.actualPrivatePageRefused = true;
  }
  result.finishedUnixMillis = Date.now();
  context.report.cases.push(result);
}

/** Runs only the selected existing AOS UI cases; never a local AOS simulation. */
export async function runAosSelection(selection) {
  requireFact(selection.scope === 'hosted_aos_browser', 'aos_scope_required');
  return withBrowser(selection, async context => {
    for (const selected of selection.cases) await runCase(context, selected);
    const response = context.report.events.some(event => event.kind === 'response' && event.url.origin === selection.origin && event.url.pathSha256 === digest(WHO_AM_I) && event.status === 200);
    if (selection.cases.some(value => ['cache_pause_resume', 'cache_abort_new_run', 'registry_publication'].includes(value.kind))) requireFact(response, 'actual_authenticated_whoami_missing');
    context.report.whoAmIObserved200 = response;
    context.report.providerPutResponses = context.report.events.filter(event => event.kind === 'response' && event.url.origin !== selection.origin && context.report.events.some(request => request.kind === 'request' && request.id === event.id && request.method === 'PUT')).map(event => ({ id: event.id, status: event.status, etagSha256: event.headers.etagSha256 ?? null, exposesEtag: event.headers.exposesEtag === true }));
    context.report.corsFailures = context.report.events.filter(event => event.kind === 'failed' && event.corsFailure).length;
    requireFact(context.report.corsFailures === 0, 'actual_browser_cors_refusal');
    context.report.actualNativeConsumedBytes = null;
    context.report.fullDirectQualification = false;
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try {
    requireFact(process.argv.length === 4 && process.argv[2] === '--selection', 'explicit_selection_argument');
    const selection = JSON.parse(await privateBytes(process.argv[3], 65536));
    const report = await runAosSelection(selection);
    process.stdout.write(`${JSON.stringify({ scope: report.scope, complete: report.complete, receipt: report.receipt, fullDirectQualification: false })}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ complete: false, refusal: error instanceof BrowserRefusal ? error.code : 'selection_or_browser_failed' })}\n`);
    process.exitCode = 1;
  }
}
