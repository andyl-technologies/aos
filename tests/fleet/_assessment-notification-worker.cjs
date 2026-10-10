// Runs production callback WASM and real durable attempt storage. The paired
// coordinator and egress gateway are protocol fixtures; this suite qualifies
// physical execution and replay, independently of public service IAM admission.
const assert = require('node:assert/strict');
const { createHash, createHmac, randomBytes } = require('node:crypto');
const { createRequire } = require('node:module');
const path = require('node:path');

const WORK = '/internal/assessment/notification-work/v1';
const EFFECT = '/internal/assessment/notification-effect/v1';
const HEADER = 'x-aos-assessment-notification-signature';
const CONTRACT = 'aos-hardened-egress-assessment-notification-v1';
const KEY = 'independent-notification-fleet-work-key-v1';
const CALLBACK_KEY = 'independent-notification-fleet-callback-key-v1';
const GATEWAY_KEY = Buffer.alloc(32, 19);
const DEPLOYMENT = 'assessment-fleet';
const ISSUER = 'coordinator';
const AUDIENCE = 'executor';
const SCOPE = 'fixture-partition';
const CALLBACK = 'https://receiver.example/callback';
const VERSION = 'worker://assessment/notification/v1';

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function semantic(domain, value) {
  return digest(Buffer.concat([Buffer.from(`${domain}\0`), Buffer.from(canonical(value))]));
}

function u64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function frame(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u64(bytes.length), bytes]);
}

function signature(domain, route, body) {
  return createHmac('sha256', KEY).update(Buffer.concat(
    [domain, 'POST', route, DEPLOYMENT, ISSUER, AUDIENCE, body].map(frame),
  )).digest('hex');
}

function timestamp(seconds) {
  return new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
}

function now() { return Math.floor(Date.now() / 1000); }
function random() { return randomBytes(24).toString('hex'); }

const destination = {
  schema: 'aos.assessment-notification-destination/v1', destinationReference: 'webhook:1',
  revision: 1, resourceScope: SCOPE, url: CALLBACK, secretVersionReference: VERSION,
  credentialFingerprint: digest(CALLBACK_KEY), expiresAt: timestamp(now() + 3600),
};

function plan() {
  const issuedAt = timestamp(now());
  const body = {
    schema: 'aos.assessment-notification-body/v1', deliveryId: random(), resourceScope: SCOPE,
    subscriptionId: 'subscription', subscriptionRevision: 1,
    events: [{ eventId: random(), sequence: '1', occurredAt: issuedAt,
      kind: 'scan-completed', uncertain: false, assessmentDigest: digest('assessment') }],
  };
  return {
    schema: 'aos.assessment-notification-work/v1', deploymentId: DEPLOYMENT,
    issuer: ISSUER, audience: AUDIENCE, claimToken: random(), attempt: 1,
    reservationDigest: digest(random()), destinationReference: destination.destinationReference,
    destinationDigest: semantic('aos.assessment-notification-destination/v1', destination),
    body, bodyDigest: semantic('aos.assessment-notification-body/v1', body),
    issuedAt, deadline: timestamp(now() + 60),
  };
}

async function dispatch(runtime, plan, supplied) {
  const body = canonical(plan);
  return runtime.dispatchFetch(`https://assessment-fleet.invalid${WORK}`, {
    method: 'POST', body, headers: {
      'content-type': 'application/json',
      [HEADER]: supplied ?? signature('aos-assessment-notification-plan-v1', WORK, body),
    },
  });
}

async function receipt(response, expectedPlan) {
  const body = await response.text();
  assert.equal(response.status, 200, body);
  assert.equal(response.headers.get(HEADER), signature('aos-assessment-notification-receipt-v1', WORK, body));
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.ok(Buffer.byteLength(body) <= 4096);
  assert.ok(!body.includes(CALLBACK_KEY) && !body.includes(KEY));
  const document = JSON.parse(body);
  assert.equal(document.planDigest, semantic('aos.assessment-notification-work/v1', expectedPlan));
  assert.equal(document.bodyDigest, expectedPlan.bodyDigest);
  assert.equal(document.claimToken, expectedPlan.claimToken);
  return { body, document };
}

function gatewayRequestBytes(headers) {
  const required = name => { const value = headers.get(name); assert.ok(value); return value; };
  const optional = name => {
    const value = headers.get(name);
    return value === null ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), frame(value)]);
  };
  const original = Buffer.concat([
    Buffer.from('aos-hardened-egress-request-v3\0'), u64(required('x-aos-egress-timestamp')),
    ...['nonce', 'target-url', 'upstream-method', 'body-sha256'].map(name => frame(required(`x-aos-egress-${name}`))),
    ...['content-type', 'range', 'if-match', 'authorization', 'webhook-event', 'webhook-signature',
      'webhook-delivery-id'].map(name => optional(`x-aos-egress-upstream-${name}`)),
  ]);
  return Buffer.concat([
    Buffer.from('aos-hardened-egress-notification-request-v1\0'), u64(original.length), original,
    ...['signature-version', 'key-version', 'timestamp'].map(name => frame(required(`x-aos-egress-notification-${name}`))),
    ...['deadline', 'effect-checked-at', 'effect-dispatch-by'].map(name => u64(required(`x-aos-egress-notification-${name}`))),
  ]);
}

async function main() {
  const [toolingRoot, scriptPath, statePath] = process.argv.slice(2);
  assert.ok(toolingRoot && scriptPath && statePath);
  const load = createRequire(path.join(toolingRoot, 'lib/node_modules/wrangler/node_modules/fleet-runner.cjs'));
  const { Miniflare, Response } = load('miniflare');
  const plans = new Map();
  const planConfirmations = new Map();
  let confirmations = 0;
  let gatewayCalls = 0;
  let disposition = 'allowed';
  let status = 204;
  let tamperGateway = false;
  let expectedBody;
  const outboundService = async request => {
    assert.equal(request.method, 'POST');
    if (request.url === `https://coordinator.example${EFFECT}`) {
      confirmations += 1;
      const body = await request.text();
      assert.equal(request.headers.get(HEADER), signature('aos-assessment-notification-effect-query-v1', EFFECT, body));
      const query = JSON.parse(body);
      const plan = plans.get(query.planDigest);
      assert.ok(plan);
      assert.equal(query.resourceScope, SCOPE);
      assert.equal(query.claimToken, plan.claimToken);
      assert.ok(!body.includes('events') && !body.includes(CALLBACK_KEY));
      const count = (planConfirmations.get(query.planDigest) ?? 0) + 1;
      planConfirmations.set(query.planDigest, count);
      if (disposition === 'revoked' || (disposition === 'revoked-after-sign' && count > 1)) {
        return new Response('refused', { status: 409 });
      }
      const checkedAt = now() - (disposition === 'stale' ? 10 : 0);
      const grant = {
        schema: 'aos.assessment-notification-effect-grant/v1',
        queryDigest: semantic('aos.assessment-notification-effect-query/v1', query),
        planDigest: query.planDigest, claimToken: query.claimToken,
        nonce: disposition === 'nonce' ? random() : query.nonce,
        checkedAt: timestamp(checkedAt), dispatchBy: timestamp(checkedAt + 5), planDeadline: plan.deadline,
      };
      const bytes = canonical(grant);
      return new Response(bytes, { headers: {
        'content-type': 'application/json', [HEADER]: signature('aos-assessment-notification-effect-grant-v1', EFFECT, bytes),
      } });
    }
    assert.equal(request.url, 'https://egress.example/v1/fetch');
    gatewayCalls += 1;
    const headers = request.headers;
    assert.equal(headers.get('x-aos-egress-contract'), CONTRACT);
    assert.equal(headers.get('x-aos-egress-upstream-authorization'), null);
    assert.equal(headers.get('x-aos-egress-target-url'), CALLBACK);
    assert.equal(headers.get('x-aos-egress-notification-key-version'), VERSION);
    const body = await request.text();
    assert.equal(body, expectedBody);
    assert.equal(headers.get('x-aos-egress-body-sha256'), digest(body).slice(7));
    const expectedMAC = createHmac('sha256', GATEWAY_KEY).update(gatewayRequestBytes(headers)).digest('base64url');
    assert.equal(headers.get('x-aos-egress-signature'), expectedMAC);
    const callbackMAC = createHmac('sha256', CALLBACK_KEY).update(Buffer.concat([
      'aos-assessment-callback-v1', headers.get('x-aos-egress-notification-signature-version'),
      VERSION, headers.get('x-aos-egress-notification-timestamp'),
      headers.get('x-aos-egress-upstream-webhook-delivery-id'), body,
    ].map(frame))).digest('hex');
    assert.equal(headers.get('x-aos-egress-upstream-webhook-signature'), `sha256=${callbackMAC}`);
    assert.ok(now() < Number(headers.get('x-aos-egress-notification-effect-dispatch-by')));
    const nonce = headers.get('x-aos-egress-nonce');
    const time = now();
    const retry = status === 429 ? 30 : null;
    const statusBytes = Buffer.alloc(2); statusBytes.writeUInt16BE(status);
    const retryBytes = Buffer.alloc(retry === null ? 1 : 5);
    if (retry !== null) { retryBytes[0] = 1; retryBytes.writeUInt32BE(retry, 1); }
    const encoded = Buffer.concat([Buffer.from('aos-hardened-egress-notification-response-v1\0'),
      u64(time), frame(nonce), frame(CALLBACK), frame('8.8.8.8'), statusBytes, retryBytes]);
    const mac = createHmac('sha256', GATEWAY_KEY).update(encoded).digest('base64url');
    const facts = {
      'x-aos-egress-contract': CONTRACT, 'x-aos-egress-key-id': 'callback-gateway',
      'x-aos-egress-timestamp': String(time), 'x-aos-egress-nonce': nonce,
      'x-aos-egress-final-url': CALLBACK, 'x-aos-egress-peer-ip': '8.8.8.8',
      'x-aos-egress-upstream-status': String(status), 'x-aos-egress-signature': tamperGateway ? 'A'.repeat(43) : mac,
    };
    if (retry !== null) facts['x-aos-egress-notification-retry-after'] = String(retry);
    return new Response(status === 204 ? null : 'response-body-must-never-be-retained'.repeat(65536),
      { status, headers: facts });
  };
  const options = {
    name: 'assessment-notification-fleet', scriptPath, modules: true,
    modulesRoot: path.dirname(scriptPath), modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
    compatibilityDate: '2024-09-23', compatibilityFlags: ['enable_request_signal'], cf: false,
    outboundService, resourcePersistencePath: statePath,
    durableObjects: { ASSESSMENT_NOTIFICATION_TASKS: { className: 'AssessmentNotificationObject' } },
    bindings: {
      HUB_RUNTIME_ROLE: 'hub_executor', HUB_TOPOLOGY: 'hybrid', HUB_HYBRID_ORIGIN_URL: 'https://coordinator.example/',
      HUB_DEPLOYMENT_ID: DEPLOYMENT, HUB_ASSESSMENT_NOTIFICATION_COORDINATOR_ID: ISSUER,
      HUB_ASSESSMENT_NOTIFICATION_EXECUTOR_ID: AUDIENCE,
      HUB_ASSESSMENT_NOTIFICATION_WORK_KEY: KEY,
      HUB_EGRESS_GATEWAY_KEY: `callback-gateway:${GATEWAY_KEY.toString('hex')}`,
      ASSESSMENT_NOTIFICATION_CALLBACK_V1: CALLBACK_KEY,
      HUB_ASSESSMENT_NOTIFICATION_CONFIG: canonical({
        schema: 'aos.assessment-worker-notification-installation/v1', egressGatewayUrl: 'https://egress.example/v1/fetch',
        installation: {
          schema: 'aos.assessment-notification-installation/v1', deploymentId: DEPLOYMENT,
          coordinatorId: ISSUER, executorId: AUDIENCE,
          destinations: [{ destination, budgetKey: 'notification:account' }],
          budgets: [{ key: 'notification:account', windowSeconds: 60, allowance: 100, minIntervalSeconds: 0 }],
        },
        secretBindings: [{ versionReference: VERSION, binding: 'ASSESSMENT_NOTIFICATION_CALLBACK_V1' }],
      }),
    },
  };
  const install = value => {
    plans.set(semantic('aos.assessment-notification-work/v1', value), value);
    expectedBody = canonical(value.body);
    return value;
  };
  let runtime = new Miniflare(options);
  try {
    const first = install(plan());
    for (const response of await Promise.all([
      dispatch(runtime, first, '0'.repeat(64)),
      dispatch(runtime, { ...first, audience: 'wrong' }),
      dispatch(runtime, { ...first, unexpected: true }),
      dispatch(runtime, { ...first, destinationDigest: digest('uninstalled') }),
    ])) assert.equal(response.status, 409);
    assert.equal(confirmations, 0);
    assert.equal(gatewayCalls, 0);

    const responses = await Promise.all(Array.from({ length: 4 }, () => dispatch(runtime, first)));
    const accepted = await Promise.all(responses.map(response => receipt(response, first)));
    for (const result of accepted) assert.equal(result.body, accepted[0].body);
    assert.equal(accepted[0].document.outcome, 'accepted');
    assert.equal(gatewayCalls, 1);
    assert.equal(confirmations, 2);
    assert.equal((await dispatch(runtime, { ...first, attempt: 2 })).status, 409);
    assert.equal(gatewayCalls, 1);

    await runtime.dispose(); runtime = new Miniflare(options);
    const replay = await receipt(await dispatch(runtime, first), first);
    assert.equal(replay.body, accepted[0].body);
    assert.equal(gatewayCalls, 1);
    assert.equal(confirmations, 2);

    for (const failure of ['revoked', 'revoked-after-sign', 'stale', 'nonce']) {
      const value = install(plan()); disposition = failure;
      assert.equal((await dispatch(runtime, value)).status, 409);
      disposition = 'allowed';
      const before = confirmations;
      assert.equal((await dispatch(runtime, value)).status, 409);
      assert.equal(confirmations, before);
      assert.equal(gatewayCalls, 1);
    }
    for (const code of [429, 302]) {
      const value = install(plan()); status = code;
      const result = await receipt(await dispatch(runtime, value), value);
      assert.equal(result.document.status, code);
      assert.equal(result.document.outcome, code === 429 ? 'retryable' : 'permanent-failure');
      assert.equal(result.document.retryAfterSeconds, code === 429 ? 30 : undefined);
      assert.ok(!result.body.includes('response-body-must-never-be-retained'));
    }
    const uncertain = install(plan()); status = 204; tamperGateway = true;
    assert.equal((await dispatch(runtime, uncertain)).status, 409);
    const calls = gatewayCalls;
    tamperGateway = false;
    await runtime.dispose(); runtime = new Miniflare(options);
    assert.equal((await dispatch(runtime, uncertain)).status, 409);
    assert.equal(gatewayCalls, calls);
    assert.equal(gatewayCalls, 4);
    console.log(JSON.stringify({ status: 'passed', gatewayCalls, concurrentReceipts: accepted.length }));
  } finally { await runtime.dispose(); }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
