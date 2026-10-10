// Exercises the production WASM executor, real R2 and durable attempt storage.
// Only fixed upstream responses are intercepted; provider routing and parsing
// run through the production Worker entry point without a Hub SQL binding.
const assert = require('node:assert/strict');
const { createHash, createHmac, randomBytes } = require('node:crypto');
const { createRequire } = require('node:module');
const path = require('node:path');

const WORK = '/_internal/assessment/v1/provider/execute';
const CAPABILITIES = '/_internal/assessment/v1/capabilities';
const SIGNATURE = 'x-aos-assessment-signature';
const KEY = 'aos-assessment-fleet-fixture-key-v1';
const DEPLOYMENT = 'assessment-fleet';
const ISSUER = 'coordinator';
const AUDIENCE = 'executor';
const PARTITION = 'fixture-partition';

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function signature(domain, route, body) {
  const mac = createHmac('sha256', KEY);
  for (const value of [domain, 'POST', route, DEPLOYMENT, ISSUER, AUDIENCE]) {
    const bytes = Buffer.from(value);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    mac.update(length).update(bytes);
  }
  return mac.update(digest(body)).digest('hex');
}

function timestamp(seconds) {
  return new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
}

function plan() {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = timestamp(now + 60);
  return {
    schema: 'aos.provider-work-plan/v1',
    deploymentId: DEPLOYMENT, issuer: ISSUER, audience: AUDIENCE,
    planId: randomBytes(16).toString('hex'),
    claim: {
      scanId: 'scan', taskId: 'provider', requestDigest: digest('request'),
      generation: 1, inventoryRevision: 1,
      claimToken: randomBytes(16).toString('hex'), attempt: 1, expiresAt,
    },
    issuedAt: timestamp(now), expiresAt, nonce: randomBytes(16).toString('hex'),
    inventoryDigest: digest('inventory'), policyDigest: digest('policy'),
    authorizationPartition: PARTITION,
    budgetReservation: {
      sourceBudget: 'github-public', reservationId: randomBytes(16).toString('hex'),
      requests: 1, deadline: expiresAt,
    },
    operation: { kind: 'observe-tags', repository: 'example/fixture', tagPrefix: 'v', page: 1 },
    adapterVersion: 'aos-maintain-providers/v1',
    limits: {
      responseBytes: 8 * 1024 * 1024, sourceBytes: 64 * 1024 * 1024,
      resultBytes: 256 * 1024, normalizedEntries: 128, requests: 1,
      concurrency: 1, connectSeconds: 10, requestSeconds: 45,
    },
  };
}

async function request(runtime, route, document, domain, suppliedSignature) {
  const body = JSON.stringify(document);
  return runtime.dispatchFetch(`https://assessment-fleet.invalid${route}`, {
    method: 'POST', body,
    headers: {
      'content-type': 'application/json',
      [SIGNATURE]: suppliedSignature ?? signature(domain, route, body),
    },
  });
}

async function receipt(response, route, domain) {
  const body = await response.text();
  assert.equal(response.status, 200, body);
  assert.equal(response.headers.get(SIGNATURE), signature(domain, route, body));
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.ok(Buffer.byteLength(body) <= 256 * 1024);
  return { body, document: JSON.parse(body) };
}

async function main() {
  const [toolingRoot, scriptPath, statePath] = process.argv.slice(2);
  assert.ok(toolingRoot && scriptPath && statePath);
  const load = createRequire(path.join(toolingRoot, 'lib/node_modules/wrangler/node_modules/fleet-runner.cjs'));
  const { Miniflare, Response } = load('miniflare');
  let physicalCalls = 0;
  let sourceBody = '[]';
  let expectedAuthorization = null;
  const outboundService = async request => {
    physicalCalls += 1;
    assert.equal(request.method, 'GET');
    assert.equal(request.url, 'https://api.github.com/repos/example/fixture/tags?per_page=20&page=1');
    assert.equal(request.headers.get('accept-encoding'), 'identity');
    assert.equal(request.headers.get('authorization'), expectedAuthorization);
    return new Response(sourceBody, { headers: { etag: 'fleet-tags' } });
  };

  const options = {
    name: 'assessment-provider-fleet', scriptPath, modules: true,
    modulesRoot: path.dirname(scriptPath),
    modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
    compatibilityDate: '2024-09-23', compatibilityFlags: ['enable_request_signal'],
    cf: false, outboundService,
    resourcePersistencePath: statePath,
    r2Buckets: { ASSESSMENT_EVIDENCE: 'assessment-fleet-evidence' },
    durableObjects: { ASSESSMENT_PROVIDER_TASKS: { className: 'AssessmentProviderObject' } },
    bindings: {
      HUB_RUNTIME_ROLE: 'hub_executor', HUB_DEPLOYMENT_ID: DEPLOYMENT,
      HUB_ASSESSMENT_COORDINATOR_ID: ISSUER, HUB_ASSESSMENT_EXECUTOR_ID: AUDIENCE,
      HUB_ASSESSMENT_WORK_KEY: KEY, HUB_ASSESSMENT_SOURCE_TTL_SECONDS: "60",
      HUB_ASSESSMENT_CREDENTIALS: JSON.stringify({
        schema: 'aos.assessment-source-credentials/v1',
        grants: [
          { reference: 'github-read-v1', partition: PARTITION, provider: 'github-tags',
            scope: { kind: 'github-repositories', repositories: ['example/fixture'] },
            secretBinding: 'ASSESSMENT_GITHUB_V1', expiresAt: timestamp(Math.floor(Date.now() / 1000) + 3600) },
          { reference: 'github-short-v1', partition: PARTITION, provider: 'github-tags',
            scope: { kind: 'github-repositories', repositories: ['example/fixture'] },
            secretBinding: 'ASSESSMENT_GITHUB_V1', expiresAt: timestamp(Math.floor(Date.now() / 1000) + 30) },
          { reference: 'github-expired-v1', partition: PARTITION, provider: 'github-tags',
            scope: { kind: 'github-repositories', repositories: ['example/fixture'] },
            secretBinding: 'ASSESSMENT_GITHUB_V1', expiresAt: timestamp(Math.floor(Date.now() / 1000) - 1) },
        ].sort((left, right) => left.reference.localeCompare(right.reference)),
      }),
      ASSESSMENT_GITHUB_V1: 'fixture-only-upstream-credential',
    },
  };
  let runtime = new Miniflare(options);
  try {
    const now = Math.floor(Date.now() / 1000);
    const challenge = {
      schema: 'aos.provider-capability-challenge/v1', deploymentId: DEPLOYMENT,
      issuer: ISSUER, audience: AUDIENCE, nonce: randomBytes(16).toString('hex'),
      issuedAt: timestamp(now), expiresAt: timestamp(now + 60),
    };
    const capabilities = await receipt(
      await request(runtime, CAPABILITIES, challenge, 'aos-provider-capability-request-v1'),
      CAPABILITIES, 'aos-provider-capability-result-v1',
    );
    assert.deepEqual(capabilities.document.challenge, challenge);
    assert.ok(capabilities.document.adapters.includes('aos-maintain-providers/v1'));
    assert.equal(physicalCalls, 0);

    const first = plan();
    const refusals = [
      request(runtime, WORK, first, 'aos-provider-plan-v1', '0'.repeat(64)),
      request(runtime, WORK, { ...first, audience: 'wrong' }, 'aos-provider-plan-v1'),
      request(runtime, WORK, { ...first, unexpected: true }, 'aos-provider-plan-v1'),
    ];
    for (const response of await Promise.all(refusals)) assert.equal(response.status, 409);
    assert.equal(physicalCalls, 0);

    // Source authority must cover the whole issued physical deadline. Neither
    // an expired grant nor a currently live thirty-second grant covers this
    // sixty-second invocation, and neither may select an anonymous fallback.
    for (const credentialRef of ['github-short-v1', 'github-expired-v1']) {
      const refused = { ...plan(), credentialRef };
      assert.equal((await request(runtime, WORK, refused, 'aos-provider-plan-v1')).status, 409);
    }
    assert.equal(physicalCalls, 0);

    // All simultaneous and sequential retries use the same physical result.
    const responses = await Promise.all(Array.from({ length: 4 }, () =>
      request(runtime, WORK, first, 'aos-provider-plan-v1')));
    const receipts = await Promise.all(responses.map(response => receipt(response, WORK, 'aos-provider-result-v1')));
    assert.equal(physicalCalls, 1);
    for (const result of receipts) assert.equal(result.body, receipts[0].body);
    assert.equal(receipts[0].document.usage.requests, 1);
    assert.equal(receipts[0].document.usage.decompressedBytes, 2);
    assert.equal(receipts[0].document.outcome, 'observed');
    const observation = receipts[0].document.normalizedObjects
      .map(projection => projection.object).find(object => object.kind === 'observation');
    assert.ok(observation, 'admitted provider observation is absent');
    assert.equal(Date.parse(observation.object.expiresAt) - Date.parse(observation.object.validatedAt), 60_000);
    assert.ok(!Object.hasOwn(receipts[0].document, 'rawBody'));
    const bucket = await runtime.getR2Bucket('ASSESSMENT_EVIDENCE');
    const evidenceKey = `assessment-evidence/v1/${digest(PARTITION)}/${digest('[]')}`;
    assert.equal(await (await bucket.get(evidenceKey)).text(), '[]');

    const changed = { ...first, nonce: randomBytes(16).toString('hex') };
    assert.equal((await request(runtime, WORK, changed, 'aos-provider-plan-v1')).status, 409);
    assert.equal(physicalCalls, 1);

    // The executor can retain a maximum-sized raw body while returning only
    // its bounded compact projection to the coordinator.
    const large = plan();
    sourceBody = '[]' + ' '.repeat(8 * 1024 * 1024 - 2);
    const largeDigest = digest(sourceBody);
    const largeReceipt = await receipt(
      await request(runtime, WORK, large, 'aos-provider-plan-v1'), WORK, 'aos-provider-result-v1',
    );
    assert.equal(largeReceipt.document.usage.decompressedBytes, 8 * 1024 * 1024);
    assert.ok(Buffer.byteLength(largeReceipt.body) < 16 * 1024);
    const largeObject = await bucket.get(`assessment-evidence/v1/${digest(PARTITION)}/${largeDigest}`);
    assert.equal(largeObject.size, 8 * 1024 * 1024);
    assert.equal(digest(Buffer.from(await largeObject.arrayBuffer())), largeDigest);
    assert.equal(physicalCalls, 2);

    // A stream exceeding its issued ceiling stays fenced after failure. An
    // identical retry cannot dispatch even when the original source recovers.
    const bounded = plan();
    bounded.limits.responseBytes = 8;
    sourceBody = '123456789';
    assert.equal((await request(runtime, WORK, bounded, 'aos-provider-plan-v1')).status, 409);
    assert.equal(physicalCalls, 3);

    const wrongScope = { ...plan(), credentialRef: 'github-read-v1', authorizationPartition: 'another-partition' };
    assert.equal((await request(runtime, WORK, wrongScope, 'aos-provider-plan-v1')).status, 409);
    const wrongProvider = { ...plan(), credentialRef: 'github-read-v1' };
    wrongProvider.operation.kind = 'observe-releases';
    assert.equal((await request(runtime, WORK, wrongProvider, 'aos-provider-plan-v1')).status, 409);
    assert.equal(physicalCalls, 3);
    const wrongRepository = { ...plan(), credentialRef: 'github-read-v1' };
    wrongRepository.operation.repository = 'another/private-project';
    assert.equal((await request(runtime, WORK, wrongRepository, 'aos-provider-plan-v1')).status, 409);
    assert.equal(physicalCalls, 3);
    expectedAuthorization = 'Bearer fixture-only-upstream-credential';
    sourceBody = '[]';
    const authorized = { ...plan(), credentialRef: 'github-read-v1' };
    const credentialReceipt = await receipt(
      await request(runtime, WORK, authorized, 'aos-provider-plan-v1'), WORK, 'aos-provider-result-v1',
    );
    assert.ok(!credentialReceipt.body.includes('fixture-only-upstream-credential'));
    assert.equal(physicalCalls, 4);
    expectedAuthorization = null;
    sourceBody = '[]';
    assert.equal((await request(runtime, WORK, bounded, 'aos-provider-plan-v1')).status, 409);
    assert.equal(physicalCalls, 4);

    // Missing references never select ambient secrets or an anonymous fallback.
    const credential = { ...plan(), credentialRef: 'uninstalled-credential' };
    assert.equal((await request(runtime, WORK, credential, 'aos-provider-plan-v1')).status, 409);
    assert.equal(physicalCalls, 4);

    await runtime.dispose();
    runtime = new Miniflare(options);
    const replay = await receipt(
      await request(runtime, WORK, first, 'aos-provider-plan-v1'), WORK, 'aos-provider-result-v1',
    );
    assert.equal(replay.body, receipts[0].body);
    assert.equal((await request(runtime, WORK, bounded, 'aos-provider-plan-v1')).status, 409);
    assert.equal(physicalCalls, 4);
    const persisted = await runtime.getR2Bucket('ASSESSMENT_EVIDENCE');
    assert.equal(await (await persisted.get(evidenceKey)).text(), '[]');
    console.log(JSON.stringify({ status: 'passed', physicalCalls, concurrentReceipts: receipts.length }));
  } finally {
    await runtime.dispose();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
