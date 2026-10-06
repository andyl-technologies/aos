// Local stream/transport and atomic-budget fixtures; no provider or deployment calls.
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { BODY_LIMIT, CORPUS_LIMIT, createObservedHandler } from "./capture.mjs";
import { createCapturedProxy } from "./origin-capture.mjs";
import { createProxy } from "./baseline-proxy.mjs";
import { bindingSink, PrivateCaptureLedger } from "./sink.mjs";

const encoder = new TextEncoder(), now = Math.floor(Date.now() / 1000);
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const policy = { version: 1, corpusId: "1".repeat(32), windowId: "2".repeat(32),
  sourceCommit: "3".repeat(40), sourceTree: "4".repeat(40), runtimeSourceDigest: "5".repeat(64),
  nativeExecutableSha256: "6".repeat(64), workerSourceDigest: "7".repeat(64),
  captureImplementationSha256: "8".repeat(64), startsAt: now - 1, expiresAt: now + 3599,
  capturePrefix: "private-capture/" + "1".repeat(32) + "/", storageOrigin: "https://storage.fixture.test",
  originProxyOrigin: "https://origin.fixture.test",
  originRoutes: [{ method: "POST", path: "/aos.hub.v1.DirectUploadService/StatusBatch", purpose: "direct-status" }],
  maximumBodyBytes: BODY_LIMIT, maximumCorpusBytes: CORPUS_LIMIT };

function context() {
  const jobs = [];
  return { waitUntil(job) { jobs.push(job); }, async flush() {
    for (let position = 0; position < jobs.length; position++) await jobs[position];
  } };
}

function memorySink() {
  return { starts: [], images: [],
    async begin(record) { this.starts.push(record); },
    async finish(record, bytes, frames) { this.images.push({ record, bytes: bytes.slice(),
      frames: frames.map(frame => ({ name: frame.name, bytes: frame.bytes.slice() })) }); },
  };
}

function metadataRequest(body = "{\"operation\":\"head\"}", extra = {}) {
  return new Request(policy.storageOrigin + "/_internal/storage/v1/execute", {
    method: "POST", body, ...extra,
    headers: { "content-type": "application/json", "authorization": "Bearer fixture-only-app-token",
      "cookie": "fixture-only-cookie", "x-aos-storage-call-id": "9".repeat(32),
      "x-aos-storage-work-signature": "a".repeat(64), ...(extra.headers ?? {}) } });
}

const tests = [];
async function test(name, body) { await body(); tests.push(name); }

await test("same URL/headers/body/status/cookies; one handler; private frames only", async () => {
  const sink = memorySink(), ctx = context(); let calls = 0;
  const source = metadataRequest();
  const selected = createObservedHandler(async request => {
    calls += 1; assert.equal(request.url, source.url);
    assert.deepEqual([...request.headers], [...source.headers]);
    assert.equal(await request.text(), "{\"operation\":\"head\"}");
    return new Response("{\"ok\":true}", { status: 202,
      headers: { "set-cookie": "fixture-response-cookie", "cache-control": "private",
        "x-aos-storage-work-signature": "b".repeat(64) } });
  }, "storage_wrapper", policy, sink);
  const response = await selected(source, {}, ctx);
  assert.equal(response.status, 202); assert.equal(response.headers.get("set-cookie"), "fixture-response-cookie");
  assert.equal(await response.text(), "{\"ok\":true}"); await ctx.flush();
  assert.equal(calls, 1); assert.equal(sink.images.length, 2);
  const request = sink.images.find(image => image.record.direction === "received_request");
  const reply = sink.images.find(image => image.record.direction === "exposed_response");
  assert.equal(digest(request.bytes), digest(encoder.encode("{\"operation\":\"head\"}")));
  assert.equal(reply.record.provenance, "wrapper_exposed_reply_bytes");
  assert.equal(reply.record.responseConsumptionClaim, false);
  assert.equal(reply.record.eof, true);
  assert.deepEqual(request.frames.map(frame => frame.name), ["x-aos-storage-work-signature"]);
  const metadata = JSON.stringify(sink.starts) + JSON.stringify(sink.images.map(image => image.record));
  for (const secret of ["fixture-only-app-token", "fixture-only-cookie", "fixture-response-cookie", "a".repeat(64)]) {
    assert.equal(metadata.includes(secret), false);
  }
});

await test("bulk and credential routes bypass without reading or minting IDs", async () => {
  for (const path of ["/objects/large.nar", "/aos.hub.v1.PublishService/UploadPart/1", "/_internal/storage/v1/bindings"]) {
    const sink = memorySink(), ctx = context(); let calls = 0;
    const source = new Request(policy.storageOrigin + path, { method: "POST", body: "fixture bulk bytes" });
    const selected = createObservedHandler(request => {
      calls += 1; assert.equal(request, source); assert.equal(request.bodyUsed, false);
      return new Response("bypass");
    }, "storage_wrapper", policy, sink);
    assert.equal(await (await selected(source, {}, ctx)).text(), "bypass"); await ctx.flush();
    assert.equal(calls, 1); assert.equal(sink.starts.length, 0); assert.equal(sink.images.length, 0);
  }
  const sink = memorySink(), ctx = context();
  const selected = createObservedHandler(async request => {
    await request.text(); return new Response("{}", { headers: { "content-type": "application/json" } });
  }, "storage_wrapper", policy, sink);
  await (await selected(new Request(policy.storageOrigin + "/_internal/storage/v1/execute",
    { method: "POST", body: "{}" }), {}, ctx)).text(); await ctx.flush();
  assert.equal(sink.starts[0].transportCallId, null); assert.equal(sink.starts[0].requestId, null);
});

await test("8MiB overflow preserves full stream; capture remains prefix only", async () => {
  const bytes = new Uint8Array(BODY_LIMIT + 17).fill(120), sink = memorySink(), ctx = context(); let calls = 0;
  const selected = createObservedHandler(async request => {
    calls += 1; assert.equal((await request.arrayBuffer()).byteLength, bytes.length);
    return new Response(bytes);
  }, "storage_wrapper", policy, sink);
  const response = await selected(metadataRequest(bytes), {}, ctx);
  assert.equal((await response.arrayBuffer()).byteLength, bytes.length); await ctx.flush();
  assert.equal(calls, 1);
  for (const image of sink.images) {
    assert.equal(image.bytes.length, BODY_LIMIT); assert.equal(image.record.state, "overflow");
    assert.equal(image.record.observedBytes, String(bytes.length));
    assert.equal(image.record.imageKind, "bounded_prefix_or_missing");
  }
});

await test("consumer cancellation reaches the same response reader exactly once", async () => {
  const sink = memorySink(), ctx = context(); let calls = 0, cancelled = [];
  const selected = createObservedHandler(async request => {
    calls += 1; await request.text();
    return new Response(new ReadableStream({ start(controller) { controller.enqueue(encoder.encode("prefix")); },
      cancel(reason) { cancelled.push(reason); } }));
  }, "storage_wrapper", policy, sink);
  const response = await selected(metadataRequest(), {}, ctx), reader = response.body.getReader();
  assert.equal(new TextDecoder().decode((await reader.read()).value), "prefix");
  await reader.cancel("fixture-cancel"); await ctx.flush();
  assert.deepEqual(cancelled, ["fixture-cancel"]); assert.equal(calls, 1);
  const image = sink.images.find(item => item.record.direction === "exposed_response");
  assert.equal(image.record.state, "cancelled"); assert.equal(image.record.eof, false);
  assert.equal(new TextDecoder().decode(image.bytes), "prefix");
});

await test("sink failure never retries or replaces delegate's response/error", async () => {
  const ctx = context(), sink = { async begin() { throw new Error("fixture persistence failure"); },
    async finish() { throw new Error("must not retry"); } };
  let calls = 0;
  const selected = createObservedHandler(async request => {
    calls += 1; await request.text(); return new Response("unchanged", { status: 409 });
  }, "storage_wrapper", policy, sink);
  const response = await selected(metadataRequest(), {}, ctx);
  assert.equal(response.status, 409); assert.equal(await response.text(), "unchanged");
  await ctx.flush(); assert.equal(calls, 1);
  const error = new Error("fixture handler error");
  const failed = createObservedHandler(() => { calls += 1; throw error; }, "storage_wrapper", policy, memorySink());
  await assert.rejects(failed(metadataRequest(), {}, ctx), candidate => candidate === error);
  assert.equal(calls, 2); await ctx.flush();
});

await test("signed URL and credential-shaped JSON are not retained as images", async () => {
  for (const body of ["{\"url\":\"https://fixture.test/object?X-Amz-Signature=fixture\"}",
    "{\"secret_access_key\":\"fixture-secret\"}"]) {
    const sink = memorySink(), ctx = context();
    const selected = createObservedHandler(async request => { await request.text(); return new Response(body); },
      "storage_wrapper", policy, sink);
    assert.equal(await (await selected(metadataRequest(body), {}, ctx)).text(), body); await ctx.flush();
    for (const image of sink.images) { assert.equal(image.bytes.length, 0); assert.equal(image.record.state, "unknown"); }
  }
});

function fakeStorage() {
  const values = new Map(); let tail = Promise.resolve();
  return { values, async get(key) { return structuredClone(values.get(key)); },
    async put(key, value) { values.set(key, structuredClone(value)); },
    transaction(work) { const result = tail.then(() => work(this)); tail = result.catch(() => {}); return result; } };
}

await test("shared atomic corpus debit across roles, duplicates refused", async () => {
  const state = { storage: fakeStorage() }, objects = new Map();
  const bucket = { async put(key, bytes) { objects.set(key, bytes instanceof Uint8Array ? bytes.slice() : bytes); } };
  const ledger = new PrivateCaptureLedger(state, { PRIVATE_CAPTURE_BUCKET: bucket, PRIVATE_CAPTURE_POLICY: JSON.stringify(policy) });
  const sink = memorySink(), ctx = context();
  const selected = createObservedHandler(async request => { await request.text(); return new Response("0123456789"); },
    "storage_wrapper", policy, sink);
  await (await selected(metadataRequest("0123456789"), {}, ctx)).text(); await ctx.flush();
  const a = sink.starts[0], b = { ...a, captureId: "c".repeat(32), role: "origin_proxy" };
  await ledger.begin(a); await ledger.begin(b);
  const totals = await state.storage.get("totals"); totals.bytes = CORPUS_LIMIT - 12;
  await state.storage.put("totals", totals);
  const observation = sink.images[0].record;
  await Promise.all([ledger.finish(observation, encoder.encode("0123456789"), []),
    ledger.finish({ ...observation, captureId: b.captureId, role: b.role }, encoder.encode("0123456789"), [])]);
  assert.equal((await state.storage.get("totals")).bytes, CORPUS_LIMIT - 2);
  assert.equal((await state.storage.get("totals")).overflow, true);
  assert.equal([...objects.keys()].filter(key => key.endsWith("-body.bin")).length, 1);
  const first = objects.get(policy.capturePrefix + a.captureId + "/received_request.json");
  await assert.rejects(ledger.finish(observation, encoder.encode("0123456789"), []));
  assert.equal(objects.get(policy.capturePrefix + a.captureId + "/received_request.json"), first);
});

function proxyFixture(selection = {}) {
  const key = "d".repeat(64);
  const configuration = { version: 1, project: "fixture-project", service: "fixture-service",
    serviceUID: "fixture-service-uid", target: "https://fixture-service.run.app", proxyOrigin: policy.originProxyOrigin,
    publicOrigin: "https://public.fixture.test", deploymentID: "fixture-deployment",
    invokerEmail: "fixture-invoker@fixture-project.iam.gserviceaccount.com", invokerUID: "12345",
    startsAt: policy.startsAt, expiresAt: policy.expiresAt, ...selection };
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const token = b64(JSON.stringify({ alg: "RS256" })) + "." + b64(JSON.stringify({ iss: "accounts.google.com",
    aud: configuration.target, sub: configuration.invokerUID, email: configuration.invokerEmail, email_verified: true,
    iat: now, exp: now + 3600 })) + "." + b64(new Uint8Array(128));
  const bytes = encoder.encode("{\"sessions\":[]}");
  const assertion = { version: 1, deployment_id: configuration.deploymentID, issued_at: now,
    expires_at: now + 30, request_id: "e".repeat(32), scheme: "https",
    authority: new URL(configuration.publicOrigin).host, method: "POST",
    path_and_query: policy.originRoutes[0].path, body_sha256: digest(bytes), upload_phase: "commit", client_ip: "127.0.0.1" };
  const payload = b64(JSON.stringify(assertion));
  const frame = payload + "." + createHmac("sha256", key).update(payload).digest("base64url");
  return { configuration, secrets: { HUB_HYBRID_INGRESS_KEY: key, GOOGLE_INVOKER_ID_TOKEN: token },
    request: signal => new Request(configuration.proxyOrigin + assertion.path_and_query,
      { method: "POST", body: bytes, signal, headers: { "x-aos-hybrid-ingress": frame,
        "x-aos-fleet-request-id": "e".repeat(32), "authorization": "Bearer fixture-app",
        "x-aos-direct-upload-logical-signature": "f".repeat(64), "x-aos-hybrid-upload-phase": "commit",
        "cookie": "fixture-cookie", host: new URL(configuration.publicOrigin).host } }), frame, token };
}

await test("original proxy HMAC/routing/manual redirect and cookies remain exact", async () => {
  const fixture = proxyFixture(), sink = memorySink(), ctx = context(); let calls = 0;
  const selected = createCapturedProxy(fixture.configuration, policy, sink, async request => {
    calls += 1; assert.equal(request.url, fixture.configuration.target + policy.originRoutes[0].path);
    assert.equal(request.redirect, "manual"); assert.equal(request.headers.get("host"), null);
    assert.equal(request.headers.get("x-aos-hybrid-ingress"), fixture.frame);
    assert.equal(request.headers.get("authorization"), "Bearer fixture-app");
    assert.equal(request.headers.get("cookie"), "fixture-cookie");
    assert.equal(request.headers.get("x-serverless-authorization"), "Bearer " + fixture.token);
    assert.equal(await request.text(), "{\"sessions\":[]}");
    return new Response("{\"redirect\":true}", { status: 302, headers: { location: "/next",
      "set-cookie": "reply-cookie", "cache-control": "private", "x-serverless-authorization": "must-strip" } });
  }, () => now);
  const response = await selected(fixture.request(), fixture.secrets, ctx);
  assert.equal(response.status, 302); assert.equal(response.headers.get("location"), "/next");
  assert.equal(response.headers.get("set-cookie"), "reply-cookie");
  assert.equal(response.headers.get("x-serverless-authorization"), null);
  await response.text(); await ctx.flush(); assert.equal(calls, 1);
  const inbound = sink.images.find(image => image.record.direction === "received_request");
  assert.equal(new TextDecoder().decode(inbound.frames[0].bytes), fixture.frame);
  assert.deepEqual(inbound.frames.map(frame => frame.name), ["x-aos-hybrid-ingress",
    "x-aos-direct-upload-logical-signature", "x-aos-hybrid-upload-phase"]);
  assert.equal(JSON.stringify(inbound.record).includes("f".repeat(64)), false);
  assert.equal(JSON.stringify(sink.images.map(image => image.record)).includes(fixture.token), false);
  const invalid = fixture.request(); invalid.headers.set("x-aos-hybrid-ingress", "invalid");
  assert.equal((await selected(invalid, fixture.secrets, ctx)).status, 401); assert.equal(calls, 1);
  await ctx.flush();
});

await test("closed selected proxy configuration refuses malformed coordinates before transport", async () => {
  const fixture = proxyFixture();
  const missing = { ...fixture.configuration };
  delete missing.serviceUID;
  for (const configuration of [missing, { ...fixture.configuration, extra: "unsupported" },
    { ...fixture.configuration, target: "https://not-provider.fixture.test" },
    { ...fixture.configuration, proxyOrigin: "https://origin.fixture.test/?query=unsupported" },
    { ...fixture.configuration, invokerEmail: "fixture-invoker@different-project.iam.gserviceaccount.com" },
    { ...fixture.configuration, serviceUID: "invalid uid" }]) {
    let calls = 0;
    assert.throws(() => createProxy(configuration, () => { calls += 1; }));
    assert.equal(calls, 0);
  }
});

await test("selected audience invoker and public origin mismatches refuse without dispatch", async () => {
  const fixture = proxyFixture();
  for (const change of [{ target: "https://different-service.run.app" },
    { invokerUID: "54321" },
    { invokerEmail: "another-invoker@fixture-project.iam.gserviceaccount.com" },
    { publicOrigin: "https://different.fixture.test" }]) {
    let calls = 0;
    const handler = createProxy({ ...fixture.configuration, ...change }, () => { calls += 1; }, () => now);
    const response = await handler(fixture.request(), fixture.secrets);
    assert.equal(response.status, 401);
    assert.equal(calls, 0);
  }
});

await test("independently selected synthetic configuration keeps exact audience and single dispatch", async () => {
  const fixture = proxyFixture({ project: "second-project", service: "second-service",
    serviceUID: "second-service-uid", target: "https://second-service.run.app",
    proxyOrigin: "https://second-origin.fixture.test", publicOrigin: "https://second-public.fixture.test",
    invokerEmail: "second-invoker@second-project.iam.gserviceaccount.com", invokerUID: "67890" });
  let calls = 0;
  const handler = createProxy(fixture.configuration, async request => {
    calls += 1;
    assert.equal(request.url, fixture.configuration.target + policy.originRoutes[0].path);
    assert.equal(request.redirect, "manual");
    assert.equal(request.headers.get("x-serverless-authorization"), "Bearer " + fixture.token);
    assert.equal(request.headers.get("authorization"), "Bearer fixture-app");
    assert.equal(request.headers.get("cookie"), "fixture-cookie");
    assert.equal(await request.text(), "{\"sessions\":[]}");
    return new Response(null, { status: 204 });
  }, () => now);
  assert.equal((await handler(fixture.request(), fixture.secrets)).status, 204);
  assert.equal(calls, 1);
});

await test("plain selected proxy forwards the caller signal through its actual Native request", async () => {
  const fixture = proxyFixture(), controller = new AbortController();
  let calls = 0, outgoing, dispatched;
  const started = new Promise(resolve => { dispatched = resolve; });
  const handler = createProxy(fixture.configuration, request => {
    calls += 1;
    outgoing = request;
    assert.equal(request.signal.aborted, false);
    assert.equal(request.redirect, "manual");
    dispatched();
    return new Promise((_, reject) => request.signal.addEventListener("abort",
      () => reject(request.signal.reason), { once: true }));
  }, () => now);
  const result = handler(fixture.request(controller.signal), fixture.secrets);
  await started;
  controller.abort(new Error("synthetic caller cancellation"));
  assert.equal(outgoing.signal.aborted, true);
  assert.equal((await result).status, 401);
  assert.equal(calls, 1);
});

await test("already cancelled plain and captured proxy inputs cannot dispatch", async () => {
  const fixture = proxyFixture(), controller = new AbortController();
  controller.abort(new Error("synthetic prior cancellation"));
  let calls = 0;
  const transport = () => { calls += 1; return new Response(null, { status: 204 }); };
  const source = fixture.request(controller.signal);
  const handler = createProxy(fixture.configuration, transport, () => now);
  assert.equal((await handler(source, fixture.secrets)).status, 401);
  assert.equal(source.bodyUsed, false);

  const sink = memorySink(), ctx = context();
  const captured = createCapturedProxy(fixture.configuration, policy, sink, transport, () => now);
  assert.equal((await captured(fixture.request(controller.signal), fixture.secrets, ctx)).status, 401);
  await ctx.flush();
  assert.equal(calls, 0);
});

await test("caller AbortSignal reaches one actual proxy transport", async () => {
  const fixture = proxyFixture(), sink = memorySink(), ctx = context(), controller = new AbortController();
  let calls = 0, dispatched;
  const started = new Promise(resolve => { dispatched = resolve; });
  const selected = createCapturedProxy(fixture.configuration, policy, sink, request => {
    calls += 1; dispatched();
    return new Promise((_, reject) => request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true }));
  }, () => now);
  const result = selected(fixture.request(controller.signal), fixture.secrets, ctx);
  await started; controller.abort(new Error("fixture caller cancellation"));
  assert.equal((await result).status, 401); await ctx.flush(); assert.equal(calls, 1);
  assert.ok(sink.images.some(image => image.record.state === "cancelled"));
});

await test("query-bearing metadata stays unresolved and forwards untouched", async () => {
  const sink = memorySink(), ctx = context(); let calls = 0;
  const request = metadataRequest();
  const queried = new Request(request.url + "?unsupported=fixture", request);
  const selected = createObservedHandler(async actual => {
    calls += 1; assert.equal(actual, queried); assert.equal(await actual.text(), "{\"operation\":\"head\"}");
    return new Response("unchanged");
  }, "storage_wrapper", policy, sink);
  assert.equal(await (await selected(queried, {}, ctx)).text(), "unchanged"); await ctx.flush();
  assert.equal(calls, 1); assert.equal(sink.images.length, 1);
  assert.equal(sink.images[0].record.queryClass, "unsupported");
  assert.equal(sink.images[0].record.state, "unknown");
  assert.equal(sink.images[0].bytes.length, 0); assert.deepEqual(sink.images[0].frames, []);
});

await test("input stream failure retains a partial image without changing application error", async () => {
  const sink = memorySink(), ctx = context(), failure = new Error("fixture input error"); let calls = 0;
  let reads = 0;
  const body = new ReadableStream({ pull(controller) {
    if (++reads === 1) controller.enqueue(encoder.encode("{\"partial\":"));
    else controller.error(failure);
  } }, { highWaterMark: 0 });
  const selected = createObservedHandler(async request => {
    calls += 1; await request.text(); return new Response("must not return");
  }, "storage_wrapper", policy, sink);
  await assert.rejects(selected(metadataRequest(body, { duplex: "half" }), {}, ctx), error => error === failure);
  await ctx.flush(); assert.equal(calls, 1);
  assert.equal(sink.images[0].record.state, "unknown"); assert.equal(sink.images[0].record.eof, false);
  assert.equal(sink.images[0].record.imageKind, "bounded_prefix_or_missing");
});

await test("real binding envelope survives binary images and rejects truncated or oversized inputs", async () => {
  const objects = new Map(), state = { storage: fakeStorage() };
  const ledger = new PrivateCaptureLedger(state, { PRIVATE_CAPTURE_BUCKET: {
    async put(key, value) { objects.set(key, value); }
  }, PRIVATE_CAPTURE_POLICY: JSON.stringify(policy) });
  const namespace = { idFromName(name) { assert.equal(name, policy.corpusId); return name; },
    get() { return { fetch(url, init) { return ledger.fetch(new Request(url, init)); } }; } };
  const sink = bindingSink(namespace, policy), ctx = context(); let calls = 0;
  const selected = createObservedHandler(async request => {
    calls += 1; await request.text(); return new Response("{\"accepted\":true}");
  }, "storage_wrapper", policy, sink);
  await (await selected(metadataRequest(), {}, ctx)).text(); await ctx.flush();
  assert.equal(calls, 1);
  const records = [...objects.entries()].filter(([name]) => name.endsWith("received_request.json"));
  assert.equal(records.length, 1);
  const record = JSON.parse(records[0][1]);
  assert.equal(record.privateImages.length, 2);
  assert.equal(record.privateImages[1].name, "x-aos-storage-work-signature");
  assert.equal(record.privateImages[1].sha256, digest(encoder.encode("a".repeat(64))));
  assert.equal(JSON.stringify(record).includes("a".repeat(64)), false);
  for (const bytes of [new Uint8Array(3), new Uint8Array(BODY_LIMIT + 32773)]) {
    assert.equal((await ledger.fetch(new Request("https://private-capture/finish", { method: "POST", body: bytes }))).status, 409);
  }
  assert.equal(JSON.parse(objects.get(policy.capturePrefix + "window.json")).captureCompleteness, "unknown");
});

await test("isolate memory pressure drops only diagnostic bytes, not delegate work", async () => {
  let release;
  const held = new Promise(resolve => { release = resolve; });
  const sink = memorySink(), ctx = context(); let calls = 0;
  const save = sink.finish.bind(sink);
  sink.finish = async (...args) => { await held; await save(...args); };
  const selected = createObservedHandler(async request => {
    calls += 1; assert.equal((await request.arrayBuffer()).byteLength, BODY_LIMIT);
    return new Response(null, { status: 204 });
  }, "storage_wrapper", policy, sink);
  for (let index = 0; index < 3; index++) {
    assert.equal((await selected(metadataRequest(new Uint8Array(BODY_LIMIT).fill(120)), {}, ctx)).status, 204);
  }
  release(); await ctx.flush(); assert.equal(calls, 3);
  const requests = sink.images.filter(image => image.record.direction === "received_request");
  assert.equal(requests.length, 3);
  assert.deepEqual(requests.map(image => image.bytes.length), [BODY_LIMIT, BODY_LIMIT, 0]);
  assert.equal(requests[2].record.state, "overflow");
  assert.equal(requests[2].record.observedBytes, String(BODY_LIMIT));
});

process.stdout.write(`PASS ${tests.length} local bounded-capture fixtures\n`);
