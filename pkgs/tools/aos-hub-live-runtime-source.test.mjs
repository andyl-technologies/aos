// Fixture-only checks. They do not execute Rust, Native IAM or hosted providers.

import test from "node:test";
import assert from "node:assert/strict";
import source, { resetLiveSourceObservations, liveSourceObservations } from "./aos-hub-live-runtime-source.mjs";
import {
  liveCorpusCases, correlateLiveCase, sourceSequenceWatermark,
  selectLiveSourceRequest, liveMetadataOverlap, validateLiveSourceAttempt, validateLiveRefusal, validateLiveStatusRefusal,
  liveHeldAdmissionExpired,
} from "./aos-hub-live-runtime-corpus.mjs";

const env = { LIVE_RUN_ID: "ab".repeat(16) };
const origin = `https://upstream.example.invalid/.aos-mirror-qualification/${env.LIVE_RUN_ID}/`;

test("held admission expiry requires actual cutoff crossing and exact occupied sources", () => {
  const identity = sequence => ({ sequence, path: "channels/hold", method: "GET" });
  const held = [1, 2].map(sequence => ({ path: "channels/hold", status: 200, sourceIdentity: identity(sequence) }));
  const record = {
    status: 409, requestIssuedAt: 100, requestExpiresAt: 102,
    dispatchStartedUtcMilliseconds: 100063, responseReceivedUtcMilliseconds: 101025,
    admissionSources: held.map(item => ({ ...item.sourceIdentity, status: 200, ended: false, cancelled: false })),
  };

  assert.equal(liveHeldAdmissionExpired(record, held, 1, 0), true);
  assert.equal(liveHeldAdmissionExpired({ ...record, responseReceivedUtcMilliseconds: 100999 }, held, 1, 0), false);
  assert.equal(liveHeldAdmissionExpired(record, held, 1, 1), false);
  assert.equal(liveHeldAdmissionExpired(record, held.slice(0, 1), 1, 0), false);
  assert.equal(liveHeldAdmissionExpired(record, [held[0], held[0]], 1, 0), false);
  assert.equal(liveHeldAdmissionExpired({ ...record, admissionSources: record.admissionSources.map(item => ({ ...item, ended: true })) }, held, 1, 0), false);
  assert.equal(liveHeldAdmissionExpired({ ...record, status: 200 }, held, 1, 0), false);
});

test("actual fixture source produces native bounded views and observes reader cancellation", async () => {
  resetLiveSourceObservations();
  const response = await source.fetch(new Request(origin + "objects/pack/full.pack"), env);
  const reader = response.body.getReader({ mode: "byob" });
  const first = await reader.read(new Uint8Array(65536));
  assert.equal(first.value.length, 65536);
  await reader.cancel();

  const [actual] = liveSourceObservations();
  assert.equal(actual.sourceBytes, 65536);
  assert.equal(actual.pulls, 1);
  assert.equal(actual.cancelled, true);
  assert.equal(actual.ended, false);
});

test("HEAD produces zero body and repeated actual pointer responses differ", async () => {
  resetLiveSourceObservations();
  const first = await (await source.fetch(new Request(origin + "HEAD"), env)).text();
  const second = await (await source.fetch(new Request(origin + "HEAD"), env)).text();
  assert.notEqual(first, second);
  const head = await source.fetch(new Request(origin + "HEAD", { method: "HEAD" }), env);
  assert.equal(head.body, null);
  assert.equal(head.headers.get("content-length"), "64");
  assert.equal(liveSourceObservations().at(-1).sourceBytes, 0);
  assert.equal((await source.fetch(new Request("https://foreign.example.invalid/HEAD"), env)).status, 403);
  assert.equal(liveSourceObservations().at(-1).path, "outside_fixture");
});

test("streamed metadata cannot become actual bounded-query or Native authorization evidence", () => {
  const query = liveCorpusCases.find(item => item.name === "bounded_metadata_query");
  const observation = {
    requestSha256: "aa".repeat(32), responseSha256: "bb".repeat(32), compiledSourceSha256: "cc".repeat(32),
    sourceDispatches: 1, clientBytes: 64, sourceClientJoin: true,
  };
  const result = correlateLiveCase(query, observation);
  assert.equal(result.state, "UNKNOWN");
  assert.ok(result.missing.includes("actual_bounded_query_executor_reply"));
  assert.ok(result.missing.includes("native_authorization_header_join"));
  assert.equal(liveCorpusCases.length, 13);
});

test("an earlier cancelled source cannot satisfy a later completed bulk overlap", async () => {
  resetLiveSourceObservations();
  const path = "objects/pack/full.pack";
  const earlier = await source.fetch(new Request(origin + path), env);
  const earlierReader = earlier.body.getReader({ mode: "byob" });
  await earlierReader.read(new Uint8Array(65536));
  await earlierReader.cancel();
  const watermark = sourceSequenceWatermark(liveSourceObservations());

  const current = await source.fetch(new Request(origin + path), env);
  const identity = selectLiveSourceRequest(liveSourceObservations(), watermark, path, "GET");
  await current.arrayBuffer();
  const metadata = await Promise.all(["HEAD", "info/refs"].map(async item => {
    const response = await source.fetch(new Request(origin + item), env);
    return { status: response.status, clientBytes: (await response.arrayBuffer()).byteLength, streamErrored: false };
  }));
  const history = liveSourceObservations();
  assert.equal(history[0].cancelled, true);
  assert.equal(history[0].ended, false);
  assert.equal(history.find(item => item.sequence === identity.sequence).ended, true);
  assert.equal(history.some(item => item.path === path && !item.ended), true);
  assert.equal(liveMetadataOverlap(identity, history, metadata), false);

  const nextWatermark = sourceSequenceWatermark(history);
  const pending = await source.fetch(new Request(origin + path), env);
  const pendingReader = pending.body.getReader({ mode: "byob" });
  await pendingReader.read(new Uint8Array(65536));
  const pendingIdentity = selectLiveSourceRequest(liveSourceObservations(), nextWatermark, path, "GET");
  assert.equal(liveMetadataOverlap(pendingIdentity, liveSourceObservations(), metadata), true);
  assert.equal(liveMetadataOverlap({ ...pendingIdentity, sequence: 999 }, liveSourceObservations(), metadata), false);
  await pendingReader.cancel();
});

test("predispatch refusal cannot substitute for intended source response cases", async () => {
  resetLiveSourceObservations();
  for (const name of ["redirect_refusal", "encoding_refusal", "length_refusal"]) {
    const spec = liveCorpusCases.find(item => item.name === name);
    assert.deepEqual(validateLiveSourceAttempt(spec, null), ["source_dispatch_missing"]);
    const watermark = sourceSequenceWatermark(liveSourceObservations());
    const response = await source.fetch(new Request(origin + spec.path), env);
    if (name === "length_refusal") await response.arrayBuffer();
    else await response.body?.cancel();
    const observations = liveSourceObservations();
    const identity = selectLiveSourceRequest(observations, watermark, spec.path, "GET");
    const actual = observations.find(item => item.sequence === identity.sequence);
    assert.deepEqual(validateLiveSourceAttempt(spec, actual), []);
    assert.ok(validateLiveSourceAttempt(spec, { ...actual, status: 409 }).includes("source_status"));
    if (name === "length_refusal") {
      const oversize = spec.additionalAttempt;
      const watermark = sourceSequenceWatermark(observations);
      const response = await source.fetch(new Request(origin + oversize.path), env);
      await response.body.cancel();
      const latest = liveSourceObservations();
      const identity = selectLiveSourceRequest(latest, watermark, oversize.path, "GET");
      assert.deepEqual(validateLiveSourceAttempt(oversize, latest.find(item => item.sequence === identity.sequence)), []);
      assert.deepEqual(validateLiveSourceAttempt(oversize, null), ["source_dispatch_missing"]);
    }
  }
});

test("zero source dispatch cannot turn an unauthorized HTTP200 into a refusal", () => {
  for (const name of ["unsafe_source_refusal", "expired_dispatch_refusal", "foreign_context_refusal"]) {
    const spec = liveCorpusCases.find(item => item.name === name);
    assert.deepEqual(validateLiveRefusal(spec, { status: 200 }, 0), ["refusal"]);
    assert.deepEqual(validateLiveRefusal(spec, { status: 409 }, 0), []);
    assert.deepEqual(validateLiveRefusal(spec, { status: 409 }, 1), ["dispatches"]);
  }
});

test("following a redirect then refusing the foreign response cannot satisfy RedirectRefusal", async () => {
  resetLiveSourceObservations();
  const spec = liveCorpusCases.find(item => item.name === "redirect_refusal");
  const watermark = sourceSequenceWatermark(liveSourceObservations());
  const redirect = await source.fetch(new Request(origin + spec.path), env);
  const identity = selectLiveSourceRequest(liveSourceObservations(), watermark, spec.path, "GET");
  const selected = liveSourceObservations().find(item => item.sequence === identity.sequence);
  assert.deepEqual(validateLiveSourceAttempt(spec, selected), []);
  assert.deepEqual(validateLiveStatusRefusal(spec, { status: 409 }), []);
  assert.deepEqual(validateLiveRefusal(spec, { status: 409 }, 1), []);

  const followed = await source.fetch(new Request(redirect.headers.get("location")), env);
  assert.equal(followed.status, 403);
  const fresh = liveSourceObservations().filter(item => item.sequence > watermark);
  assert.equal(fresh.length, 2);
  assert.equal(fresh[1].path, "outside_fixture");
  assert.deepEqual(validateLiveSourceAttempt(spec, fresh[0]), []);
  assert.deepEqual(validateLiveRefusal(spec, { status: 409 }, fresh.length), ["dispatches"]);
  assert.deepEqual(validateLiveRefusal(spec, { status: 409 }, undefined), ["dispatches"]);
});
