// Controlled fixture observations must preserve uncertain custody and secrets.

import assert from "node:assert/strict";
import { test } from "node:test";
import { guardState } from "./aos-hub-mirror-runtime-guard-state.mjs";

test("unknown absence inspection reads exact custody without changing it", async () => {
  const pending = {
    claim_id: "original-claim", expected_etag: '"etag"', expected_size: 7,
    expected_hash: null, expected_provider_version: "writer-version-one",
    unselectedSecret: "never returned",
  };
  const retained = new Map([
    ["pending-delete", pending],
    ["mirror-owner", { job_id: "original-job", unselectedSecret: "never returned" }],
  ]);
  const reads = [];
  const storage = {
    async get(key) { reads.push(key); return retained.get(key); },
    put() { assert.fail("inspection wrote durable custody"); },
    delete() { assert.fail("inspection cleared durable custody"); },
  };
  const observed = await guardState(storage, "original-claim");
  assert.equal(observed.pendingDelete.expected_provider_version, "writer-version-one");
  assert.equal(observed.deleteReceipt, null);
  assert.equal(observed.mirrorOwnerJobId, "original-job");
  assert.equal(JSON.stringify(observed).includes("never returned"), false);
  assert.equal(retained.get("pending-delete"), pending);
  assert.deepEqual(reads.sort(), ["delete-receipt:original-claim", "mirror-owner", "pending-delete", "pending-mutation"]);
});

test("receipt preserves original claim and terminal outcome without arbitrary fields", async () => {
  const claim = {
    claim_id: "exact", expected_etag: '"original"', expected_size: 0,
    expected_provider_version: "original-version",
  };
  const receipt = { claim, outcome: { kind: "deleted", etag: '"original"', secret: "excluded" } };
  const observed = await guardState({ async get(key) {
    return key === "delete-receipt:exact" ? receipt : undefined;
  } }, "exact");
  assert.equal(observed.deleteReceipt.claim.expected_provider_version, "original-version");
  assert.deepEqual(observed.deleteReceipt.outcome, { kind: "deleted", etag: '"original"' });
});

test("invalid claim cannot select or enumerate durable state", async () => {
  for (const claim of [undefined, null, "", "../credential", "a".repeat(129)]) {
    await assert.rejects(guardState({ get() { assert.fail("invalid selector read storage"); } }, claim));
  }
});
