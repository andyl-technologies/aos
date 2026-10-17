// Actual SQLite and streaming provider tests for the controlled R2 facade.
// These tests qualify the fixture itself, not the Rust Worker or hosted R2.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { MirrorFixtureStore, mirrorFixtureEnv } from "./aos-hub-mirror-r2-fixture.mjs";

const PART_BYTES = 8 * 1024 * 1024;
const key = `.aos-mirror-qualification/${"a".repeat(32)}/final/nar/source.nar`;

function fixture(path) {
  const database = new DatabaseSync(path);
  const sql = {
    exec(query, ...parameters) {
      if (parameters.length === 0 && query.includes("CREATE TABLE")) {
        database.exec(query);
        return { toArray: () => [] };
      }
      const statement = database.prepare(query);
      const rows = statement.columns().length === 0
        ? (statement.run(...parameters), [])
        : statement.all(...parameters);
      return { toArray: () => rows };
    },
  };
  const state = {
    storage: {
      sql,
      transactionSync(action) {
        database.exec("BEGIN IMMEDIATE");
        try {
          const result = action();
          database.exec("COMMIT");
          return result;
        } catch (error) {
          database.exec("ROLLBACK");
          throw error;
        }
      },
    },
  };
  const store = new MirrorFixtureStore(state);
  const namespace = {
    idFromName: value => value,
    get: () => ({
      fetch: (url, options) => store.fetch(new Request(url, { ...options, duplex: "half" })),
    }),
  };
  return {
    database,
    bucket: mirrorFixtureEnv({ MIRROR_FIXTURE_STORE: namespace }).REGISTRY_BUCKET,
    observations: async () => (await store.fetch(new Request("https://fixture/observations"))).json(),
    fault: async action => {
      const response = await store.fetch(new Request("https://fixture/fault", {
        method: "POST", body: JSON.stringify({ action, remaining: 1 }),
      }));
      assert.equal(response.status, 204);
    },
  };
}

async function digestBody(body) {
  const hash = createHash("sha256");
  const reader = body.getReader({ mode: "byob" });
  let size = 0;
  let maximumView = 0;
  for (;;) {
    const { done, value } = await reader.read(new Uint8Array(64 * 1024));
    if (value?.length) {
      size += value.length;
      maximumView = Math.max(maximumView, value.length);
      hash.update(value);
    }
    if (done) break;
  }
  reader.releaseLock();
  return { hash: hash.digest("hex"), size, maximumView };
}

test("multipart completion retains real chunks and stable full/range incarnation", async () => {
  const directory = mkdtempSync(join(tmpdir(), "aos-mirror-r2-provider-"));
  const current = fixture(join(directory, "provider.sqlite"));
  try {
    const first = new Uint8Array(PART_BYTES).fill(0x61);
    const last = new Uint8Array(777).fill(0x62);
    const upload = await current.bucket.createMultipartUpload(key);
    const firstReceipt = await upload.uploadPart(1, first);
    const lastReceipt = await upload.uploadPart(2, last);
    const receipt = await upload.complete([
      { partNumber: 1, etag: firstReceipt.etag },
      { partNumber: 2, etag: lastReceipt.etag },
    ]);
    assert.equal(receipt.size, PART_BYTES + last.length);
    assert.deepEqual(await current.bucket.head(key), receipt);

    const object = await current.bucket.get(key);
    const actual = await digestBody(object.body);
    const expected = createHash("sha256").update(first).update(last).digest("hex");
    assert.equal(actual.hash, expected);
    assert.equal(actual.size, receipt.size);
    assert.ok(actual.maximumView <= 64 * 1024);
    assert.equal(object.version, receipt.version);

    const ranged = await current.bucket.get(key, { range: { offset: PART_BYTES - 17, length: 33 } });
    const range = await digestBody(ranged.body);
    assert.equal(range.size, 33);
    assert.equal(range.hash, createHash("sha256")
      .update(first.subarray(first.length - 17)).update(last.subarray(0, 16)).digest("hex"));
    assert.equal(ranged.version, receipt.version);
    await assert.rejects(upload.uploadPart(3, new Uint8Array(1)));

    const observations = await current.observations();
    assert.equal(observations.openUploads, 0);
    assert.equal(observations.operations.find(row => row.action === "get").output_bytes,
      receipt.size + 33);
    assert.equal(observations.operations.find(row => row.action === "part").input_bytes,
      receipt.size);
    const maximum = current.database.prepare(
      "SELECT max(length(bytes)) AS bytes FROM mirror_fixture_chunks").get().bytes;
    assert.ok(maximum <= 64 * 1024);
  } finally {
    current.database.close();
    rmSync(directory, { recursive: true });
  }
});

test("lost positive Complete reply survives actual database reopen without fabricated receipt", async () => {
  const directory = mkdtempSync(join(tmpdir(), "aos-mirror-r2-provider-"));
  const path = join(directory, "provider.sqlite");
  let current = fixture(path);
  try {
    const bytes = new Uint8Array(91).fill(0x37);
    const upload = await current.bucket.createMultipartUpload(key);
    const part = await upload.uploadPart(1, bytes);
    await current.fault("complete");
    await assert.rejects(upload.complete([{ partNumber: 1, etag: part.etag }]), /502/);
    current.database.close();
    current = fixture(path);

    const observed = await current.bucket.head(key);
    assert.equal(observed.size, bytes.length);
    const object = await current.bucket.get(key);
    assert.equal((await digestBody(object.body)).hash,
      createHash("sha256").update(bytes).digest("hex"));
    const requests = (await current.observations()).operations;
    assert.equal(requests.find(row => row.action === "complete").requests, 1);
    await assert.rejects(current.bucket.resumeMultipartUpload(key, upload.uploadId)
      .uploadPart(2, new Uint8Array(1)));
  } finally {
    current.database.close();
    rmSync(directory, { recursive: true });
  }
});

test("lost Create leaves one unacknowledged upload and performs no automatic retry", async () => {
  const current = fixture(":memory:");
  try {
    await current.fault("create");
    await assert.rejects(current.bucket.createMultipartUpload(key), /502/);
    const observations = await current.observations();
    assert.equal(observations.openUploads, 1);
    assert.equal(observations.operations.find(row => row.action === "create").requests, 1);
    assert.equal(await current.bucket.head(key), null);
  } finally {
    current.database.close();
  }
});

test("Abort closes the actual upload and reserved namespace excludes ordinary objects", async () => {
  const current = fixture(":memory:");
  try {
    const upload = await current.bucket.createMultipartUpload(key);
    await upload.abort();
    await assert.rejects(upload.uploadPart(1, new Uint8Array(1)));
    await assert.rejects(current.bucket.createMultipartUpload("registry/public/object"));
    assert.equal((await current.observations()).openUploads, 0);
  } finally {
    current.database.close();
  }
});
