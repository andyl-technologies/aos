// Actual fixture HTTP/TLS checks only. These do not execute a Worker, Native
// authorization, accepted-purpose admission or a hosted provider.

import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { request } from "node:https";
import test from "node:test";
import { createLiveSocketSource } from "./aos-hub-live-runtime-http-source.mjs";

const runId = "ab".repeat(16);
const prefix = `/.aos-mirror-qualification/${runId}/`;
const fixture = new URL("../../tests/fixtures/", import.meta.url);
const [ca, cert, key] = await Promise.all([
  readFile(new URL("hub-hybrid-fleet-ca.crt", fixture)),
  readFile(new URL("hub-hybrid-fleet-server.crt", fixture)),
  readFile(new URL("hub-hybrid-fleet-server.key", fixture)),
]);

async function source(t) {
  const fixture = createLiveSocketSource({ runId, cert, key });
  fixture.server.listen(0, "127.0.0.1");
  await once(fixture.server, "listening");
  t.after(() => fixture.close());
  return { ...fixture, port: fixture.server.address().port };
}

function options(source, path, extra = {}) {
  return {
    hostname: "127.0.0.1", port: source.port, servername: "localhost",
    ca, rejectUnauthorized: true, agent: false, path: prefix + path,
    method: "GET", headers: { host: "upstream.example.invalid" }, ...extra,
  };
}

function consume(source, path, extra) {
  return new Promise((resolve, reject) => {
    const req = request(options(source, path, extra), response => {
      let bytes = 0;
      const body = [];
      response.on("data", chunk => {
        bytes += chunk.length;
        if (bytes <= 128 * 1024 + 1) body.push(chunk);
      });
      const finish = errored => resolve({ bytes, errored, body: Buffer.concat(body),
        status: response.statusCode, headers: response.headers });
      response.once("end", () => finish(false));
      response.once("aborted", () => finish(true));
      response.on("error", () => finish(true));
    });
    req.on("error", reject);
    req.end();
  });
}

function partial(source) {
  return new Promise((resolve, reject) => {
    const req = request(options(source, "objects/pack/hold.pack"), response => {
      let bytes = 0;
      response.on("error", () => {});
      response.on("data", chunk => {
        bytes += chunk.length;
        if (bytes >= 65536) {
          response.pause();
          resolve({ req, response, bytes });
        }
      });
    });
    req.on("error", reject);
    req.end();
  });
}

async function observed(source, predicate) {
  const deadline = performance.now() + 2000;
  while (performance.now() < deadline) {
    const rows = source.observations();
    if (predicate(rows)) return rows;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail("exact fixture socket observation did not settle");
}

test("partial TLS cancellation joins the exact incomplete response and socket", { timeout: 10000 }, async t => {
  const actual = await source(t);
  const opened = await partial(actual);
  const [before] = actual.observations();
  assert.equal(before.path, "objects/pack/hold.pack");
  assert.equal(before.sequence, 1);
  assert.ok(Number.isSafeInteger(before.socketId));
  assert.equal(before.sourceBytes, 65536);
  assert.equal(before.sourceBytesKind, "producer_write_accepted");
  assert.equal(before.cancelled, false);

  opened.response.destroy();
  opened.req.destroy();
  const [after] = await observed(actual, rows => rows[0]?.socketClosed);
  assert.equal(after.socketId, before.socketId);
  assert.equal(after.sequence, before.sequence);
  assert.equal(after.responseClosedBeforeFinish, true);
  assert.equal(after.responseFinished, false);
  assert.equal(after.ended, false);
  assert.equal(after.fixtureTeardown, false);
  assert.equal(after.sourceFailure, false);
  assert.equal(after.sourceBytes, 65536);
  assert.equal(after.cancelled, true);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(actual.observations()[0].sourceBytes, after.sourceBytes);
});

test("completed TLS bodies and their later socket close are not cancellations", async t => {
  const actual = await source(t);
  const response = await consume(actual, "objects/pack/full.pack");
  assert.equal(response.status, 200);
  assert.equal(response.bytes, 16 * 1024 * 1024);
  const [entry] = await observed(actual, rows => rows[0]?.socketClosed);
  assert.equal(entry.sourceBytes, response.bytes);
  assert.equal(entry.pulls, 256);
  assert.equal(entry.ended, true);
  assert.equal(entry.responseFinished, true);
  assert.equal(entry.responseClosedBeforeFinish, false);
  assert.equal(entry.cancelled, false);
});

test("fixture teardown after positive partial bytes cannot qualify cancellation", { timeout: 10000 }, async t => {
  const actual = await source(t);
  await partial(actual);
  assert.equal(actual.observations()[0].sourceBytes, 65536);

  await actual.close();
  const [entry] = await observed(actual, rows => rows[0]?.socketClosed);
  assert.equal(entry.responseClosedBeforeFinish, true);
  assert.equal(entry.responseFinished, false);
  assert.equal(entry.ended, false);
  assert.equal(entry.fixtureTeardown, true);
  assert.equal(entry.cancelled, false);
});

test("TLS source preserves closed metadata and refusal corpus behavior", async t => {
  const actual = await source(t);
  const first = await consume(actual, "HEAD");
  const second = await consume(actual, "HEAD");
  assert.equal(first.bytes, 64);
  assert.notDeepEqual(first.body, second.body);
  const head = await consume(actual, "HEAD", { method: "HEAD" });
  assert.equal(head.bytes, 0);
  assert.equal(head.headers["content-length"], "64");
  assert.equal((await consume(actual, "channels/missing")).status, 404);
  const redirect = await consume(actual, "channels/redirect");
  assert.equal(redirect.status, 307);
  assert.equal(redirect.headers.location, "https://foreign.example.invalid/HEAD");
  assert.equal((await consume(actual, "channels/encoding")).headers["content-encoding"], "gzip");
  const truncated = await consume(actual, "channels/truncated");
  assert.equal(truncated.headers["content-length"], "65");
  assert.equal(truncated.bytes, 64);
  assert.equal(truncated.errored, true);
  const oversize = await consume(actual, "channels/oversize");
  assert.equal(oversize.bytes, 128 * 1024 + 1);
  assert.equal((await consume(actual, "HEAD", { headers: { host: "foreign.example.invalid" } })).status, 403);
  assert.equal(actual.observations().at(-1).path, "outside_fixture");
  const count = actual.observations().length;
  const diagnostic = await consume(actual, "unused", { path: "/__fixture/live-observations" });
  assert.equal(JSON.parse(diagnostic.body).length, count);
  assert.equal(actual.observations().length, count);
});
