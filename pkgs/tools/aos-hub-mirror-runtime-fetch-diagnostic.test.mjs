// Synthetic source tests for a value-free observer; these are not runtime or
// provider evidence and never start a Worker or send a network request.

import assert from "node:assert/strict";
import test from "node:test";
import { observeFetch } from "./aos-hub-mirror-runtime-fetch-diagnostic.mjs";

test("observer preserves exact request and successful response identity", async () => {
  const input = "http://127.0.0.1:1234/__hub/mirror-candidate";
  const options = { body: Buffer.from(JSON.stringify({
    plan_id: "original", operation: { items: [{ step: { kind: "complete_promotion" } }] },
    private_fixture_value: "must-not-appear",
  })) };
  const response = { status: 200 };
  const rows = [];
  const fetch = observeFetch(async (actualInput, actualOptions) => {
    assert.equal(actualInput, input);
    assert.equal(actualOptions, options);
    return response;
  }, row => rows.push(row));

  assert.equal(await fetch(input, options), response);
  assert.deepEqual(rows[0].steps, ["complete_promotion"]);
  assert.match(rows[0].bodySha256, /^[a-f0-9]{64}$/);
  assert.match(rows[0].planIdSha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(rows).includes("must-not-appear"), false);
  assert.equal(JSON.stringify(rows).includes("original"), false);
  assert.equal(JSON.stringify(rows).includes("1234"), false);
});

test("rejected fetch keeps its original error and records only safe codes", async () => {
  const error = Object.assign(new Error("sensitive request context"), {
    code: "ECONNRESET", cause: { code: "UND_ERR_SOCKET", hostname: "sensitive.invalid" },
  });
  const rows = [];
  const fetch = observeFetch(async () => { throw error; }, row => rows.push(row));

  await assert.rejects(fetch("http://127.0.0.1:1234/__fixture/memory"), actual => actual === error);
  assert.equal(rows[0].errorCode, "ECONNRESET");
  assert.equal(rows[0].causeCode, "UND_ERR_SOCKET");
  assert.equal(JSON.stringify(rows).includes("sensitive"), false);
});

test("unselected origins pass through without collecting any observations", async () => {
  let calls = 0;
  const response = { status: 200 };
  const rows = [];
  const fetch = observeFetch(async () => { calls += 1; return response; }, row => rows.push(row));

  for (const input of ["https://127.0.0.1/private", "http://foreign.invalid/__fixture/memory",
    "http://127.0.0.1:1234/__fixture/memory?credential=private"]) {
    assert.equal(await fetch(input), response);
  }
  assert.equal(calls, 3);
  assert.deepEqual(rows, []);
});

test("observation write failures never replace actual fetch results", async () => {
  const write = async () => { throw new Error("synthetic observation failure"); };
  const response = { status: 200 };
  const success = observeFetch(async () => response, write);
  assert.equal(await success("http://127.0.0.1:1234/__fixture/memory"), response);

  const error = new Error("synthetic original transport failure");
  const failure = observeFetch(async () => { throw error; }, write);
  await assert.rejects(failure("http://127.0.0.1:1234/__fixture/memory"), actual => actual === error);
});
