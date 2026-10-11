import assert from "node:assert/strict";
import test from "node:test";
import { BoundedWasmSink, observeWasm } from "./wasm-observer.mjs";

const request = () => new Request("https://fixture.invalid/");

test("actual same Memory grows while response and body owner pass through", async () => {
  const response = new Response("actual offered body");
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
  const sink = new BoundedWasmSink();
  const result = await observeWasm(async () => { memory.grow(1); return response; },
    () => memory, request(), sink);
  assert.equal(result, response);
  assert.equal(result.bodyUsed, false);
  const row = sink.snapshot().rows[0];
  assert.equal(row.wasmAllocationHighWaterBytes, 131072);
  assert.equal(row.wholeIsolateBytes, null);
  assert.equal(row.jsSdkBytes, null);
});

test("full or invalid sink preserves the exact original handler error", async () => {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const original = new Error("existing handler refusal");
  const full = new BoundedWasmSink();
  for (let index = 0; index < 128; index++) full.append({ version: 1 });
  for (const sink of [full, { append: () => new Promise(() => {}) }]) {
    await assert.rejects(observeWasm(async () => { throw original; },
      () => memory, request(), sink), value => value === original);
  }
  assert.equal(full.snapshot().rows.length, 128);
  assert.equal(full.snapshot().overflow, true);
});

test("equal-sized replacement Memory remains unknown", async () => {
  let memory = new WebAssembly.Memory({ initial: 1 });
  const response = new Response();
  const sink = new BoundedWasmSink();
  const result = await observeWasm(async () => {
    memory = new WebAssembly.Memory({ initial: 1 });
    return response;
  }, () => memory, request(), sink);
  assert.equal(result, response);
  assert.equal(sink.snapshot().rows[0].memoryObservation, "unknown");
  assert.equal(sink.snapshot().rows[0].wasmAllocationHighWaterBytes, null);
});

test("undefined rejection remains a rejection when observation is absent", async () => {
  let caught = false;
  try {
    await observeWasm(async () => { throw undefined; }, () => { throw new Error(); },
      request(), null);
  } catch (error) {
    caught = true;
    assert.equal(error, undefined);
  }
  assert.equal(caught, true);
});
