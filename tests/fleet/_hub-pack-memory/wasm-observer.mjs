// Fixed in-memory observations never await a caller-owned sink or read a body.
// Full/missing samples remain unknown; the original handler outcome is preserved.

export class BoundedWasmSink {
  #rows = [];
  #overflow = false;

  append(row) {
    if (this.#rows.length >= 128) {
      this.#overflow = true;
      return;
    }
    this.#rows.push(Object.freeze(row));
  }

  snapshot() {
    return { rows: this.#rows.slice(), overflow: this.#overflow };
  }
}

function sample(getMemory) {
  try {
    const instance = getMemory();
    if (!(instance instanceof WebAssembly.Memory)) return null;
    const bytes = instance.buffer.byteLength;
    return Number.isSafeInteger(bytes) && bytes > 0 ? { instance, bytes } : null;
  } catch {
    return null;
  }
}

export async function observeWasm(dispatch, getMemory, request, sink) {
  const before = sample(getMemory);
  const started = performance.now();
  let response;
  let originalError;
  let handlerFailed = false;
  try {
    response = await dispatch(request);
  } catch (error) {
    handlerFailed = true;
    originalError = error;
  }

  const after = sample(getMemory);
  const sameInstance = before !== null && after !== null
    && before.instance === after.instance && after.bytes >= before.bytes;
  try {
    // This concrete adapter is synchronous, fixed-capacity and body-free. Call
    // the original method directly so a caller override cannot hold dispatch.
    BoundedWasmSink.prototype.append.call(sink, {
      version: 1,
      wasmAllocatedBeforeBytes: before?.bytes ?? null,
      wasmAllocatedAfterBytes: after?.bytes ?? null,
      wasmAllocationHighWaterBytes: sameInstance ? after.bytes : null,
      memoryObservation: sameInstance ? "same_instance_allocation" : "unknown",
      wholeIsolateBytes: null,
      jsSdkBytes: null,
      elapsedMillis: performance.now() - started,
      outcome: handlerFailed ? "handler_error" : "handler_returned",
      scope: "linear-memory allocation; not live Rust heap or whole-isolate memory",
    });
  } catch {
    // Missing retention is unknown and never replaces handler response custody.
  }
  if (handlerFailed) throw originalError;
  return response;
}
