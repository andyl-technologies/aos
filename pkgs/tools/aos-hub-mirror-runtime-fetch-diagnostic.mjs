// Observes one isolated mirror fixture's Node fetch boundary without changing
// request bytes, results, retry policy or the deployed Worker implementation.

import { createHash } from "node:crypto";
import { appendFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

const ROUTES = new Set([
  "/__hub/mirror-candidate", "/__hub/mirror-candidate-query",
  "/__fixture/memory", "/__fixture/provider/observations",
]);
const STEPS = new Set([
  "status", "begin", "upload_parts", "close_stage", "verify_stage",
  "begin_promotion", "copy_parts", "complete_promotion", "acknowledge",
]);

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function safeCode(value) {
  return typeof value === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(value) ? value : null;
}

function shape(input, options) {
  if (typeof input !== "string") return null;
  let url;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1"
      || url.username || url.password || url.search || !ROUTES.has(url.pathname)) {
    return null;
  }

  const row = { route: url.pathname };
  if (!(options?.body instanceof Uint8Array)) return row;
  const bytes = options.body;
  row.bodyBytes = bytes.byteLength;
  row.bodySha256 = digest(bytes);
  if (bytes.byteLength > 256 * 1024) return row;
  try {
    const plan = JSON.parse(Buffer.from(bytes).toString("utf8"));
    // Keep only commitments and a closed operation vocabulary. Raw controls
    // can contain credentials or source URLs and never enter this report.
    row.planIdSha256 = typeof plan.plan_id === "string" ? digest(plan.plan_id) : null;
    const steps = plan.operation?.items?.map(item => item.step?.kind)
      ?? [plan.operation?.step?.kind];
    row.steps = steps.map(step => STEPS.has(step) ? step : "other");
  } catch {
    row.controlParse = "unavailable";
  }
  return row;
}

/** Wraps an existing fetch function with bounded, value-free observations. */
export function observeFetch(fetch, record) {
  let sequence = 0;
  async function retain(row) {
    try {
      await record(row);
    } catch {
      // Missing diagnostics remain missing. Observation failure cannot replace
      // a successful response or change the original transport exception.
    }
  }
  return async function(input, options) {
    const selected = shape(input, options);
    if (!selected) return fetch(input, options);
    const row = { sequence: ++sequence, ...selected };
    const started = performance.now();
    try {
      const result = await fetch(input, options);
      await retain({ ...row, outcome: "response", status: result.status,
        wallMillis: performance.now() - started });
      return result;
    } catch (error) {
      await retain({ ...row, outcome: "rejected", errorCode: safeCode(error?.code),
        causeCode: safeCode(error?.cause?.code),
        wallMillis: performance.now() - started });
      throw error;
    }
  };
}

// This opt-in preload belongs only to the fresh controlled fixture invocation.
// Cleanup subprocesses do not perform fetches and cannot truncate its journal.
const root = process.env.AOS_MIRROR_RUNTIME_EVIDENCE;
if (root && isAbsolute(root)) {
  let writes = Promise.resolve();
  globalThis.fetch = observeFetch(globalThis.fetch, row => {
    writes = writes.then(() => appendFile(join(root, "fetch-diagnostic.jsonl"),
      JSON.stringify(row) + "\n", { mode: 0o600 }));
    return writes;
  });
}
