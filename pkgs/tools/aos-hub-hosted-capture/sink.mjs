// One private Durable Object owns the capture budget across both Worker roles.
import { BODY_LIMIT, CORPUS_LIMIT, checkedCapturePolicy, sha256 } from "./capture.mjs";

const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
const RECORD_RESERVATION = 16384;
const ENVELOPE_LIMIT = 32768;
const MAX_CALLS = 8192;
const idPattern = /^[0-9a-f]{32}$/;
const frameNames = new Set(["x-aos-hybrid-ingress", "x-aos-storage-work-signature",
  "x-aos-direct-upload-logical-signature", "x-aos-hybrid-upload-phase"]);
const baseFields = ["version", "captureId", "corpusId", "windowId", "role", "purpose",
  "sourceCommit", "sourceTree", "runtimeSourceDigest", "nativeExecutableSha256", "workerSourceDigest",
  "captureImplementationSha256", "transportCallId", "requestId", "method", "pathSha256",
  "queryClass", "status", "provenance", "instrumentationTraffic"];
const observationFields = ["direction", "state", "observedBytes", "retainedBytes", "eof", "imageKind",
  "frameState", "startedAtMillis", "finishedAtMillis", "responseConsumptionClaim"];

function baseMatches(record, policy) {
  const fields = record.direction === undefined ? baseFields : [...baseFields, ...observationFields];
  if (Object.keys(record).length !== fields.length || fields.some(field => !(field in record))) {
    throw new Error("closed capture record refused");
  }
  for (const name of ["corpusId", "windowId", "sourceCommit", "sourceTree", "runtimeSourceDigest",
    "nativeExecutableSha256", "workerSourceDigest", "captureImplementationSha256"]) {
    if (record[name] !== policy[name]) throw new Error("capture identity refused");
  }
  if (record.version !== 1 || !idPattern.test(record.captureId)
      || !["origin_proxy", "storage_wrapper"].includes(record.role)
      || !/^[a-z][a-z0-9-]{0,47}$/.test(record.purpose)
      || !/^[0-9a-f]{64}$/.test(record.pathSha256)
      || record.method !== "POST"
      || !["absent", "unsupported"].includes(record.queryClass)
      || ![record.transportCallId, record.requestId].every(value => value === null || idPattern.test(value))
      || record.provenance !== (record.direction === "exposed_response"
        ? "wrapper_exposed_reply_bytes" : "independent_wrapper_received_bytes")
      || !(record.status === null || Number.isInteger(record.status) && record.status >= 100 && record.status <= 599)
      || record.instrumentationTraffic !== true) throw new Error("capture metadata refused");
  if (encoder.encode(JSON.stringify(record)).length > 4096) throw new Error("capture record bound refused");
}

function encodeBase64(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

export function bindingSink(namespace, policy) {
  const stub = namespace.idFromName(policy.corpusId);
  const object = namespace.get(stub);
  async function call(path, body) {
    const response = await object.fetch(`https://private-capture${path}`, { method: "POST", body });
    if (!response.ok) throw new Error("capture persistence remains unknown");
  }
  return {
    begin: record => call("/begin", JSON.stringify(record)),
    async finish(record, bytes, frames) {
      const metadata = encoder.encode(JSON.stringify({ record,
        frames: frames.map(frame => ({ name: frame.name, body: encodeBase64(frame.bytes) })) }));
      if (metadata.length > ENVELOPE_LIMIT || bytes.length > BODY_LIMIT) throw new Error("capture envelope bound refused");
      const body = new Uint8Array(4 + metadata.length + bytes.length);
      new DataView(body.buffer).setUint32(0, metadata.length);
      body.set(metadata, 4); body.set(bytes, 4 + metadata.length);
      await call("/finish", body);
    },
  };
}

export class PrivateCaptureLedger {
  constructor(state, env) {
    this.storage = state.storage;
    this.bucket = env.PRIVATE_CAPTURE_BUCKET;
    this.policy = checkedCapturePolicy(JSON.parse(env.PRIVATE_CAPTURE_POLICY));
  }

  async summary() {
    const totals = await this.storage.get("totals");
    await this.bucket.put(this.policy.capturePrefix + "window.json", JSON.stringify({
      version: 1, corpusId: this.policy.corpusId, windowId: this.policy.windowId,
      sourceCommit: this.policy.sourceCommit, sourceTree: this.policy.sourceTree,
      maximumCorpusBytes: CORPUS_LIMIT, conservativeDebitedBytes: totals?.bytes ?? 4096,
      admittedCalls: totals?.calls ?? 0, droppedCalls: totals?.dropped ?? 0,
      overflow: totals?.overflow ?? false, captureCompleteness: "unknown",
      instrumentationTraffic: true, qualificationClaim: false,
    }));
  }

  async begin(record) {
    baseMatches(record, this.policy);
    if (record.status !== null) throw new Error("initial capture status refused");
    const now = Math.floor(Date.now() / 1000);
    if (now < this.policy.startsAt || now >= this.policy.expiresAt) throw new Error("capture window refused");
    const admitted = await this.storage.transaction(async storage => {
      const totals = await storage.get("totals") ?? { bytes: 4096, calls: 0, dropped: 0, overflow: false };
      const key = "call/" + record.captureId;
      if (await storage.get(key)) return false;
      if (totals.calls >= MAX_CALLS || totals.bytes + RECORD_RESERVATION > CORPUS_LIMIT) {
        totals.dropped += 1; totals.overflow = true;
        await storage.put("totals", totals); return false;
      }
      totals.bytes += RECORD_RESERVATION; totals.calls += 1;
      await storage.put("totals", totals);
      await storage.put(key, { record, directions: [] });
      return true;
    });
    if (!admitted) { await this.summary(); throw new Error("capture admission dropped"); }
    await this.bucket.put(`${this.policy.capturePrefix}${record.captureId}/pending.json`,
      JSON.stringify({ ...record, captureState: "pending", qualificationClaim: false }));
    await this.summary();
  }

  async finish(record, bytes, frames) {
    baseMatches(record, this.policy);
    if (!["received_request", "exposed_response"].includes(record.direction)
        || !["eof", "cancelled", "overflow", "unknown"].includes(record.state)
        || typeof record.eof !== "boolean" || record.responseConsumptionClaim !== false
        || !["complete_received_image", "complete_wrapper_reply_image", "bounded_prefix_or_missing"].includes(record.imageKind)
        || !["bounded", "overflow", "unknown"].includes(record.frameState)
        || ![record.observedBytes, record.retainedBytes, record.startedAtMillis, record.finishedAtMillis]
          .every(value => typeof value === "string" && /^(?:0|[1-9][0-9]{0,19})$/.test(value))
        || bytes.length > BODY_LIMIT
        || record.retainedBytes !== String(bytes.length) || frames.length > 3) {
      throw new Error("capture completion refused");
    }
    const images = [{ name: "body", bytes }];
    const names = new Set();
    for (const frame of frames) {
      const allowed = record.role === "origin_proxy"
        ? frame.name !== "x-aos-storage-work-signature"
          && (frame.name !== "x-aos-hybrid-ingress" || record.direction === "received_request")
        : frame.name === "x-aos-storage-work-signature";
      if (!frameNames.has(frame.name) || !allowed || names.has(frame.name) || frame.bytes.length > (frame.name === "x-aos-hybrid-ingress" ? 16384 : 128)) {
        throw new Error("capture private frame refused");
      }
      names.add(frame.name);
      images.push(frame);
    }
    const charged = images.reduce((sum, image) => sum + image.bytes.length, 0);
    const outcome = await this.storage.transaction(async storage => {
      const key = "call/" + record.captureId, call = await storage.get(key);
      if (!call || call.directions.includes(record.direction)) return "unknown";
      const totals = await storage.get("totals");
      call.directions.push(record.direction);
      if (totals.bytes + charged > CORPUS_LIMIT) {
        totals.overflow = true; totals.dropped += 1;
        await storage.put("totals", totals); await storage.put(key, call); return "overflow";
      }
      // Debit before R2 effects; an interrupted/failed put never frees quota or
      // permits an ambiguous raw image to be dispatched again under this ID.
      totals.bytes += charged;
      await storage.put("totals", totals); await storage.put(key, call); return "admitted";
    });
    const prefix = `${this.policy.capturePrefix}${record.captureId}/${record.direction}`;
    if (outcome === "unknown") throw new Error("capture duplicate or absent original refused");
    if (outcome !== "admitted") {
      await this.bucket.put(prefix + ".json", JSON.stringify({ ...record,
        capturePersistence: outcome, privateImages: [], qualificationClaim: false }));
      await this.summary(); return;
    }
    const refs = [];
    for (const image of images) {
      const key = prefix + "-" + image.name + ".bin";
      await this.bucket.put(key, image.bytes);
      refs.push({ name: image.name, key, bytes: String(image.bytes.length), sha256: await sha256(image.bytes) });
    }
    await this.bucket.put(prefix + ".json", JSON.stringify({ ...record,
      capturePersistence: "written", privateImages: refs, qualificationClaim: false }));
    await this.summary();
  }

  async fetch(request) {
    try {
      const path = new URL(request.url).pathname;
      if (request.method !== "POST") return new Response(null, { status: 404 });
      const maximum = path === "/finish" ? BODY_LIMIT + ENVELOPE_LIMIT + 4 : 4096;
      const reader = request.body?.getReader();
      const parts = []; let length = 0;
      if (reader) {
        try {
          for (;;) {
            const chunk = await reader.read(); if (chunk.done) break;
            length += chunk.value.length;
            if (length > maximum) throw new Error("capture input bound refused");
            parts.push(chunk.value);
          }
        } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
      }
      const body = new Uint8Array(length); let position = 0;
      for (const part of parts) { body.set(part, position); position += part.length; }
      if (path === "/begin") await this.begin(JSON.parse(decoder.decode(body)));
      else if (path === "/finish") {
        if (length < 4) throw new Error("capture envelope truncated");
        const count = new DataView(body.buffer).getUint32(0);
        if (count > ENVELOPE_LIMIT || count + 4 > length) throw new Error("capture envelope refused");
        const metadata = JSON.parse(decoder.decode(body.subarray(4, count + 4)));
        if (Object.keys(metadata).sort().join(",") !== "frames,record") throw new Error("capture envelope fields refused");
        const frames = metadata.frames.map(frame => {
          if (Object.keys(frame).sort().join(",") !== "body,name") throw new Error("capture frame fields refused");
          return { name: frame.name, bytes: Uint8Array.from(atob(frame.body), character => character.charCodeAt(0)) };
        });
        await this.finish(metadata.record, body.subarray(count + 4), frames);
      } else return new Response(null, { status: 404 });
      return new Response(null, { status: 204 });
    } catch { return new Response("capture remains unknown", { status: 409 }); }
  }
}
