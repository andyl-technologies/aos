// Closed live measurement plan. Candidate observations cannot qualify Hosted
// production, and a streamed body cannot substitute for the query executor.

export const liveCorpusCases = Object.freeze([
  { name: "fresh_pointer", route: "stream", path: "HEAD", method: "GET", repeat: 2, requireChangedBody: true, expectedStatus: 200, sourceStatus: 200 },
  { name: "head", route: "stream", path: "HEAD", method: "HEAD", expectedClientBytes: 0, expectedStatus: 200, sourceStatus: 200 },
  { name: "full_pack", route: "stream", path: "objects/pack/full.pack", method: "GET", expectedClientBytes: 16 * 1024 * 1024, expectedStatus: 200, sourceStatus: 200 },
  { name: "missing", route: "stream", path: "channels/missing", method: "GET", expectedStatus: 404, sourceStatus: 404 },
  { name: "redirect_refusal", route: "stream", path: "channels/redirect", method: "GET", expectRefusal: true, sourceStatus: 307, expectedDispatches: 1 },
  { name: "unsafe_source_refusal", route: "stream", path: "HEAD", method: "GET", substitution: "unsafe_source", expectedDispatches: 0, expectRefusal: true },
  { name: "expired_dispatch_refusal", route: "stream", path: "HEAD", method: "GET", queuedBehind: ["channels/hold", "channels/hold"], ttlSeconds: 2, expectedDispatches: 0, expectRefusal: true },
  { name: "foreign_context_refusal", route: "stream", path: "HEAD", method: "GET", substitutionAfterSigning: "request_id", expectedDispatches: 0, expectRefusal: true },
  { name: "encoding_refusal", route: "stream", path: "channels/encoding", method: "GET", expectRefusal: true, sourceStatus: 200, sourceEncoding: "gzip" },
  { name: "length_refusal", route: "stream", path: "channels/truncated", method: "GET", expectStreamError: true, sourceStatus: 200, sourceDeclaredBytes: 65, sourceProducedBytes: 64, sourceEnded: true,
    additionalAttempt: { route: "stream", path: "channels/oversize", method: "GET", expectStreamError: true, sourceStatus: 200, sourceDeclaredBytes: 128 * 1024 + 1 } },
  { name: "cancellation", route: "stream", path: "objects/pack/hold.pack", method: "GET", cancelAfterBytes: 65536, requireSourceCancellation: true, expectedStatus: 200, sourceStatus: 200 },
  { name: "metadata_during_bulk", route: "stream", path: "objects/pack/hold.pack", method: "GET", concurrentMetadata: ["HEAD", "info/refs"], requireMetadataBeforeBulkEOF: true, expectedStatus: 200, sourceStatus: 200 },
  { name: "bounded_metadata_query", route: "query", path: "HEAD", method: "GET", requirePositiveQueryReply: true, expectedStatus: 200, sourceStatus: 200 },
]);

// A path is insufficient: earlier cancelled streams retain ended=false. Keep
// the exact fresh source sequence selected for this one captured control.
export function sourceSequenceWatermark(observations) {
  let latest = 0;
  for (const entry of observations) {
    if (!Number.isSafeInteger(entry.sequence) || entry.sequence <= latest) throw new Error("Source sequence is missing or reordered");
    latest = entry.sequence;
  }
  return latest;
}

export function selectLiveSourceRequest(observations, afterSequence, path, method) {
  sourceSequenceWatermark(observations);
  const fresh = observations.filter(entry => entry.sequence > afterSequence && entry.path === path && entry.method === method);
  if (fresh.length !== 1) throw new Error("Exact original has no unique fresh source dispatch");
  const { sequence } = fresh[0];
  return { sequence, path, method };
}

export function liveMetadataOverlap(identity, observations, metadataRecords) {
  sourceSequenceWatermark(observations);
  const selected = observations.filter(entry => entry.sequence === identity.sequence && entry.path === identity.path && entry.method === identity.method);
  return selected.length === 1 && selected[0].status === 200 && selected[0].sourceBytes > 0
    && !selected[0].ended && !selected[0].cancelled && metadataRecords.length === 2
    && metadataRecords.every(item => item.status === 200 && item.clientBytes > 0 && !item.streamErrored);
}

export function validateLiveSourceAttempt(spec, source) {
  const violations = [];
  if (!source) return ["source_dispatch_missing"];
  if (source.path !== spec.path || source.method !== (spec.method ?? "GET")) violations.push("source_original");
  if (source.status !== spec.sourceStatus) violations.push("source_status");
  if (spec.sourceEncoding !== undefined && source.contentEncoding !== spec.sourceEncoding) violations.push("source_encoding");
  if (spec.sourceDeclaredBytes !== undefined && source.declaredBytes !== spec.sourceDeclaredBytes) violations.push("source_declared_bytes");
  if (spec.sourceProducedBytes !== undefined && source.sourceBytes !== spec.sourceProducedBytes) violations.push("source_produced_bytes");
  if (spec.sourceEnded !== undefined && source.ended !== spec.sourceEnded) violations.push("source_eof");
  return violations;
}

export function validateLiveStatusRefusal(spec, record) {
  const violations = [];
  if (spec.expectRefusal && (!Number.isInteger(record.status) || record.status < 400 || record.status > 599)) violations.push("refusal");
  return violations;
}

// Per-attempt status checks use the helper above. Only the original's complete
// observation window supplies this strict count, including foreign dispatches.
export function validateLiveRefusal(spec, record, sourceDispatches) {
  const violations = validateLiveStatusRefusal(spec, record);
  if (spec.expectedDispatches !== undefined && sourceDispatches !== spec.expectedDispatches) violations.push("dispatches");
  return violations;
}

// Integer UTC plus immutable uncertainty may expire a two-second grant in less
// than one elapsed second. Require the actual cutoff crossing and both exact
// occupied metadata admissions rather than an unrelated minimum wait duration.
export function liveHeldAdmissionExpired(record, heldRecords, uncertainty, sourceDispatches) {
  const { dispatchStartedUtcMilliseconds: started, responseReceivedUtcMilliseconds: received,
    requestIssuedAt: issued, requestExpiresAt: expires } = record;
  if (![started, received, issued, expires, uncertainty].every(Number.isSafeInteger)
      || uncertainty < 1 || uncertainty >= 30 || received <= started || expires <= issued
      || record.status < 400 || record.status > 599 || sourceDispatches !== 0) return false;
  const initialLatest = Math.floor(started / 1000) + uncertainty;
  const responseLatest = Math.floor(received / 1000) + uncertainty;
  if (initialLatest < issued || initialLatest >= expires || responseLatest < expires) return false;
  if (heldRecords.length !== 2 || !Array.isArray(record.admissionSources)) return false;
  const identities = heldRecords.map(item => item.sourceIdentity?.sequence);
  if (identities.some(item => !Number.isSafeInteger(item)) || new Set(identities).size !== 2) return false;
  return heldRecords.every(item => item.status === 200 && item.path === "channels/hold"
    && record.admissionSources.some(source => source.sequence === item.sourceIdentity.sequence
      && source.path === item.sourceIdentity.path && source.method === item.sourceIdentity.method
      && source.status === 200 && !source.ended && !source.cancelled));
}

// Accept only measured fields supplied by the actual transport/executor joins.
// UNKNOWN remains explicit when Native authorization, client or source evidence
// is missing. This function neither invents reports nor signs review artifacts.
export function correlateLiveCase(plan, observation) {
  if (!liveCorpusCases.includes(plan)) throw new Error("Unknown closed corpus case");
  const missing = [];
  for (const field of ["requestSha256", "responseSha256", "compiledSourceSha256", "sourceDispatches", "clientBytes"]) {
    if (observation[field] === undefined || observation[field] === null) missing.push(field);
  }
  if (plan.route === "query" && (!observation.queryReplyAuthenticated || !observation.queryOutcomeValidated
      || !(observation.queryReplyBytes > 0 && observation.queryReplyBytes <= 256 * 1024)
      || !(observation.querySourceBytes > 0 && observation.querySourceBytes <= 128 * 1024))) {
    missing.push("actual_bounded_query_executor_reply");
  }
  if (!observation.sourceClientJoin) missing.push("source_client_join");
  if (!observation.nativeAuthorizationHeaderJoin) missing.push("native_authorization_header_join");
  const violations = [];
  if (plan.expectedDispatches !== undefined && observation.sourceDispatches !== plan.expectedDispatches) violations.push("dispatch_count");
  if (plan.expectedClientBytes !== undefined && observation.clientBytes !== plan.expectedClientBytes) violations.push("client_bytes");
  if (plan.expectedStatus !== undefined && observation.status !== plan.expectedStatus) violations.push("status");
  if (plan.requireChangedBody && observation.pointerChanged !== true) violations.push("fresh_pointer");
  if (plan.expectRefusal && observation.refused !== true) violations.push("refusal");
  if (plan.expectStreamError && observation.streamErrored !== true) violations.push("length_refusal");
  if (plan.requireSourceCancellation && observation.sourceCancelled !== true) violations.push("source_cancellation");
  if (plan.requireMetadataBeforeBulkEOF && observation.metadataBeforeBulkEOF !== true) violations.push("metadata_capacity");
  return { case: plan.name, state: missing.length ? "UNKNOWN" : violations.length ? "FAIL" : "PASS", missing, violations };
}
