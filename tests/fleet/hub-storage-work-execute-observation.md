# Ordinary storage-work attempt observations

The Native client retains one bounded, value-free observation for each actual
HTTP attempt. The `x-aos-storage-call-id` header is fresh for each retry and is
observational only. Existing request signatures, retries, response bounds,
result validation and current SQL checks retain their ordering.

The `storage_work_attempt_observed ` marker precedes closed JSON with these
fields:

```text
version, invocationId, transportCallId, attempt, planId, operation,
endpointScheme, offeredRequestSha256, offeredRequestBytes, replyStatus,
exposedReplySha256, exposedReplyBytes, replyEof, unreadResponse, outcome,
elapsedMicros, observedAtUnixMicros, replyMacAuthentication
```

`invocationId` is the existing aggregate exchange ID; `transportCallId` is the
fresh attempt ID actually offered in the header. Byte counts and microseconds
are decimal strings. UTC is optional observational time, not an authorization
clock. `replyStatus` is null before response headers. `replyMacAuthentication`
is null: this ordinary route uses the actual selected HTTP client's TLS and
existing typed result checks, without a reply MAC. `endpointScheme` describes
the actual endpoint and does not independently attest a TLS peer.

Offered request bytes are not delivered request bytes. Exposed response bytes
are exactly the chunks returned by the existing HTTP client, including a chunk
that triggers the existing size refusal. Their SHA commits the concatenated
exposed prefix. An unread non-success status has zero exposed bytes and unknown
remote drain. EOF is reported only when that actual body stream returns EOF.
Retry, transport failure, status refusal, malformed/invalid/expired result,
read failure and dropped future remain distinct. Missing or oversized logging
omits evidence without changing the operation result.

`storage_work_final_sql_checked ` carries `version`, the checked `attempt`,
`contextKind: surface_fetch_current_sql`, `commitments` and optional
`completedAtUnixMicros`. Only the existing surface-fetch caller emits it after
its actual current placement/binding and, when present, published credential
snapshot checks. Commitment values hash the already-read checked rows; no extra
SQL or provider query is performed. Other callers do not inherit this context.
A typed result observed before a later SQL refusal is still a transport result,
not a completed current-state acceptance.

The shared fixture codec classifies complete, independently captured upstream
bodies. Its payload partition must be joined separately to the actual Native
exposed prefix/EOF/unread record, ingress acceptance or refusal, current state,
source/process lifetime and complete provider window. A known complete upstream
metadata response and a proven exposed prefix may describe that prefix without
claiming Native accepted the response. Unknown prefixes and incomplete global
inventories remain unresolved. Actual selected source-built executables and
whole-window originals are required; source tests do not qualify a fleet or
provider deployment.

The called fixture interfaces are:

```text
storage_work_execute_receipts(source, native_process, file_provenance=None)
  -> {version: 1, attempts, finalContexts}
join_storage_work_execute(originals, received, original_headers,
  received_headers, records, codec_rows, source_digest, codec_source_sha256)
  -> {version: 1, joined, unresolvedNativeRequestIds,
      unassignedAttemptCallIds, unassignedFinalContextCallIds,
      nativeBulkBytes: null, scope}
```

The reader reuses the existing journal process or private file-window custody
checks. Each retained event carries its actual JSON commitment and optional
journal timestamp. Plain-log collection brackets do not invent an event UTC.
The join reopens both private request/reply pairs and requires exact per-attempt
call ID, route/header/body/status, selected codec source and body commitments.
It compares the Native prefix hash with the same prefix of the independently
captured complete upstream reply. A partial reply that contains selected object
content remains unresolved; its full codec payload count cannot substitute for
the consumed prefix. Known metadata-only responses may be partitioned at an
actual proven prefix without claiming result acceptance.

Unassigned attempts and final contexts remain in the complete window inventory.
The GC subset must share the same body/source/payload commitments rather than
count another copy of the same exchange. This join leaves current actor, purpose
and provider partitions absent for their independent source-owned checks.
