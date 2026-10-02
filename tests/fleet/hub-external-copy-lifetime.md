# Confined Copy cancellation and participating pool observations

This source fixture supports an actual small same-binding Copy at the accepted
minimum provider concurrency of three. It preserves the existing successful
scan, Replicate, Repair and exact Apply replay caller. Its observations do not
qualify a provider, authenticate a SQL actor, or prove remote drain.

## Initial configuration

The do-e2e-only `HUB_EXTERNAL_COPY_LIFETIME_OBSERVER` binding selects an exact
fresh capture and the real source/destination prefixes:

```json
{"version":1,"capture_id":"0123456789abcdef0123456789abcdef","source_prefix":"selected/source","destination_prefixes":["selected/source-replicate-run","selected/source-repair-run","selected/source-cancel-run"]}
```

Missing, foreign or invalid selection emits no matching bracket and cannot be
accepted as coverage. Default Worker builds have no observer declaration or
logging hooks. Selection grants no permission and changes no capacity limit,
signed original, lease, source key ownership or provider result.

The optional initial runner factory `createCopyIsolation(api, options,
{version:1, sourceWorkerName})` maps `EXTERNAL_OBJECT_GUARD/ExternalObjectGuard`
and `HYBRID_BINDING_STATE/HybridBindingState` to the selected source worker. A
distinct source worker uses the same script, modules and authority bindings;
it has no public routes, cron triggers, or queue producers/consumers. The
factory splits shared options using the actual pinned Miniflare schemas.
`HYBRID_OBJECT_GUARD/HybridObjectGuard` remains a separate Managed R2 namespace.

`namespaceReadback(runtime, {configurationBytes, miniflareModulePath,
runnerPath})` returns actual namespace keys and object IDs for both External
bindings, complete source/configuration hashes and actual runner PID/start
ticks. Source files are checked before and after the asynchronous readback.
Worker names and namespace keys are mapping facts, not engine isolate IDs.
Actual Copy events record the runtime-generated participating pool marker.
The caller retains the complete raw namespace report; dynamic IDs are not
silently normalized into installation identity.

## Pending request correlation

The current source-built body codec supports a separate request-only mode:

```text
storage-body-codec copy-request private-selection.json
selection = {version:1, sourceDigest, deploymentId,
             originalRequest:{file,sha256,byteSize},
             receivedRequest:{file,sha256,byteSize}}
```

Both owner-private files must contain identical canonical bounded
`ExternalCopyRequest` bytes. The helper uses the existing shared intrinsic
validator and `ExternalCopyOriginal::fingerprint`. Its output scope is
`intrinsic_unauthenticated_pending_copy_request`; it returns the typed request,
request hash/count and shared original fingerprint. It does not authenticate a
MAC, current SQL claim, clock, reply, or provider effect. Its private output
contains the selected request context and must be retained privately.

The ordered codec source commitment is `main.rs`, `files.rs`, `classify.rs`,
`storage_work.rs`, `ingress.rs`, `controls.rs`, then `copy_request.rs`. A prior
six-file codec or executable is not this helper.

The callback `await_source_progress(token, operationId)` supplies the exact
request-only output as `originalValidationReceipt`, its typed `original`,
`originalSha256`, selected `captureId`, actual `workerLogText`, and raw custody
`receipt`. An actual post-auth `source_guard` event must match that fingerprint
and contain at least 65,536 consumed bytes with `eof:false` and no terminal.
Raw log/process/configuration/request joins remain independently necessary;
the parser alone supplies no authority or complete transport coverage.

## Actual partial-response transport

The initial topology is TLS S3 -> loopback 3903 partial Copy listener -> existing
3902 verification listener -> actual Garage 3900. Existing 3902 behavior is
unchanged. Unarmed and unselected requests stream through unchanged.

```json
{"version":1,"root":"/owner/private/copy-hold","host":"s3.fleet.test","targetPrefixes":["/fleet-s3/.aos-direct-qualification/external-oci/0123456789abcdef0123456789abcdef/registry/"]}
```

At most two exact fresh prefixes are planned before startup. Each has a separate
private directory and a one-use arm. The private control socket accepts closed
`arm`, `state` and `release` commands selecting one exact configured prefix:

```text
arm = {version:1, kind:"arm", targetPrefix, holdUntilUnixMillis}
state/release = {version:1, kind:"state"|"release", targetPrefix}
```

The fixture ceiling is future and at most 35 seconds; it never extends the
original's earlier lease/plan cutoff. The first selected real signed strong
If-Match range starting at zero must return an eligible actual 200/206 response
larger than 65,536 bytes. Headers and provider bytes are preserved. The listener
offers exactly the first 65,536 actual bytes, retains their private hash/count,
and pauses the remainder with bounded reads. A wrong/short provider response
is forwarded unchanged. A caller must separately observe actual Worker
consumption. A proxy write, local close, or fixture ceiling is not remote drain.

Ready metadata includes actual PID/start ticks/UID, executable/source and exact
configuration hashes, private command-line/environment originals, addresses,
control socket, selected prefixes and the 65,536-byte limits. Missing events,
overflow, partial response, timeout or process loss stay incomplete/unknown.

## Called cancellation and recovery

`run_external_copy_cancellation(controls, reviewed_plan, label, *, surface,
destination_name, begin_window, await_source_progress, finish_window, retain)`
begins the raw window before the genuine reviewed `ReplicatePlacement` Apply.
It waits for the actual pending source handshake, checks the current target and
missing selected object through normal SQL-backed APIs, and calls
`OperationService/CancelOperation` with the current `GetOperation` resource
version. It retains the actual cancelled result, physical terminal/unknown
window, and selected object's missing presence afterward. Earlier genuinely
completed objects are not treated as unauthorized effects.

SQL cancellation does not revoke a signed Worker original before its cutoff.
Remote work may finish after cancellation, or an unknown permanent turn may
remain. Native current-claim checks must still prevent logical settlement of
the paused object. A dropped local future is not evidence of remote cleanup.
The helper retains intermediate reviewed/Apply/progress/cancel/window facts
before later assertions; it never creates a new physical retry identity.

Cold recovery uses the real current cancelled/failed `RetryOperation` CAS after
an actual same-source/configuration/persistence restart. It can resume genuine
positively retained parts or refuse an unknown turn. It cannot clear unknown
state or replace a retained source. Actual process/namespace/log-inode facts and
new readiness must be observed; Clock refusal remains refusal.

Exact Apply replay is API idempotence only. A separate physical Closed replay
needs an actual lost positive Worker reply before Native ACK, a genuine failed
operation, cold restart and explicit retry, followed by independent current
catalogue, permanent receipt and provider-effect observations. This capsule
does not implement or claim that lost-positive-reply producer, a provider
qualification, or an actual fleet cancellation/replay result.
