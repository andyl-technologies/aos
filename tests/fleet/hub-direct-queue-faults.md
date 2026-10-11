# Direct queue fault and process observation fixtures

## Called production window

`run_production_queue_fault_window` runs after the ordinary publication while
the issuer remains live, before the existing lifecycle and cold-recovery cases.
Each case uses a fresh publication manifest, real Begin/Grant/provider PUT/Report,
and the staged driver's saved first Complete request. Its callback captures the
admission-only SQL row and requires the selected Core-backed `native-bodies`
observer before installing a one-shot production queue wrapper. A missing
observer is a prerequisite refusal, never a skipped validation or stock-codec
substitution. The whole source-owned SQL journal marker is preserved separately.

The wrapper retains the actual selected SDK job in its confined R2 capture
prefix. Capture PUT, local SDK return, queue acceptance, delivery and provider
settlement are distinct observations. The bounded runner read-hook exports only
that key under its selected process/configuration/source lifetime. The original
job, options and SDK receiver are preserved, including immediately after awaited
capture; a known acknowledgment may send the identical job without a second PUT.

The conditional-replacement case uses an unarmed GET owner on port 3904 ahead of
the existing 3903 chain. It holds only an actually received conditional signed
GET for the selected staging object, before forwarding, and releases the same
request in `finally`. The real SigV4 adapter first verifies the old bytes and
condition, performs one conditional replacement, and observes the provider's
actual old-condition reply. A still-readable pinned old version is unavailable
for this case; the fixture never manufactures a 412 response. The extra GET hop
is part of the measured fixture topology, not a production performance claim.

Actor invalidation follows the actual first pending Complete/job. Its retained
known-acknowledgment continuation may establish same-original promotion refusal;
it does not establish consumer revocation from a generic denial. Early expiry
remains setup refusal and never selects a renewed token. Lost/refused/unknown
phases do not authorize a new original or automatic mutation replay.

These separate 8 MiB originals leave the main three 2 GiB objects and 12,535
metadata objects unchanged. Missing consumer-authority, provider-redispatch,
foreground-budget and full-resource assessments remain null. Object progression
does not invoke publication Commit. The collector's actual terminal is retained
before its window image; an existing zero-byte collection prefix is not completion.
Controlled source gates do not establish runtime qualification for these windows.

## Individual helper contracts

These additive helpers prepare faults around one retained production admission
and Complete item. They do not install acceptance, construct an admission or mint
a JWT. Their API calls are identity controls and exact Complete retries. They
never call Begin, GrantParts or upload endpoints. An exact Complete retry
can eventually publish when real verification and current Native authorization
succeed. A pending-barrier assertion therefore belongs to the pending interval,
not to an assertion that successful recovery must remain pending forever.

## Required runtime custody

Select a reviewed immutable Worker distribution, its actual compiled source
digest, both registered module hashes, real installed queue configuration, and a
fresh dedicated persistence root. Preserve the existing three 2 GiB objects and
the 12,535-object business corpus. Fault objects and resource windows are
additional named windows; they do not replace those workloads.

Retain the exact Native admission and Complete from read-only SQL, not a rebuilt
summary. `capture_pending_sql` runs source-built `psql` in a read-only transaction
with a 30-second statement timeout. It selects the actual persisted completion
intent and publication state. Copy its private output through the existing
bounded log-window transport, verify its bytes and SHA, and call
`pending_snapshot` against the producer's retained originals. This first helper
is limited to publication objects; cache and OCI owners need their own barrier
joins.

`prepare_queue_fault_modules` copies the two exact installed files into a fresh
private root. Its entry re-exports the original named Durable Object classes and
wraps only the default fetch/queue handlers. The resulting graph is a fixture
graph with its own hashes. The registered original artifacts retain their
identity. Use the existing runner's `scriptPath` to select that entry, retaining
the complete parsed configuration and hashes. No runner or main-flow edits are
part of this helper.

Generate the selection with `queue_selection` from actual admission/Complete,
placement ID, compiled source digest and fresh run digest. The wrapper matches
those originals, records the digest of the *actual* later closed queue job, and
never replaces its body. That full digest includes the internal close receipt.
Production Status does not export that receipt; neither a pending status nor a
SQL state alone proves its provider closure. Join the actual wrapper send/consume
and production queue telemetry with the independent provider closure receipts.

## Fault cases

| Case | Actual fault boundary and required observation |
| --- | --- |
| Lost enqueue acknowledgment | `enqueue_ack_lost` waits for the actual selected Queue `send` return and then throws to its caller once. A rejected SDK call remains unknown; it is not a successful injected loss. Queue server acceptance remains unknown until actual delivery/receipts establish it. |
| Lost completion acknowledgment | `completion_ack_lost` throws once at the selected Message `ack` callback before calling the SDK. Durable verification precedes that callback. Let the real queue decide redelivery, then require the same full job digest and actual production `replayed: true` finish. An SDK ACK return is a local invocation observation, not server settlement. |
| Replaced source | Use the controlled provider adapter below. Require the real provider condition and response, production refusal, unchanged pending SQL barrier and complete provider window. |
| Revoked authorization | Exchange the real provisioning secret, then authenticate its JWT with WhoAmI and join it to the original deployment/principal/actor. Retire that exact active token using current List metadata and PlanRetireAccessToken/RetireAccessToken. Retry the same Complete through `QueueFaultNativeTransport`, without refresh. Require an actual authentication/authorization denial and unchanged publication barrier. |
| Expired delegation | Issue a real 1–60-second persisted token through PlanIssueAccessToken/IssueAccessToken. Run `QueueFaultNativeTransport.provision()` against actual `POST /oauth2/token` before RPC, then retain its real List metadata after exchange and authenticate WhoAmI before the original admission. Preserve the persisted `createdAt`/`expiresAt` separately from the JWT's `accessExpiresAt`. `wait_actual_token_expiry` requires real 403 `permission_denied` while the JWT remains within its separate expiry, plus the unchanged active, unretired List record. A 401 JWT denial, a pre-expiry denial, or changed token metadata refuses. Independently join current actor facts and the actual denied Complete retry. |

The provisioning response and JWT are separate private files, never logs or
returned secret values. Every RPC rechecks the exact original JWT digest; the
persisted provisioning secret is used only at `/oauth2/token`. The expiry
comparison retains actual client UTC observation and requires the selected
fixture's independent clock alignment evidence. A denial alone cannot prove
that expiry was its cause or establish actor/purpose/provider qualification.

The wrapper's one-shot latch is process local. Restart does not preserve its
disarm. A reviewed restart configuration must explicitly select `fault: none`
when testing later recovery; retain both configuration hashes. Preserve the
existing qualifier Begin/restart/requeue originals separately. These helpers
do not convert that qualifier into production session redelivery evidence.

Before any publication-eligible retry, retain the pending snapshot and provider
log cursors. A pending report requires zero completion receipts and publication
`preparing`. `assert_pending_did_not_publish` refuses selected provider mutation
receipts, unknown callers, unknown methods and unpartitioned physical paths.
Capture completeness, authentication and exact source/key mapping still require
independent review. An empty supplied list does not qualify zero Native bulk;
`nativeBulkBytes` and acceptance stay null until the actual body assessor joins
the complete Native and provider windows.

## Confined controlled provider replacement

`queueFaultProvider` accepts the actual completed-object Map from an existing
controlled provider, plus one exact selection:

```json
{
  "version": 1,
  "runDigest": "<fresh 64 lowercase hex digits>",
  "bucket": "fixture-bucket",
  "key": ".aos-direct-qualification/<runDigest>/queue-fault/source/payload",
  "expected": {"version": "<actual version>", "etag": "\"<actual ETag>\"", "sha256": "<actual SHA256>", "byteSize": 8388608}
}
```

The selected fault object is at most 32 MiB. This bound applies to the additional
controlled replacement case, not the real 2 GiB queue resource measurement.
Call `read(request, response)` only after the owning TLS provider fixture's real
SigV4 verifier, and delegate when it returns false. It intercepts only selected
GET/HEAD. It supplies no verifier, credentials, Write/Delete capability, provider
contract or production binding. Leave the existing upload/close handlers intact.

Call `administer(request, response)` on a distinct owner-only loopback listener.
Its endpoints are `POST /fixture/queue-fault/replace-source` and
`POST /fixture/queue-fault/arm-source-replacement`. The body must be
the adapter's exact closed `trigger` object: version, runDigest, keyDigest and
expectedIdentityDigest. No caller-selected replacement URL, bytes or key is
accepted. The one-shot action rechecks actual old bytes/version/ETag, changes one
byte of that stored object, derives a new identity, and retires the old serving
incarnation. `privateIdentities()` retains actual old/current version, ETag, SHA
and size; keep it in the private fixture evidence. Numeric `snapshot()` records
the actual old/new commitments, replacement count and read selections. Replacement
administration is separate from provider SDK mutation counters. The arm form
defers that one replacement until the first actual selected GET after signature
verification. Arm it before enqueue/delivery, after the selected completed object
exists. It introduces no scheduling sleep or read hold. A foreign path or
different version/ETag cannot consume the arm; store drift refuses before mutation.

An explicit old version receives 404; an old If-Match against the new incarnation
receives 412. An unconditional GET receives the actual changed bytes. No fake
412 is injected. Response-offered bytes are provider writes, not measured client
consumption. Retain actual downstream consumption separately.

`external_object/stage/executor.rs` constructs `VerifyClosedStage` through
`closed_stage_read_request`, which signs the retained strong ETag in If-Match and
includes the actual provider version when present. The complete SHA/size verifier
also checks bytes returned by the provider. Retain the actual request condition,
version and provider response before reporting conditional-read refusal; preserve
post-hash refusal as a separate observation. This Map adapter does not qualify
Garage or a hosted provider. The test trigger deliberately violates a source
serving assumption; it proves no provider immutability guarantee.

## Whole-handler resource observations

The wrapper emits `direct_queue_fault_observation ` followed by a closed JSON
object. Fields are version, sourceDigest, runDigest, kind, invocationDigest,
atMillis, jobDigest, batchMessages, selectedMessages, outcome and sdkReturned.
All identifiers are digests; no URLs, material, body or provider references are
logged. Invocation entry precedes selection inspection and callback dispatch;
exit records actual return/throw. Missing exit remains unresolved.

For a dedicated singleton queue window, start the source-built collector before
delivery and finish after the actual handler exit:

```text
<AOS Python>/bin/python3 -B tests/fleet/_hub-direct-invocation-resources.py \
  --pid <owned workerd PID> --executable <actual registered workerd path> \
  --start-ticks <observed lifetime pin> --duration-seconds <bounded duration> \
  --interval-millis 100 --output <fresh owner-private report path>
```

The collector validates ownership, executable, argument digest and process
lifetime at every sample. It never signals a process. `single_invocation_resources`
requires one selected singleton wrapper invocation, an actual whole production
attempt and no overlapping observed handler/queue invocation. Retain complete
logs/configuration and exact process identity so that a missing invocation cannot
be hidden by a selected excerpt. Native work, separate provider processes and
other workerd child processes are outside this process counter.

Linux counters measure all CPU threads in that process. Brackets wholly before
entry and after exit provide a conservative CPU envelope with tick quantization
reserve. VmHWM is lifetime process resident high-water, including startup and
other isolates. Neither is platform charged invocation CPU or per-isolate memory.
Those facts remain explicit nulls. Process exits, missing brackets, concurrent
observed calls, counter drift and clock steps leave the join unresolved.

`foreground_comparison` compares measured whole verification wall time with the
retained original foreground window, the actual conservative dispatch clock and
settlement reserve. It never extends a deadline and establishes no foreground
execution, CPU or memory acceptance. Current Complete queues verification; an
inline execution claim needs its own actual path and measurements.

## Local source gates

Use only declared AOS-built Node and Python:

```text
<AOS Node>/bin/node --test tests/fleet/_hub-direct-queue-fault-worker-tests.mjs tests/fleet/_hub-direct-queue-fault-provider-tests.mjs
<AOS Python>/bin/python3 -B tests/fleet/_hub-direct-queue-fault-tests.py
```

Node tests exercise controlled SDK callback boundaries and actual owned loopback
HTTP provider reads/replacement. Python tests exercise exact original/refusal
joins and actual CPU/RSS sampling of their own child process. They do not run a
Worker, Native authority, queue, Hosted provider or final fleet. Actual selected
runtime fault windows, SDK proxy compatibility and platform resource acceptance
remain pending a reviewed common tuple and explicit fixture integration.
