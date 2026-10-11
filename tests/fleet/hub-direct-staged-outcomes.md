# Staged outcome fixture contracts

These fixtures retain finite source Complete loss, destination Complete loss and
Native completion-receipt persistence cases. They do not alter application Rust,
admission, ordinary deployment configuration, provider permission or journal
state. Raw observations and callback outcomes remain separate from qualification.
Selected staged-supervisor and positive cold issuer recovery dependencies must be
reviewed independently before calling these cases.

## Called subset

`_hub-direct-staged-matrix.py` consumes the selected Native staged supervisor's same-child handoff:

```text
before_complete(prepared, private_scope_root, deadline_monotonic_seconds)
  -> {admissionObservation, wrapperObservation}
```

It requires the actual Report `status` in the prepared envelope, state `creating`,
unchanged session/fingerprint, intent, placement and RV. It reopens the retained
Complete body, source and handoff references. Native's handoff refs have exactly
`{file, bytes, sha256}`; observation refs have `{file, sha256, byteSize}`.
Both count fields are bounded canonical decimal strings. Integer, boolean,
leading-zero and oversized counts refuse before numeric comparison. No broad
schema fallback or fresh admission is created. The original child continues its
first Complete once. The adapter never encodes or dispatches that mutation.

`refs.beginBody` is mandatory and must contain the unchanged original intent.
`refs.capabilities` is present exactly when retained selectionValues uses the
capabilities alternative instead of a preselected placement. The copied actual
capability bytes are reopened with a 256 KiB bound and matched to the original
selected hash/count. They are retained association evidence, not authentication
or renewed discovery. Native independently reopens its original selection file
and validates every capability/association before actual progression.

Prepared `clock` is exactly `{bootId,cutoffUptimeMs}`. The default matrix path
requires execution in the original CLIENT guest: private reference locators,
root/file custody and proc boot/uptime are checked there. The printed uptime
resolution is added conservatively before comparison; rounding grants no time.

A controller caller cannot apply these local Path/stat or proc-clock operations
to guest locators. It requires an independently selected source-owned CLIENT
reference reader, actual guest clock custody and genuine guest CLI continuation.
Those caller adapters must preserve raw locators/hashes/owner/mode/link checks and
the original eligibility. The controller's callback deadline is measured in its
own clock; a guest monotonic scalar cannot stand in for it.

The optional `client_io` is the called owner's selected `ClientPreparedIO`:

```text
read_reference(reference, original_guest_scope_root, maximum) -> bytes
within_original(prepared, controller_deadline_monotonic_seconds) -> None
continue_acknowledged(selection_file, accepted_originals_file, fresh_output) -> actual_phase_result
```

Matrix validates the same closed count/hash/original commitments before and after
delegating reads. Guest locators never reach controller file operations or proc
clock reads. The selected adapter retains actual root/file custody and guest
clock observation with conservative round-trip age; those facts grant no
admission or authority. The initial phase pin names the genuine Python launcher,
not Node. An exited initial parent stays historical during a fresh continuation;
actual Node lifetime is only available from Native's retained supervision.

No supplied ready dictionary establishes this connected caller. A controller
invocation must select the actual installed reader/launcher source and its tool
hashes, preserve current process custody, and retain the actual observations.

`run_prepared_case(driver, observe, retain, case=..., scratch_sql=...,
arm_provider_loss=..., continue_original=..., commit_original=...,
client_io=...)` calls the driver exactly once. A same-guest caller binds `driver`
to the staged supervisor's existing `run(..., before_complete=callback)`. A
controller caller uses the source-owned CLIENT phase launcher with the existing
external pre-Complete mode, performs actual selected checks, then publishes its
create-only guest continuation. It must provide a controller-local callback
deadline and preserve the guest prepared envelope and locators.
Supported called cases are source Complete response loss, destination Complete
response loss, and Native completion receipt INSERT refusal. The caller's
`observe("before", prepared)` returns the two actual bounded private refs;
`observe("after", prepared)` retains subsequent receiver/journal/SQL/SDK
observations even if the driver threw; missing preparation is passed as NULL.
`arm_provider_loss(case, prepared, item)` must return the transport owner's closed
selection JSON as a private reference. Its kind, full original body and cutoff
must match the saved Complete body; the arm cannot extend that cutoff. The
actual emitted provider request must be captured before constructing this
selection, rather than predicting its signature or key. The caller still needs
an existing owned request-hold boundary connecting that observation to the
pre-Complete continuation; this draft does not claim that connection is installed.

For source Complete response loss, both progression and publication Commit
callbacks are forbidden: an unknown initial reply stops. Destination Complete
response loss requires `continue_original` after the actual initial HTTP200
pending acknowledgement, because normal destination completion occurs in later
object progression. It forbids publication Commit. An unknown later reply stops
without another continuation or reissue. Missing progression refuses before the
first driver. A successful callback alone does not prove that the selected
provider fault was reached.

For the SQL case, `continue_original(prepared, first_outcome, original_root)` and
`commit_original(prepared, progressed_outcome)` are mandatory. The former calls
the selected Native standalone entry point for this exact acknowledged original,
while the trigger remains installed. The first 200 pending Complete only queues
verification. Following actual error-free known pending acknowledgements, normal
same-original Complete progression can advance object phases. UNKNOWN/refused/
lost replies stop; no reissue follows. The latter is the distinct actual normal
publication Commit path. Object `committed` is not publication Commit/visibility.
After-observation and cleanup run after either callback returns or fails. Missing
callers refuse before the first driver; no Commit DTO is constructed here.

The small source-owned continuation adapter is:

```text
continue_acknowledged_original(selected_native_supervisor, selection_file,
  accepted_originals_reference, original_private_scope_root, fresh_output,
  prepared=actual_prepared)
```

It reopens the closed actual accepted-original file and exact prepared/first
response locators. Input is `{version:1,originals:[{scope,prepared,firstResponse}]}`,
with one original and private `{file,sha256,byteSize}` refs. Initial response must
be actual 200 with the original Complete request ref. It then calls exactly
`selected_native_supervisor.continue_acknowledged(selection_file,
accepted_originals_file,fresh_output)`. It does not stage, reconstruct or issue a
request itself. The selected Native entry point validates full raw pending
reply/operation/session/intent/placement, prior markers, every original byte and
same boot/cutoff before mutation. It creates its own create-only consumed marker
and never repeats after an unknown next reply or crash. Its incomplete result
explicitly says `publicationCommit: "not_invoked"`.

For a controller caller, pass `supervisor=None`, the selected `client_io`, and
`deadline_monotonic_seconds` from its independently selected original controller
window. The actual guest adapter invokes the same Native CLI using the original
phase selection file and a create-only accepted envelope inside the original
scope. Only fresh output/log/invocation paths are new. The CLI's normal retained
incomplete observation exits **2**, including verified object progression;
errors exit **1**. The adapter must retain every actual outcome first, then require
exit2 without timeout, exact accepted-original incomplete summary, one selected
scope with object terminal `committed`, and `publicationCommit: "not_invoked"`.
Missing/refused/lost outcomes stop before any further mutation. Exit0, a result
file alone or the word `incomplete` cannot substitute for those checks.

The actual caller must bind
the installed source-built supervisor to this named source; a supplied Python
object or dictionary is not evidence of that installation or authority.

All conclusions keep `phaseQualification`, `providerSettlement` and
`noReissueQualification` NULL. A same-original negative/replay, complete scoped
dispatch inventory and independent actual current SQL/authentication joins are
mandatory caller prerequisites before runtime qualification. Normal control
ACKs, local HTTP counts, raw collector files and callback success do not replace
those joins. Driver, cleanup and retention exceptions preserve the active
original error; an otherwise successful driver with failed cleanup must fail.

Create/Abort are supported by the selected transport owner, but the existing
pre-Complete handoff occurs after Create and cannot inject those cases. An actual
normal original callback before the corresponding dispatch is still required.
Native Commit response loss also needs its current typed authenticated envelope
consumer. The existing Copy Closed-loss caller is reusable for its own real
original; it is not silently relabeled as Direct Commit. These missing called
phases remain incomplete, rather than replaying a manufactured request.

## Transport owner

`createStagedLoss(selection, owner_private_root, actual_upstream_port)` returns one
handler for an existing owned listener. It starts no server. The installed caller
must select and observe a connected loopback route before startup; existing
Garage3900/3902 routing and unrelated traffic stay under their current owners.

Selection fields are closed:

```text
version=1, kind=create|source_complete|destination_complete|abort
originalSha256, originalReference={file,sha256,byteSize}
method=POST|DELETE, target, host
requestSha256, requestBytes, rawHeadersSha256
cutoffUnixMs, expected={bucket,key,uploadId}
```

The handler reopens the private full original and pins it before forwarding. It
matches actual method/target/Host/raw-header commitment and bounded body exactly,
then invokes loopback upstream once with the unchanged selected URI/body/headers.
The fixture caller must independently join that request to actual protected
admission/current physical owner and provide actual selected provider TLS custody.
An HTTP loopback response alone does not establish those facts.

Request/reply bodies and retained metadata are capped64KiB. The original wall and
monotonic deadlines both apply, with a30s maximum arm. Abort requires actual204
and empty body. Create and Complete require closed bounded S3 XML with the exact
Bucket/Key; Create records the actual UploadId. Complete requires strong ETag and
cannot accept an HTTP200 Error body. Unknown/duplicate/truncated XML refuses.
This intentionally narrow parser cannot qualify an unsupported provider reply.
The raw reply/body/headers and parsed positive are persisted before caller socket
destruction. No provider mutation is retried. Failed retention, cancellation or
deadline yields unknown. `upstreamEndInvocations` is a local call counter;
`providerDispatches`, `journalPersistence` and `providerSettlement` remain NULL.

## Scratch SQL fault and restore

`ScratchSql` takes the closed selection:

```text
version=1, runId=<32 lowerhex>
databaseName=fleet_staged_<runId>, databaseUrlFile, postgresBin
deploymentId, sessionId, operationId=<64 lowerhex>
logicalFingerprint=<64 lowerhex>, expectedResourceVersion=<canonical positive decimal>
cutoffUnixMs
```

The selected scratch database must be genuinely created/admitted through normal
APIs, with independently observed source/profile/process/schema pins. The fixture
does not provision a database, seed a session, grant permissions or copy a receipt.
`postgresBin` must contain the selected canonical immutable AOS-built psql,
pg_dump and pg_restore; actual hashes and private URL hash are retained. No URL,
password or raw error is emitted in summary output. Commands inherit the original
environment without rewriting HOME. The selected URL is parsed into private
PGDATABASE/PGHOST and any explicit PGPORT/PGUSER/PGPASSWORD child environment
values. Conflicting PGSERVICE/PGHOSTADDR are excluded. Those values and the URL
are absent from process arguments and emitted receipts. pg_restore receives only
the non-secret selected database name in its required `--dbname` argument.

`install_fault()` first checks actual connected database, selected session
fingerprint/RV/state, and unused generated trigger/function names. It installs a
transactional `BEFORE INSERT` trigger on `direct_upload_completion_receipts`
restricted to the exact deployment/session/operation. Other originals pass
through unchanged. The real Native checked batch must then fail with the retained
selected exception after positive physical work; the collector independently
checks unchanged target/accounting/session rows and absent completion receipt.
Installing this trigger alone is not evidence that the intended INSERT ran.

The installed catalogue observation binds the actual target relation, function
and trigger OIDs, exact function body/language/return type, ROW+BEFORE+INSERT,
normal enabled state, zero arguments and no WHEN/transition/constraint behavior.
Successful installation must pass this check and retain the full pinned image.
A same-name trigger calling another function or using another event is refused.

`remove_fault()` verifies the exact pinned image before removal, then rechecks
that same image in the locked-table transaction containing both DROP statements.
The selected scratch resource remains under the fixture owner's exclusive DDL
control; this is not a general concurrent administration facility. An uncertain
install with no remaining objects is observed as absent. If objects remain but
no validated installation image was retained, cleanup refuses and remains
unknown. Foreign/replaced definitions refuse removal. Cleanup DDL has a separate
fixed5s per-command bound (at most five commands), never a renewed provider grant
or target settlement. Ordinary SQL commands remain inside the selected cutoff.
Temporary output and SQL errors are bounded; unknown cleanup survives failure.

`snapshot()` and `restore(snapshotRef)` act only on this selected scratch DB and
the create-only owner-private dump under this object's root. Dump size is capped
256MiB and hashed in64KiB blocks. `restore_scratch` calls the selected real Native
stop/restart lifetime callbacks and existing issuer/current-state observations.
Those callbacks must quiesce all scratch writers before backup/restore and retain
actual process pins. Restore must run against the disposable DB, while issuer/
Worker journals stay untouched. The resulting old SQL state is tested through
actual current remote reconciliation/admission; NULL qualification is retained
until those independent signed/current facts are complete. A successful pg_restore
is neither admission nor provider-drain evidence.
An uncertain restore or start is retained without an automatic second launch.

## Authority scope

`replay_previous_publication` reopens an actual earlier private SQL export and
passes unchanged bytes' document to the existing shared Rust issuer exchange for
a fresh authenticated Publish. A refusal must be distinguished from expired
transport/bad authentication, then joined to a separately verified current head.

`rotate_credential` calls existing reviewed PlanRotate/Rotate and actual validation
APIs for a genuinely different private secret version/fingerprint. It stages the
exact failed unstaged probe original, explicitly retries that task through current
RV CAS, and waits for real completion. Export/hydrate/current issuer publish and
the pre-rotation old capability/unknown guard are separate mandatory caller joins.
It does not replace issuer signing keys, clear a guard, claim old-tail settlement
or let credential cutoff stand for drainage.

Worker Finish and Stage Terminal receipt-persistence faults remain unavailable:
there is no established exact selected backend fault here. Generic quota/read-only
failure can hit an earlier clock-floor/CAS write. Runtime valid same-generation
fork generation is unavailable from ordinary monotonic CAS/export. Existing Rust
deterministic journal/fork tests remain separate source evidence. No speculative
DO database edit, JS storage Proxy or production fork producer is included.

## Focused gate plan

After source review, run only changed matrix cases using the selected AOS-built
Python, with at most two CPUs and a 180-second bound. Relevant subcases cover
actual string-count shape, raw Begin/capability substitutions, strict clock
binding, selected continuation arguments, initial acknowledgement refusal,
case-specific progression/Commit requirements, and unknown progression stopping
before any publication Commit. Test supervisor/callback substitutes are
controlled; they do not authenticate a pending reply or admit a writer.

Unchanged local transport and SQL tests retain their earlier source-bound scope.
They exercise disposable HTTP response ownership, bounded input/EOF/cutoff,
private-file custody, selected SQL catalogue definitions, changed trigger linkage
and event/enabled predicates, cleanup refusal and original exception preservation.
These tests cannot prove actual PostgreSQL rollback, current issuer authority,
provider no-reissue or a connected controller/CLIENT caller.

Before fixture activation, review the actual called reference/clock/continuation
adapters, original/receiver/SDK/SQL collectors, fixed initial network route,
eligibility, process ownership and disposal. The scratch PostgreSQL gate must
execute real production finalization against the scoped trigger, verify complete
transaction rollback and remove only the exact owned fault. Provider windows
need actual positive response, unknown/restart and unchanged-original no-reissue
joins. Managed R2 and External S3 remain separate. Missing multipart POST capture
or guest custody adapters remain explicit activation prerequisites.
