# Independently observed node execution

The `crucible-campaign::observed_node_attempt` module implements a separate
versioned request, result, reservation, lifecycle and worker family for admitted
node realizations. It does not extend the legacy deterministic `Observation`
codec or populate its attempt memoization indexes. No existing checkpoint,
lineage, campaign fact or observation acquires a new backend identity.

## Identity and admission

`ObservedAttemptRequest` binds an independent nonzero `ExecutionId`, the complete
`ExecutorNodeCapabilities`, and a retained input closure. Its `plan_digest()`
excludes the execution nonce; its request digest includes it.
`ObservedAttemptResult` additionally binds actual incoming and outgoing trace
roots, retained outcome evidence and the observed outcome. Consequently, two
physical executions of the same planned configuration remain different observed
results even when their trace bytes happen to be identical.

Repository admission loads and authenticates the exact scenario and
configuration artifacts, checks their relationship, authenticates the retained
input closure, and invokes the mandatory `ObservedAttemptAdmission` verifier.
That verifier must bind the artifact payloads and inputs to the host-sealed graph,
including every execution/capture owner and complete provider compatibility,
clock policy, ordering, device and external-context inputs. Matching names or
comparing unverified digests is insufficient. Native adapter realization
validation happens before reservation or dispatch effects.

The admission verifier performs local authentication inside repository
publication/mutation exclusion and cannot trigger native effects, mutate the
repository or acquire a later subsystem fence.

Version one explicitly supports fresh execution. An advertised exact-restore,
live-fork or transcript capability does not implicitly authorize a source
closure or qualify deterministic replay. Retained observations alone never
authorize equivalence checks, cache reuse, thin replay or minimization.

## Publication and recovery

The authoritative namespaces are:

| Namespace | Binding |
| --- | --- |
| `observed-attempt-ledgers/<name>` | Exact realization digest and a Merkle index of execution lifecycle records |
| `observed-execution-reservations/<nonce-digest>` | Original execution nonce, ledger name and immutable request |

The nonce namespace prevents the same execution from obtaining a new dispatch
permit under another ledger name. Every immutable object precedes its owning ref
publication. The worker starts the native adapter only after both the nonce
reservation and the ledger reservation succeed. The first reservation returns a
non-cloneable, non-serializable `ObservedExecutionPermit`; every retry returns
existing state instead.

Native startup or polling uncertainty quarantines the nonce. A crash or uncertain
store error between the two ref publications likewise quarantines recovered
ownership. A reconstructed worker cannot restart a retained `Reserved` execution.
An explicitly new nonce represents a new physical sample. Completed publication
is idempotent only for the original request and result bytes; divergent retry
bytes cannot replace a recorded result.

Quarantine also requires native containment: the adapter stops or fences every
coupled owner and withholds further budgets. Pending containment retains active
worker ownership even after ledger quarantine succeeds. Repeated containment
checks cannot start or resume native execution. Only complete containment
acknowledgment releases that worker slot.
The worker refuses additional fresh dispatch while containment is pending.
Realization admission also authenticates physical-owner leases and incarnation
fences, preventing another worker from reusing uncertain native ownership.
Dropping the native adapter transfers unresolved native, ledger and scheduler
custody into an already-reserved owning retirement slot. It cannot release
physical-owner leases while unresolved execution survives.

When evidence publication fails after native completion, the worker retains the
original result and retries publication only. It never polls or starts the
native execution again. Quarantine publication failures similarly retain their
pending host work. Deployments needing restart durability require durable blob
and ref backends; the memory backend remains a process-local fixture.

## Retention and schema validation

New records use exact, version-one generic `ContentEnvelope` schemas. Request,
result, lifecycle, ledger and dispatch-reservation records derive their complete
child tables from canonical bodies. Unsupported versions, wrong object kinds,
omitted/extra children and noncanonical or trailing bytes refuse. The legacy
`ObjectEnvelope` decoder continues to reject this record family.

The campaign closure walker and object profiler explicitly authenticate these
new schemas. The existing GC root inventory includes both authoritative
namespaces as ordinary ref roots, so retained input artifacts and actual
provenance participate in the same authenticated closure walk. Observed results
are canonical evidence, never rebuildable deterministic cache entries.

Adapters must retain native pending-result evidence until publication succeeds.
A GC retention owner inventories `ObservedAttemptWorker::retention_roots()` under
the same ownership fence that excludes worker mutations. This protects evidence
while the ledger still contains only its reservation. Actual boundary trace roots
use opaque `Trace` objects; hierarchical evidence uses the supported versioned
envelope/manifest closure formats.

Concurrent owners acquire repository GC exclusion before taking the worker's
mutation/retention fence. This follows GC's ref-before-operational-owner lock
order; native adapter callbacks do not run under repository mutation locks.

## Validation

Focused contract tests cover independent physical identities, strict codecs,
failed admission, reservation before native effects, nonce reuse across ledgers,
partial reservation recovery, uncertain startup/poll quarantine, worker restart,
publication-only retry, divergent completion refusal, retained provenance,
object profiling and SQLite/directory reopen.

These fixture adapters verify host transaction and identity semantics. They do
not qualify native QEMU, gem5, KVM or external-device determinism, pacing,
transcript completeness or exact-state capture. Native adapters must implement
the admission and backend contracts and supply their own qualified evidence.

```sh
bash tools/dev/aos-dev cargo test --manifest-path crates/Cargo.toml \
  -p crucible-campaign --lib observed_node_attempt::tests --locked
```
