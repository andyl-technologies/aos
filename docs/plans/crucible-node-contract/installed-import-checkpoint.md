# Installed-import checkpoint and consumed journal retirement

This is a proposed implementation sequence, not an implemented codec, release
rule or qualification result. Source reader references were inspected on
2026-10-16; they do not extend the original implementation-study audit. The plan
separates a bounded first change to decoded import ownership from later
retirement of consumed action journals. RFC-0025
remains the target: [CN-STATE-6](../../rfcs/0025-crucible-node-contract/05-state-and-replay.md)
permits verified immutable state, [CNP section 6.6](../../rfcs/0025-crucible-node-contract/06-provider-protocol-and-security.md#66-idempotency-retry-and-reconnect)
requires durable consumption and nonreuse for journal eviction, and CN-STATE-15
forbids hiding state transitions inside exact Capture.

## First increment: release decoded import duplicates

The first increment replaces repeated reads of the initial archived validation
graph with a distinct installed-import checkpoint reader. Here the checkpoint
is a local, nonportable validation witness, not a newly published archive root.
It releases only independently decoded initial-import duplicates in Core's
`ColdGroup`. The verified original archive and immutable content remain retained
and available. Every native/SDK Commit, World, upload, current pair, action
attempt, deferred witness, model, pending event, pin and spent counter stays live
and unchanged.
It does not retire requests, shrink action history, refund lifetime quotas or
require the later post-Observe journal protocol.

The current selected path retains the actual decoded Host, native-before,
native-after and registry owners in
[`archive_owner/retained.rs`](../../../crates/crucible/engine/crucible-engine/src/node_adapters/cnp/semantic/packet_complete_source/archive_owner/retained.rs).
Clearing the unrelated Owned11-only `InstalledArchivedProtocolState` slot would
not change these consumers. A digest or a successful installation flag cannot
replace the predicates they currently evaluate.

The first concrete cohort releases only decoded native-before, native-after and
registry owners; it retains decoded Host for the actual original Capture-terminal
signing loan until a separately admitted terminal projection replaces that loan.

Implement this sequence under a new explicitly selected reader family:

1. **Reach genuine installation.** Complete all four actual owner restorations,
   durable target World activation, all three MAC-verified first Observes and
   all three verified continuation seeds. Preserve the original full validators
   and their Source/native fences through this point. An archive decoder, copied
   receipt, caller-supplied root or initial geometry row cannot issue the witness.
2. **Admit the transition before work.** Under the same runtime, Window, plan,
   Source members, tickets and read owners, retain a once-attempt transition
   owner and independently admit its evidence, immutable lookup, hashing, decode,
   destination and observer demand. Count old owners and all new partials
   simultaneously. Reject pending action/current-observation/Capture scopes,
   unresolved installation and live old-view loans.
3. **Bind the installed checkpoint.** A private constructor records the actual
   source-owner roles, target World, signed index/manifest/runtime/semantic/
   ancestry/protocol/model full references, initial cursor/inventory, and exact
   installed Commit/Hold/World/first-Observe/seed correspondence. Retain the
   bounded initial journal and Capture-terminal facts still needed by signing
   readers. Verify each reference against the admitted immutable closure.
   Existing verified archive bytes and the actual fresh Commit/World/Observe/seed
   owners remain retained. Sealing their local correspondence needs no additional
   durable publication in this increment. No mutable original path is a fallback;
   exporting that correspondence later requires a separately versioned portable
   writer/reader and genuine durable placement, not serialization of the witness.
4. **Replace readers before releasing storage.** Initially run the new reader
   beside the old full-owner predicates and compare their complete results.
   Each later selected SourceRead must authenticate the installed witness and
   actual live native/SDK proof, with final same-owner/currentness fences. A
   historical initial cursor never substitutes for the current checkpoint after
   model progress. Switch only after every reachable old cold loan has a new
   reader or a proven phase refusal.
5. **Install, then take the enumerated duplicates.** The current immutable
   `Window.cold: OnceCell` is not an owner that can simply be emptied through
   an `Rc`. Introduce an explicit selected state owner with synchronous bounded
   loans and guarded transition. Acquire borrows and preallocate the destination
   before the final fence; install the completed checkpoint before taking the
   actual eligible decoded owners. No allocation, callback or serialization may
   follow the point where their removal becomes irreversible. Keep any ancestor
   still required by a saved signing/context reader.
6. **Recount actual owners.** Only actual release followed by a complete fresh
   owner census can reduce resident storage. Narrow recurring validation demand
   only for work made unreachable by the replacement reader; remaining live
   native/history work stays independently funded. Saved rows, counts and spent
   permissions are not renewed. Capture remains a later, separately admitted
   read of the reached state and its pinned immutable dependencies. Any decoded
   owner still required by an existing Capture reader stays outside the release
   roster until its paired portable writer/reader exists. A local witness cannot
   be persisted as reconstructed live authority; unsupported new representations
   must refuse before effects.

These current reader sites define the minimum replacement surface; the
implementation must also audit their callers and error paths:

| Consumer | Required replacement or phase proof |
| --- | --- |
| [`window/observation_continuation.rs`](../../../crates/crucible/engine/crucible-engine/src/node_admission/conformance/restoration_construction/window/observation_continuation.rs) | Replace repeated archived runtime/protocol/native validation while retaining actual current Source/native checks. |
| [`window.rs::original_signing_inputs_data`](../../../crates/crucible/engine/crucible-engine/src/node_admission/conformance/restoration_construction/window.rs) and `archive_owner/retained.rs` | Supply the authenticated initial journal/Capture terminal from the new bounded immutable reader; activation and later signing callbacks reach this path. |
| [`window/continuation.rs`](../../../crates/crucible/engine/crucible-engine/src/node_admission/conformance/restoration_construction/window/continuation.rs) and [`window/installed_context.rs`](../../../crates/crucible/engine/crucible-engine/src/node_admission/conformance/restoration_construction/window/installed_context.rs) | Add distinct installed-checkpoint loans, or prove each old branch is unavailable after transition; preserve ordinary failure and partial-owner handling. |
| [`restoration_activation/evidence.rs`](../../../crates/crucible/engine/crucible-engine/src/node_adapters/cnp/semantic/packet_complete_source/ack_peer/association/restoration_activation/evidence.rs) | Keep actual saved Commit/World pairs and immutable Hold lineage; join the new archived-validation reader under the same SourceRead. |

A failed admission, immutable lookup, validation, live borrow or final
currency check retains the old graph and every actual partial transition owner.
An issued attempt stays spent. If a local no-fail replacement cannot be
established, retain both completed graphs rather than leave half-erased
ownership. Decoded checkpoint DATA supplies no Source key, physical Hold, native
registration, Window, ticket, grant or resumed permit; genuine fresh constructors
issue those.

## Later increment: retire a consumed action prefix

This is a separate administrative transition. The first increment does not make
current SDK journals, native ledgers or Source Producer attempts disposable.
The later order is:

```text
actual Begin/Poll outcome -> durable result publication -> scheduling commit/ACK
-> matching native Consumed Retire -> fresh grant-free Observe
-> separately durable checkpoint DAG -> authenticated retirement receipt/ACK
-> install checkpoint + nonreuse state -> release only eligible consumed owners
```

The existing result root precedes Retire and final Observe. It cannot certify
those later records. Native Producer Retire also does not retire every Poll,
Observe or upload request or prove all content pins discharged.

The new post-Observe checkpoint must contain the exact eligible raw/typed pairs,
Outcome and consumption evidence, native proofs and measurement content, latest
model/cursor/inventory, immutable first ancestry, previous checkpoint identity,
logical operation/slot counts, originating ID/hash roster and required deferred
prior event/evaluation/completion/payload evidence. Use a bounded acyclic DAG
with checked count, depth, individual/total size and separately admitted lookup
and decode work. A real durable publisher must accept its complete reachable
closure and retain the exact root before protocol retirement starts.

Add separate native and SDK installed-checkpoint/currentness readers before
removing their historical owners. The receipt must bind the same current
Source/World/controller/native epoch, consumed prefix, checkpoint root and
explicit retirement IDs. Retain actual receipt transfer and ACK custody through
positive completion. If administrative retirement moves the Session frontier,
keep its verified before/after bridge and same-model correspondence; an old
Observe pair must not become current through fallback.

Client journal lookup must distinguish **Live**, **Retired** and **Absent** on
every assignment, retry, resend, receive and fresh-unused path. Retired request
IDs stay nonreusable in their origin/session/incarnation; changed material
conflicts and retired operations return `OPERATION_RETIRED`. Lifetime request,
frame, byte and operation ceilings remain independent of live map/vector sizes.
Do not recycle their credit in this increment. Preserve absolute historical
frame ordinals if literal banks are externalized; never renumber live slots.

All current model state, pending reactions/deliveries/outputs, native grants,
current registration/Hold/control identity, active original custody, latest
required proof/frontier, failed/uncertain/malformed attempts, quarantine and
unsettled pins remain exact and live. Retain the immediately prior operation
until its deferred consumer is discharged unless the replacement historical
reader fully validates that dependency. A stage flag, report hash or common
Outcome equality cannot establish discharge.

Preallocate checkpoint/tombstone slots and retain the transition before effects.
Unknown publication, partial upload/Retire/ACK or a failed final fence preserves
old plus partial new owners. Reconciliation uses the same actual attempt and
identities; it cannot repeat modeled effects or mint replacement credit. Only
an acknowledged, privately issued same-owner transition may perform a no-fail
swap. Capture never publishes, drains, retires, ACKs or retries this transition.

## Compatibility and behavioral acceptance

Use explicit new versioned checkpoint writers/readers and negotiated selection;
legacy11/15/16 entrypoints keep their full predicates and refuse new bodies.
The proposed settled17 family is a distinct path, not a cast into old Owned11.
An immutable ancestral component may use its genuine old decoder without making
current checkpoint DATA old live authority. Any needed capability/schema roster
must be present before the original implementation/binding is hashed; preserve
that exact implementation and actual preservation profile in fresh targets.
Never rekey an old archive or change a profile to force compatibility.

Accept the first increment only after genuine restoration, first Observe, seeds,
recurring Observe and nonempty Producer/deferred continuation agree with and
without the explicit transition. Instrument old cold-reader entrypoints to
prove the selected post-transition path cannot reach released graphs. Include
foreign/stale World, member, root and role negatives; active old loans; missing
or tampered dependencies; and one-short row/byte/decode limits. Failures must
retain old/partial owners and never reopen a once attempt.

Accept later retirement only after two genuine operations across checkpointing
preserve private state, deferred event timing, nonempty payloads and scheduling;
retired/changed IDs remain refused; lifetime ceilings and cap-next negatives
remain effective; and altered/missing/cyclic DAG dependencies fail strict loading.
Exercise interrupted durable placement, readback, pin settlement, receipt/ACK
and final fences. Verify Capture before/after success or failure leaves the
corresponding reached state and transition count unchanged. Load the same signed
checkpoint into two independent fresh Worlds and continue both after removal of
the original mutable scene/publication stores, retaining only the declared
immutable implementation and archive closure. Preserve legacy positive and
negative controls. These are required behaviors, not reported test results.
