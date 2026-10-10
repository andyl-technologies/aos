# 08. State transfer

## 08.1 Scope and baseline

This chapter proposes transfer of complete authenticated exact closures using
logical RAM trees. Transfer operates on host-side state; an unmodified guest
does not participate, expose a paging interface, or receive migration-related
events. The same logical image can be materialized on a different admitted
instance or machine without changing guest RAM capacity or the declared
operating-mode contract. Equal RAM contents do not authorize cross-profile
continuation.

The [historical transfer inventory](../../plans/crucible-paged-ram/current-state.md)
records existing archive and offline maintenance integration points.

These facilities are a foundation for the design here. They are not evidence
that live migration, remote fault serving, pre-copy, post-copy, or distributed
execution ownership are implemented. This chapter specifies an admitted
complete-closure transfer mode and identifies additional gates required for
future modes.

- **[TRANSFER-1]** The initial transfer mode MUST transfer a coherent complete
  whole-world exact closure and establish mode-specific destination readiness
  before any source execution authority is destructively released. A RAM root
  alone MUST NOT be offered as a resumable machine or world.
- **[TRANSFER-2]** Host location, transfer progress, packing, physical page
  size, and paging-policy settings MUST NOT alter the logical RAM roots or
  modeled configuration. Destination execution MUST retain guest transparency,
  capture compatibility, and the admitted operating-mode contract. Deterministic
  profiles MUST retain their deterministic clock/event-order contract; KVM MUST
  retain PROFILE-5 and PROFILE-6's quantized clock, budget, and publication rules,
  without claiming deterministic hardware execution.

## 08.2 Identities and selected closure

A transfer selects one immutable whole-world exact root and its complete
required descendants. The offered manifest binds scenario/configuration,
boundary, nodes, RAM scopes and roots, CPU/device state, disks, scheduler/host
continuation, pending modeled I/O, fault/plugin state, and provenance. Selection
of a different root requires a new offer generation; changing objects under an
existing root is corruption.

`PageDigest`, `RegionTreeDigest`, and `RamRootDigest` use
[Chapter 02](02-logical-ram-and-merkle-format.md). Page placement belongs to the
ordered logical tree. Storage `PageObjectId` associations are separately
authenticated under [Chapter 07](07-checkpoints-and-storage.md). An association
to another physical copy can satisfy transfer if it proves the same typed
content, logical page bytes, authorization, and retained availability.

- **[TRANSFER-3]** A transfer operation identity MUST bind its schema,
  selected exact root, source and destination authorities, namespace, transfer
  mode, required durability, and offer generation. Every request, response,
  journal, and terminal receipt MUST bind that operation identity.

The source records the selected root in durable transfer retention before
discovery begins. The destination records incoming roots and acquired objects
before they can become ordinary GC candidates. A remote source is not
automatically authorized to enumerate arbitrary destination contents or request
arbitrary source objects. Traversal and transfer are limited to the selected
closure and the explicitly authorized storage namespace.

## 08.3 Tree comparison and missing content

The destination can compare the offered logical tree with an already retained
tree of compatible geometry and coverage. Equal authenticated subtree digests
identify equal logical contents and positions. Differing subtrees are walked
using bounded metadata pages until required page contents are known. The
destination then resolves each page to an already possessed immutable object
or requests missing content.

The comparison baseline is only an optimization. It may be absent, incomplete,
or rejected without changing the offered image. Unrelated object hashes do not
allow the destination to skip required catalog validation. A page written and
returned to an earlier value can be reused by its content digest regardless of
the source's dirty history. Dirty tracking avoids unnecessary source hashing;
hash equality establishes actual content equality.

- **[TRANSFER-4]** Every skipped object MUST have authenticated destination
  possession and a retention lease sufficient for this operation. A cached
  presence bit, Bloom-filter positive, matching filename, or claimed peer
  inventory MUST NOT authorize skipping required bytes.
- **[TRANSFER-5]** Tree comparison MUST authenticate schema, scope, geometry,
  ordered child relationships, positions, counts, and digest associations.
  Equal content digests MUST NOT permit substitution of an incompatible scope,
  region catalog, or whole-world continuation.

A Bloom filter may prioritize requests or reduce discovery probes. A positive
result is followed by authoritative possession resolution; a negative result
may conservatively cause a request. If the destination already holds an object,
the store either provides a current integrity/possession capability with stable
retention or reads it to authenticated completion. A remote acknowledgment that
does not bind such authority is merely a claim.

Physical packs need not match across machines. The source extracts logical
content through a pinned generation, and the destination places it through its
own store. Transfer batching can carry many page objects together, but every
object retains independent framing, identity, exact length, validation, and
receipt. Neither endpoint treats a received pack path as logical authority.

## 08.4 Proposed control messages

The following messages describe the required control semantics for a future
versioned transfer adapter. They are proposed interfaces, not names of current
implemented RPCs. Exact binary encoding belongs to the protocol specification
and must obey the repository's versioned socket/shared-memory boundary rules.

Every frame carries protocol version, operation identity, offer generation,
message kind, bounded payload length, and sequence identifier. Messages
requesting bytes also carry an authorized closure coordinate or object identity.
An endpoint rejects unsupported versions before processing payload effects.

| Message | Required contents and effect |
|---|---|
| `TransferOffer` | Exact root, manifest identity/length, mode, logical schemas, node/boundary summary, provenance, durability requirement, declared resource bounds |
| `TransferAccept` | Admitted operation identity, destination authority, accepted limits, selected compatible comparison root if any, initial credit, durable journal receipt |
| `CatalogRequest` | Authenticated catalog/subtree coordinate, requested bounded page/range, expected digest, cursor |
| `CatalogResponse` | Requested canonical metadata, digest bindings/proof, exact framing, continuation cursor or complete marker |
| `NeedObjects` | Bounded ordered object requests with logical digest, typed storage identity, exact length, and request sequence |
| `ObjectData` | One bounded object stream or batch fragment, request/object identity, offset, exact fragment length, terminal marker |
| `ObjectReceipt` | Authenticated identity/length, durable placement floor, retained possession lease, request sequence |
| `TransferProgress` | Monotonic authenticated discovery, verification, persistence, and remaining-work counters |
| `TransferSeal` | Source declaration that the offered immutable closure is complete, with final authenticated inventory summary |
| `ClosureStored` | Receipt binding complete authenticated local closure, structural/provenance validation, required durability, namespace, and retention; no execution admission implied |
| `RestoreReady` | Receipt extending `ClosureStored` with current destination machine/resource admission, complete continuation checks, and execution ownership generation |
| `TransferCommit` | Authorized archive publication bound to `ClosureStored`, or maintenance handoff bound to `RestoreReady` and the execution ownership transition |
| `TransferComplete` | Durable destination selection/publication receipt and final journal disposition |
| `TransferCancel` | Authorized cancellation generation and reason, without releasing unresolved ownership |
| `TransferFailure` | Typed integrity, compatibility, resource, storage, transport, or supervision failure and recoverable journal state |

Credit bounds total in-flight bytes and objects. Control messages have reserved
capacity so cancellation and failure reporting cannot wait behind bulk pages.
Catalog cursors are bound to the immutable offered root and validated on every
resume; they cannot be reused to enumerate another root.

- **[TRANSFER-6]** Receivers MUST validate bounds and identities before
  allocating buffers or reserving storage. Fragment offsets and lengths MUST
  be checked for overflow, overlap, gaps, duplication, and final length. An
  object MUST remain unpublished until its complete bytes authenticate.
- **[TRANSFER-7]** Repetition of a valid request or receipt MUST be idempotent
  within the bound operation. An out-of-order, stale, foreign, or conflicting
  message MUST NOT advance readiness, release retention, or grant execution.

Exactly repeated data can be acknowledged after checking the existing staged
or immutable object. Conflicting bytes for the same named object fail the
operation. A sequence number is a replay/ordering aid, not a replacement for
authenticated object identity or durable journal state.

## 08.5 State machine and publication

Each endpoint has its own durable journal. No protocol operation relies on
holding both repositories' GC fences simultaneously. The source and destination
states are reconciled using bound receipts rather than assuming atomic
cross-machine transactions.

```text
source:      selected -> retained -> offered -> transferring -> sealed
             -> mode-ready -> committed -> transfer-retention-released

destination common:
             absent -> storage-admitted/journaled -> discovering -> receiving
             -> closure-verified -> closure-stored

archive:     closure-stored -> archive-published -> transfer-retention-retired
maintenance: closure-stored -> restore-admitted -> restore-ready
             -> ownership-committed -> executable-selection-published
             -> transfer-retention-retired
```

`discovering` and `receiving` may overlap within credit limits. `sealed` means
the immutable offer has a complete authenticated inventory; it does not mean
that the destination has those bytes. `closure-verified` means every required
descendant is present or canonically derivable locally and retained.
`closure-stored` additionally establishes the requested durable possession and
receipt. Storage admission does not require an executable machine profile.
`restore-admitted` adds execution compatibility, whole-world continuation checks,
and physical resource admission. `mode-ready` means `ClosureStored` for archive
copy and `RestoreReady` for maintenance handoff. Publication and execution
authority remain distinct.

- **[TRANSFER-8]** Destination readiness MUST require complete local
  availability, authenticated whole-world relationships, required durability,
  and retained sources. Missing RAM pages MUST NOT be deferred to guest
  execution in the complete-closure mode.
- **[TRANSFER-9]** Destination publication MUST install ordinary selection
  retention before retiring transfer retention. Source retention MUST remain
  until the corresponding destination receipt is durably reconciled.

- **[TRANSFER-17]** Archive publication MUST require `ClosureStored` and MUST
  NOT require destination QEMU launch or restore admission. A later restore
  MUST independently establish current execution compatibility, resources,
  retention, and ownership. Maintenance execution handoff or destruction of
  source execution recovery authority MUST additionally require `RestoreReady`
  and the durable execution-ownership transition. Neither receipt alone grants
  permission to run a canonical continuation twice.

An archive transfer may finish by publishing an archive ref without executing
anything. Executable imports must additionally satisfy the exact selection and
replay-oracle rules. An offline maintenance handoff requires the source campaign
to remain quiesced under its ownership contract and a separate authorized
destination restore action. The root's location-independent identity does not
authorize simultaneous execution of one canonical continuation.

## 08.6 Ownership, resume, and source release

A destination may restore all nodes into a private unexposed world while
checking readiness. It installs the complete scheduler/host continuation and
pager sources before publishing that world. Every node must bind the same
whole-world boundary; constructing a world from separately valid checkpoints
at different times is prohibited.

- **[TRANSFER-10]** Execution handoff MUST bind an explicit ownership
  generation and the admitted complete closure. The source MUST be unable to
  resume that continuation after releasing its execution authority. A lost
  completion message MUST NOT result in both sides independently resuming.
- **[TRANSFER-11]** Source destruction MUST occur only after authenticated
  `RestoreReady` and the durable execution-ownership transition required by the
  transfer mode. Before that transition, failure MUST leave a valid retained
  source closure or recoverable source process.

Retiring an archive copy's temporary transfer lease after `ClosureStored` and
publication is not destruction of source execution authority. Ordinary source
selection/process retention remains governed by its existing owner. A storage-only
destination can therefore complete an archive transfer even when it cannot run
the offered machine; incompatibility becomes a separately typed later restore
refusal. Maintenance release requires revalidation if readiness expires or its
execution/reservation generation changes before ownership commit.

Copying a closure for independent campaign branches is different from moving
the same execution owner. Branch creation must use the campaign's declared
derivation and assignment mechanisms. Content sharing does not implicitly
create a branch or permit duplicate canonical workers.

If a maintenance destination has `RestoreReady` but the commit decision is
unknown, its executable world remains unexposed and retained until the ownership
authority resolves the operation. An archive ref may already be published
without creating that world or granting execution.
If the source has durably released execution authority but transport loses the
receipt, recovery follows the recorded owner generation; the source cannot
infer permission to resume from elapsed time. These rules need the surrounding
campaign ownership machinery and are not solved by RAM hashing.

## 08.7 Failure, cancellation, and restart

An integrity failure identifies the object, logical coordinate, expected
identity, and failing validation stage without dumping guest bytes. It leaves
the destination unready and preserves journaled objects for authorized recovery
or cleanup. A compatibility failure occurs before expensive materialization
where possible and never falls back to an older checkpoint reader, fresh boot,
or guest-assisted migration.

Storage/transport failures can be retried only while the selected root,
operation authority, retention, and accepted policy remain valid. Retrying
cannot reinterpret corruption as a cache miss. A destination read of an
existing object that fails authentication is an integrity incident; replacement
requires the admitted repair policy rather than unconditional overwrite.

- **[TRANSFER-12]** Cancellation MUST stop new discovery and object requests,
  cancel bounded outstanding work, and resolve staged resources under durable
  ownership. It MUST NOT publish readiness or release source recovery
  authority merely to meet a cleanup deadline.
- **[TRANSFER-13]** Restart MUST authenticate journals and reconcile terminal
  receipts before resuming copy, publishing refs, or retiring retention.
  Orphan staging may be removed only after proving that no active or unresolved
  operation owns it.

After cancellation, completed immutable objects may remain reusable. Their
ordinary reachability or explicit recovery roots determine GC eligibility.
Partially received objects stay private, cannot satisfy possession probes, and
are charged to staging quotas until removed. A cleanup failure transfers the
remaining owner to quarantine and reports the retained resources.

Unexpected endpoint disappearance does not manufacture a cancel acknowledgment.
The surviving journal preserves the selected closure until an authorized
reconciliation determines whether to continue, abandon, or complete the
operation. Every outcome is idempotent and bound to the same operation identity.

## 08.8 Resource limits and supervision

Admission bounds logical RAM bytes, unique object count, metadata bytes, tree
depth, catalog pages, maximum object/frame length, in-flight bytes, request
count, staging disk, retained descriptors, durable placements, and discovery
scratch space. Declared source bounds are checked against independently derived
authenticated counts; they are not trusted resource promises.

- **[TRANSFER-14]** Discovery and verification MUST use bounded streaming
  cursors or admitted disk-backed indexes. Neither endpoint may collect every
  page, object ID, or tree node into memory without an explicit capacity bound.
- **[TRANSFER-15]** Backpressure MUST preserve capacity for control,
  cancellation, and integrity reporting. Runtime paging and transfer share
  admitted storage bandwidth fairly enough that bulk transfer cannot deadlock
  a guest fault or ownership operation waiting on the same device.

Operation-level supervision separates negotiation, discovery, object read,
network transport, destination persistence, final closure validation, restore,
and ownership commit. Progress renews only the configured lack-of-progress
budget; it cannot silently extend an explicit total deadline. A byte repeated
forever is not durable progress. Timers classify host operational failures and
cannot change guest virtual-time limits.

Runtime residency-policy changes during transfer may alter prefetch and
writeback scheduling, but not the sealed offered image or its leased versions.
Lowering a residency target cannot evict the only preserved version required by
an outstanding capture or transfer. Raising it cannot bypass destination
integrity checks by installing received data directly into guest RAM.

## 08.9 Future pre-copy and post-copy admission

Persistent trees and independent dirty epochs support future live pre-copy:
transfer a coherent baseline while source execution continues, record changes,
then quiesce at an exact boundary and transfer the final changed pages and
whole-world continuation. High dirtying rates may prevent convergence; the
future protocol must define bounded rounds, a final pause budget, and fallback
to complete offline transfer. A baseline tree is not the final executable root.

Post-copy would instead execute while some admitted pages remain at a remote
source. That introduces fault-service availability, source leasing, network
deadlock, authenticated request authorization, revocation, storage latency,
cross-machine cleanup, and whole-world ownership dependencies absent from
complete local restore. Arbitrary remote objects cannot be requested on demand
merely because a guest produced an address.

- **[TRANSFER-16]** Live pre-copy, post-copy, remote page serving, and execution
  dependent on remote missing pages MUST remain disabled unless a separately
  specified mode provides explicit admission, ownership, liveness, integrity,
  cancellation, and qualification contracts. Their implementation MUST NOT be
  claimed by completing this RFC's offline transfer path.

Future remote faults would be limited to authenticated positions within the
admitted final tree, checked at both endpoints, and installed only after page
validation. The guest would remain unmodified. Host delays would remain outside
logical execution time, but storage/network failure could still prevent host
progress. That operational distinction needs explicit supervision and cannot
be inferred from deterministic TCG alone.

## 08.10 Acceptance cases

Qualification compares source and destination complete logical roots and
canonical continuation after restore under different residency budgets.
Transfers with equal roots should reuse retained pages; transfers differing by
one page should avoid sending unrelated RAM; write-and-revert should reuse
content. Every case includes incompressible RAM and sufficient retained history
to exceed the old packed-object cap.

Negative cases include false-positive inventory hints, corrupt existing
destination objects, truncated or overlapping fragments, wrong page position,
wrong storage kind, stale catalog cursors, mismatched scope, incompatible
provenance, missing device state, and unknown ownership outcomes. Crash and
cancellation injection covers every journal, receipt, publication, and release
transition. GC and repacking run concurrently with authenticated extraction.

The archive case must succeed on a storage-only destination with no QEMU profile
or execution reservation. Its later restore must independently refuse an
incompatible profile or insufficient resources. Maintenance must fail safely
when readiness becomes stale before ownership commit, preserving source recovery
authority. Dropped receipts cannot promote `ClosureStored` into `RestoreReady`.

Acceptance also measures peak metadata/buffer memory, discovery scratch,
temporary disk, transferred logical bytes, durable progress, and time to
cancel. A successful transfer must demonstrate both the unchanged guest
semantics and a recoverable ownership state at every failure boundary.
