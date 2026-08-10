# Patch 0050 — `crucible-memory-access-faults`

## Purpose

Adds persistent and opportunity-scoped transforms around guest instruction fetch,
CPU load/store, and DMA read/write. It implements stuck bits, read corruption,
lost/torn writes, poison/failed regions, retention decay, rowhammer disturbance,
and modeled memory latency/bandwidth.

## Capability and dependencies

- Provides `qemu.memory.access-transform.v1`, `qemu.memory.region-state.v1`, and
  `qemu.memory.service.v1` on x86-64 and AArch64.
- Depends on 0047–0049, safe translation evidence, and sim time control.

## Rule payload and index

An install/remove command at `node_boundary` carries the authenticated action,
target, schema, and generation identities; resolved start and positive length;
the six explicit access-class booleans (`fetch`, `cpu_load`, `cpu_store`,
`dma_read`, `dma_write`, `page_table_walk`); an optional canonical `dma_device` identity that is
valid only with a DMA-only class set; `violate_atomicity`; one closed transform; and one
closed `every/periodic` occurrence policy. The target fields carry the node,
guest address, optional vCPU context, and length. The plugin resolves any GVA
target to GPA intervals at install and records the translation identity in rule
state and evidence; a changed translation invalidates rather than silently
retargets the rule.

QEMU stores immutable rule generations in a canonical GPA interval index plus
separate PC/fetch and device DMA scope indexes. Read-mostly lookups do not allocate
or lock on the hot path. Replacing a generation occurs only at a safe boundary;
old generations remain until no callback can reference them.

A replacement is a new experiment state, not an in-place edit: its occurrence
ordinals, retention exposure coordinate, rowhammer counters, and translation
staleness state start fresh at zero. State is never inferred or migrated from a
prior generation. Removing and later reinstalling a binding has the same fresh
state semantics. Shared service ledgers are the exception because they belong to
the declared service scope rather than to a rule generation. A node or controller
ledger survives replacement/removal of one contributing binding while another
binding still references that scope; a range ledger is keyed by address-space
kind, optional vCPU, exact start, and exact length.

## Access identity and order

Access identity includes node, vCPU or DMA device, architecture PC/TB/instruction
identity where applicable, GPA, length, access type, access ordinal within the
instruction/device transaction, and retry/replay ordinal. The hook resolves all
matching rules and applies them in binding-hash order.

For CPU memory helpers, one top-level translated load, store, fetch, or atomic
helper is one transaction; page splits and unaligned sub-accesses increment its
zero-based fragment ordinal. Re-entry of the same actor, access class, virtual
address, width, and observed instruction coordinate increments the retry/replay
ordinal. Instruction fetch caches transformed bytes by instruction-relative
offset inside that transaction, so overlapping decoder reads neither reapply a
transform nor consume another opportunity. For DMA, one `dma_memory_rw`, cached virtqueue access, map fill, or
writeback is one transaction. A selectable virtio device MUST have an explicit
QEMU device `id`; its identity is SHA-256 over the ASCII domain
`qemu.virtio.dma-id.v1` followed immediately by that UTF-8 ID. The host derives
the same digest from `dma_device`. An id-less virtio device and an unidentified
DMA caller remain usable by unscoped rules but cannot satisfy a device-scoped
selector. The full digest, not only a numeric abbreviation, is evidence.

`page_table_walk` selects the architecture MMU's implicit reads of normal-RAM
page-table descriptors. Its rule range is always guest physical and identifies
the descriptor bytes, while evidence separately records the initiating virtual
address, initiating fetch/load/store class, vCPU, architecture level (`-1`
through `3` on AArch64 and `1` through `5` on x86-64), translation stage, entry
GPA, entry width, retry ordinal, and before/after descriptor bytes. Debugger,
capability-probe, command-admission, and other inspection translations are not
opportunities and never consume occurrence state. Each live descriptor read is
one transaction; an architecture retry of the same descriptor at the same
instruction coordinate increments the retry ordinal. That retry key includes
the instruction PC and ordinal, initiating virtual address and access class,
descriptor GPA and width, translation stage, and architecture walk level.
Under nested translation, the descriptor GPA is the final ordinary-RAM address
after the outer descriptor address has crossed the second-stage translation;
stage identifies the table being walked rather than the MMU index used to read
that table.

`stuck`, `read_corrupt`, corrected poison, retention, rowhammer accounting,
and memory service apply to a selected descriptor read exactly as they do to
another read. `lost_write` and
`torn_write` reject a `page_table_walk` class because the walk opportunity is a
read; explicit guest writes of accessed/dirty bits remain CPU stores.
`access_error` and failed-region error policy produce the architecture's native
page-table-walk fault without exposing descriptor bytes. A configured generic
CPU `exception` policy rejects `page_table_walk`, because its numeric exception
contract lacks the architecture walk-level/stage fields needed to replace the
native fault precisely. MMIO page tables remain outside the advertised class;
installation requires the complete selected GPA range to resolve to ordinary
writable RAM.

A mapped DMA write is admitted over the full mapping grant because QEMU cannot
report an error from `address_space_unmap`. Poison and failed-region policy
therefore accept or reject that grant at map time. Byte transforms, persistent
state, and service accounting use the exact `access_len` reported at unmap; a
zero-length unmap performs none of those effects. The grant pins the complete
ordered rule-generation snapshot and its occurrence state through unmap, so a
concurrent rule replacement cannot retarget the transaction.

Ordering is:

```text
resolve address -> check poison/failed state -> read source or prepare write
-> stuck transform -> corruption/torn/lost transform -> service penalty
-> commit or return outcome -> update retention/rowhammer counters -> evidence
```

Instruction result faults occur later under patch 0052. Boundary impulses from
0049 occur between accesses and update real RAM, so subsequent accesses see them.

## Transform semantics

| Kind | Exact behavior |
| --- | --- |
| `stuck` | On reads force selected bits after source read; on writes force stored selected bits to configured zero/one while unselected bits follow the write. |
| `read_corrupt` | Return the repeated XOR transform without changing RAM. Persistent corruption is a separately evidenced boundary mutation. |
| `lost_write` | Suppress selected complete write fragments while preserving the production path's ordinary successful completion semantics. Error outcomes use poison or a typed device fault. |
| `torn_write` | Commit exact selected bytes/bits in increasing GPA order; unselected bytes retain before state. CPU architectural atomicity is deliberately violated only when capability fields permit it. |
| `poison` | Produce architecture/device-specific poison outcome before returning data; no bytes are exposed unless policy says corrected data. |
| `failed_region` | Every selected access applies the embedded `access_error` or CPU/fetch architecture-exception poison policy. Correctable data corruption is an access transform, not a failed-region state. |
| `retention` | At each positive virtual exposure interval apply the declared repeated decay mask at the exact refresh/read/boundary opportunity. |
| `rowhammer` | Increment exact aggressor-row access counters; at the positive threshold XOR the declared repeated mask into victims at the declared row distance. |

Atomic/locked instructions, page-table walks, instruction fetch, DMA, and MMIO
declare separate capability fields. Page-table-walk support covers normal-RAM
descriptor reads on x86-64 and AArch64. MMIO transforms are rejected in v1 of this
patch; MMIO instruction replay belongs to 0052 and typed device faults belong to
their adapter. CPU atomic operations can be torn only when the effect explicitly
sets `violate_atomicity = true`, the target architecture capability advertises
the exact operation width, and the live gate covers it. The v1 capability
advertises only 1-, 2-, 4-, 8-, and 16-byte atomics, including both
compare-exchange success and failure paths.

## Memory service

Latency adds exact virtual nanoseconds at the access completion boundary.
Bandwidth/service uses a checkpointed token/service-curve state shared by the
declared node/controller/range scope. A vCPU waiting for memory cannot retire the
dependent instruction; the sim scheduler may run another eligible vCPU or
advance virtual time through the existing authorized time-control barrier. DMA
completion follows the same scheduler-visible service deadline. Host sleeps or
callback delays never model memory latency.

Fixed latency is checked-summed across matching bindings and does not consume or
serialize service capacity. Each shared ledger advances by the exact ceiling of
bytes/rate plus operations/rate; the access waits for the maximum queue deadline
across its ledgers. Thus two bindings sharing a controller serialize through one
cursor, while unrelated ranges remain independently serviceable.
Every service event carries the canonical ledger-scope hash, ready coordinate
before and after, configured rates and fixed latency, byte and capacity demand,
queue and composed completion delay, retry/fragment identity, ordered
match-chain hash, and final outcome.

Every reachable runtime limit is checked before memory, counters, service
ledgers, or event state changes. Exhaustion emits one terminal `CRUCLIM1`
record with a closed resource kind and exact `current`, incremental
`requested`, `configured`, and implementation-hard values. Resource kinds are
event slots (1), arithmetic composition (2), monotonic counters (3), service
rule slots (4), accumulated service bytes (5), virtual-time coordinates (6),
persistent sparse cells (7), and exact-evidence bytes (8). Once emitted, the
node stops at the same boundary and no later opportunity can mutate state.

## Retention and rowhammer geometry

The realized machine manifest declares memory channel/rank/bank/row/column
mapping or an explicit GPA-to-row artifact. Retention state stores the last
refresh/program coordinate and exposure accumulator per sparse affected region.
Rowhammer stores bounded counters keyed by bank/row plus next threshold;
`row_bytes` and `victim_distance` make adjacency explicit. Counter saturation is
an error. Refresh events are exact modeled events and are checkpointed.

## Evidence and VMState

Evidence contains rule generation, access ID, matched rules, original/final
bytes or digests, suppressed/applied byte mask, outcome, service ledger,
counter/state transitions, physical mutations, and fingerprints. QEMU dirty
tracking/TB invalidation applies to persistent changes. Patch 0059 serializes
rule generations, sparse region state, counters, service state, and pending
access delay. Mapped DMA evidence records both the admitted mapping-grant length
and the exact used length, so a partial writeback is distinguishable from an
exact mapping and a zero-length writeback is provably event-free.

## Live microtests

1. x86-64 and AArch64 guests exercise every transform on aligned, unaligned,
   cross-page, fetch, load/store, atomic, and permitted DMA accesses.
2. On both architectures, exercise page-table `read_corrupt`, corrected poison,
   native walk `access_error`, failed-region error, service, and a guest-handled
   retry. Prove inspection translations produce no opportunity or occurrence.
3. Run a real x86 nested guest and independently target the final-RAM
   stage-1 descriptor and the NPT stage-2 descriptor. Assert stage, level,
   initiating virtual address/class, final descriptor GPA, and guest result.
4. Verify CPU, DMA, and page-walk access identity/order, retries, and
   instruction replay ordinals under host perturbation.
5. Run stuck bits, transient corruption, lost/torn write, poison, retention, and
   rowhammer with known bytes and exact guest/QEMU evidence.
6. Verify row geometry, threshold, counter overflow, range overlap, and invalid
   MMIO/atomic requests fail loudly.
7. Prove latency/service blocks architectural completion at the exact virtual
   coordinate and resumes identically after checkpoint.
8. Benchmark disabled, enabled-empty-index, sparse non-match, and active match.
9. Revert patch and prove live gates fail; prove non-sim inertness.

## Licensing checklist

Hooks in TCG/system memory/DMA paths remain in QEMU's applicable GPL scope and
take the verbatim upstream path unless sim-fault mode and a nonempty matching
rule generation are active. Public protocol carries addresses/bytes/evidence,
not QEMU objects. DCO, notices, new-file inventory, microtests, catalog, and
corresponding source are mandatory.

- **[QFP-MEMA-1]** Every access class advertised in capabilities MUST pass a live
  transform test; CPU-only coverage cannot advertise DMA/fetch support.
- **[QFP-MEMA-2]** Empty-index overhead and output MUST meet the
  [resource contract](../13-resource-and-performance-bounds.md) without changing
  upstream non-sim behavior.
