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
the five explicit access-class booleans (`fetch`, `cpu_load`, `cpu_store`,
`dma_read`, `dma_write`); `violate_atomicity`; one closed transform; and one
closed `every/periodic` occurrence policy. The target fields carry the node,
guest address, optional vCPU context, and length. The plugin resolves any GVA
target to GPA intervals at install and records the translation identity in rule
state and evidence; a changed translation invalidates rather than silently
retargets the rule.

QEMU stores immutable rule generations in a canonical GPA interval index plus
separate PC/fetch and device DMA scope indexes. Read-mostly lookups do not allocate
or lock on the hot path. Replacing a generation occurs only at a safe boundary;
old generations remain until no callback can reference them.

## Access identity and order

Access identity includes node, vCPU or DMA device, architecture PC/TB/instruction
identity where applicable, GPA, length, access type, access ordinal within the
instruction/device transaction, and retry/replay ordinal. The hook resolves all
matching rules and applies them in binding-hash order.

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
| `failed_region` | Every selected access applies the embedded `access_error`, `corrected`, or architecture-exception poison policy. |
| `retention` | At each positive virtual exposure interval apply the declared repeated decay mask at the exact refresh/read/boundary opportunity. |
| `rowhammer` | Increment exact aggressor-row access counters; at the positive threshold XOR the declared repeated mask into victims at the declared row distance. |

Atomic/locked instructions, page-table walks, instruction fetch, DMA, and MMIO
declare separate capability fields. MMIO transforms are rejected in v1 of this
patch; MMIO instruction replay belongs to 0052 and typed device faults belong to
their adapter. CPU atomic operations can be torn only when the effect explicitly
sets `violate_atomicity = true`, the target architecture capability advertises
the exact operation width, and the live gate covers it.

## Memory service

Latency adds exact virtual nanoseconds at the access completion boundary.
Bandwidth/service uses a checkpointed token/service-curve state shared by the
declared node/controller/range scope. A vCPU waiting for memory cannot retire the
dependent instruction; the sim scheduler may run another eligible vCPU or
advance virtual time through the existing authorized time-control barrier. DMA
completion follows the same scheduler-visible service deadline. Host sleeps or
callback delays never model memory latency.

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
access delay.

## Live microtests

1. x86-64 and AArch64 guests exercise every transform on aligned, unaligned,
   cross-page, fetch, load/store, atomic, and permitted DMA accesses.
2. Verify CPU and DMA access identity/order, retries, and instruction replay
   ordinals under host perturbation.
3. Run stuck bits, transient corruption, lost/torn write, poison, retention, and
   rowhammer with known bytes and exact guest/QEMU evidence.
4. Verify row geometry, threshold, counter overflow, range overlap, and invalid
   MMIO/atomic requests fail loudly.
5. Prove latency/service blocks architectural completion at the exact virtual
   coordinate and resumes identically after checkpoint.
6. Benchmark disabled, enabled-empty-index, sparse non-match, and active match.
7. Revert patch and prove live gates fail; prove non-sim inertness.

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
