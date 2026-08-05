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

An install/remove command at `node_boundary` carries rule ID, binding ID,
address space and resolved GPA intervals, access types (`fetch`, `cpu_load`,
`cpu_store`, `dma_read`, `dma_write`), widths/alignment policy, phase, transform,
activation generation, opportunity filter, and bounded transform state. GVA rules
are resolved to GPA intervals at install and either pin translation generation or
declare deterministic re-resolution events.

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
| `read_corrupt` | Return ordered bit/byte transform without changing RAM unless `persist = true`, which performs a separately evidenced 0049-style mutation. |
| `lost_write` | Suppress selected complete write fragments while reporting the configured architectural/device success or error outcome. |
| `torn_write` | Commit exact selected bytes/bits in increasing GPA order; unselected bytes retain before state. CPU architectural atomicity is deliberately violated only when capability fields permit it. |
| `poison` | Produce architecture/device-specific poison outcome before returning data; no bytes are exposed unless policy says corrected data. |
| `failed_region` | Persistent error, corruption, or hang outcome selected by region state. |
| `retention` | At exact refresh/read/boundary opportunities evaluate time, temperature, and rule-table state and commit keyed physical bit mutations. |
| `rowhammer` | Increment exact aggressor row access counters; at declared thresholds mutate keyed bits in mapped victim rows and advance threshold state. |

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

The world declares memory channel/rank/bank/row/column mapping or an explicit
GPA-to-row lookup artifact. Retention state stores last refresh/program
coordinate and exposure accumulator per sparse affected region. Rowhammer stores
bounded counters keyed by bank/row plus next threshold; adjacency is explicit.
Counter saturation is an error. Refresh events are exact modeled events and are
checkpointed.

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
