# Implementation profile roadmap

## Delivery states and scope

The RAM contract has three distinct delivery states:

1. Shared foundation: canonical logical pages/topology, persistent trees,
   authenticated storage, generations, finite resource ownership, and leases.
2. Specified profile: a concrete execution/capture/timing contract, with its
   implementation-private writer, fault, removal, and lifecycle obligations.
3. Qualified capability: actual build/configuration/mode evidence permits the
   exact advertised combination. Missing evidence prevents activation.

A codec, an independent oracle, or an equal RAM root proves neither a complete
checkpoint nor a compatible execution owner. Profile capability selection is
explicit; unsupported selections refuse before execution without fallback.
gem5 and KVM work below is planning only, outside the initial implementation.

## Shared foundation and admission interfaces

Retain the 4096-byte logical page format and all current domain preimages. Keep
backend identity out of page hashes; bind it with semantic configuration,
capture schema/fidelity, and operating mode in the enclosing state contract.
Host residency policy remains operational, outside RAM semantic identity.

At actual provider integration, identify logical region owners, execution and
capture owners, coherent observation boundaries, and paging contexts. Make each
actual profile declare supported mappings, host fault origins, tracking epochs,
safe removal mechanism, clock behavior, branch reconstruction, and lazy restore.
Derive compatibility from the admitted build and configuration, rather than
from a generic `supports_paging` Boolean or provider family name.

Keep the QEMU-specific RAMBlock/BQL/QMP/migration/plugin mechanisms within their
implementation. Generalize a host interface only when a second real integration
needs it; avoid speculative provider abstractions and redundant code paths.
Cross-process contracts retain checked offsets, explicit editions, bounds, and
license/ABI review. No implementation-private pointers cross the public boundary.

## Initial QEMU-SIM delivery

Complete the [existing work packages](phased-implementation.md), including the
required kernel-swap experiment, complete write oracle, runtime policy and
supervision, storage scale, cold fork/restore, transfer, and coordinated cutover.
Retain all current deterministic guarantees: host page service does not advance
modeled time, consume modeled instruction/service budgets, introduce modeled
accesses, or change event order. Resume the original access exactly once.

Review pre-save behavior against the reached-state capture contract. Existing
admitted QEMU serialization order is not permission to execute additional guest
instructions, advance timers, or apply a new modeled mutation to obtain a
convenient snapshot. Account for each future-affecting component and validate
complete continuation independently of the RAM root.

Initial eviction remains at existing coherent paused boundaries. Reserve full
guest RAM plus separate progress resources unless an actual smaller interval
population bound has been proved. Runtime targets can lower achieved residency
without lowering the admitted peak. New suspension boundaries or concurrent
eviction require their own wait-for, pointer-lifetime, dirty-generation, event
ordering, and performance proofs before general low-peak activation.

Preserve the fixed QEMU regression plans and zero permitted CPU/elapsed-time
regression against comparable master. Do not raise caps or deadlines, alter
guest workloads, combine unrelated workload families, or substitute savings in
allocations/frames for measured parity. Retain failed attempts and receipts.

## Future deterministic gem5 integration

Before code integration, inventory the actual ISA/CPU model, cache hierarchy,
coherence protocol, controllers, devices, event queues/threads, and semantic
parameters. Allocate one capture owner to each future-affecting domain. A host
allocation is not operational merely because it lives outside backing RAM.
Specify canonical components for caches, coherence transients, pending requests,
controllers, pipelines, predictors, translations, and event state when realized.
Do not invent RAM aliases between independent domains or commit the same bytes
under multiple owners.

Separate backing-root observation from coherent architectural observation.
Fault predicates and guest assertions need a qualified projection that sees
newer cache-owned values when appropriate, without functional inspection
changing coherence, replacement, pending queues, or event order. Capture must
preserve an arbitrary admitted continuation without modeled drain, cache flush,
event advancement, instruction retirement, or hidden prefix re-execution.
Unsupported exact boundaries refuse that fidelity rather than silently downgrade.

Retain pending modeled access identity across population: request, operands,
partial progress, accepted transaction, and ordering position. Inventory backing,
cache/coherence, DMA/device, functional/debug, loader, reset, restore, and fault
writers. Qualify removal against retained packets, native pointers, event
callbacks, aliases, and kernel access. Event dispatch suspension alone is not
physical-access proof.

Private RAM branching needs independent event/thread reconstruction and complete
modeled-domain ownership. Unix process COW is candidate machinery only. Require
identical complete state and event traces for resident/paged/branched/restored
realizations, including dirty caches, outstanding transactions, and cold accesses
during capture and reconstruction, before claiming any deterministic capability.

## Future nondeterministic quantized KVM integration

Declare nondeterministic hardware execution and actual exposed capture fidelity.
Do not promise physical cache/predictor/pipeline preservation, instruction-exact
stopping, or repeatable multi-vCPU interleavings. Clock freezing does not change
this classification. Preserve nondeterministic provenance in coupled scenarios
unless a separate qualified record/replay contract establishes more.

Implement the explicit clock/timer and grant contract before admitting paged
execution. A blocked owner retains its original window and input batch; affected
vCPUs/devices and controlled clocks/timer injection are held. Preserve due timer
custody and remaining execution budget on its original admitted basis. Active
execution budgets exclude only attested held intervals; elapsed-wall budgets
continue expiring. Host operational deadlines continue. No page-in renews a
grant, admits later inputs into its batch, or publishes outputs prematurely.
Unsupported clocks/devices refuse the paged mode; strict wall-time modes may
require reserved, prefaulted, appropriately locked resident memory.

Combine actual hardware dirty logging with device/DMA/host writers and coherent
epoch reconciliation. Qualify kernel-originated faults and actual mapping
granularity, permissions, feature/ioctl sets, secondary translations, mappings,
and pins. Stopping vCPUs is insufficient to authorize removal; unsupported
passthrough/pinned paths refuse before execution.

Create fresh kernel VM/vCPU/device execution objects for any claimed branch or
restore and reconstruct the qualified exposed state. Descriptor inheritance or
RAM COW alone cannot qualify that capability. Test coherent state, integrity,
writer coverage, isolation, kernel-fault progress, clocks/timers, acknowledged
stopping, remaining budgets, and quantum containment; repeated execution equality
is not the criterion for the declared nondeterministic profile.

## Cross-profile use and activation

Common guest images permit fresh-run testing in KVM, QEMU-SIM, and gem5. That
progression is not checkpoint conversion. A continuation conversion requires
its own schema, validation, and explicit lost guarantees; equal RAM roots cannot
authorize one.

Complete the qualification matrix for every claimed combination, retain actual
build/kernel/filesystem observations, and activate capabilities individually.
Keep low-peak execution, concurrent eviction, exact capture, branch creation,
and lazy restore disabled where their independent proofs are missing. All
affected versions make one immediate coordinated deployment cutover.
