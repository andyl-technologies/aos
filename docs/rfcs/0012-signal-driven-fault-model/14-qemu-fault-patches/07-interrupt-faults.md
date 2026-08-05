# Patch 0053 — `crucible-interrupt-faults`

## Purpose

Adds typed interception and mutation of interrupt raise, routing, acknowledge,
delivery, and return phases. It implements drop, delay, duplicate, vector/type
replacement for spurious interrupts, and bounded storms without depending on
host signal timing.

## Capability and dependencies

- Provides `qemu.interrupt.control.x86_64.v1` and
  `qemu.interrupt.control.aarch64.v1`.
- Depends on 0047–0048, existing deterministic IPI/preemption injection, and
  architecture interrupt-controller state.

## Interrupt manifest

QEMU reports supported interrupt families and phases for the realized machine:

- x86: local APIC fixed interrupts, IPI, IOAPIC/PIC routes where present,
  MSI/MSI-X, NMI, and architecture timer interrupts. SMI is rejected unless a
  later explicit manifest row proves complete SMM semantics.
- AArch64: GIC SGI/PPI/SPI/LPI classes present in the realized GIC version,
  virtual/physical timer interrupts, and architecture SError only through 0054.

Each manifest row gives stable controller/source type, numeric ranges, trigger
mode (`edge`/`level`), polarity where relevant, routable target set, phases,
priority fields, and VMState coverage. Device-private callbacks never enter the
public manifest.

## Rule and event identity

Rules select source family/ID, controller, vector/type range, target vCPU, phase,
trigger mode, occurrence, and optional producer opportunity. An interrupt event
ID includes originating device/vCPU event, controller generation, source
sequence, routing generation, and duplicate/storm ordinal.

## Phase-specific dispositions

| Disposition | Exact semantics |
| --- | --- |
| `drop_raise` | Suppress an edge assertion before controller pending state; for level sources, suppress the sampled transition but leave the external line state under device control. |
| `drop_route` | Controller accepts source state but selected route produces no target pending event for this event ID. |
| `drop_delivery` | Pending controller state is consumed or retained according to explicit `pending_policy`; guest receives no exception entry. |
| `delay` | Remove/withhold at selected phase and enqueue the complete event for exact virtual/icount delivery with controller-state policy. |
| `duplicate` | Create bounded child events with the same typed source and stable ordinals at declared gaps. |
| `replace` | Produce a typed spurious event with declared controller/vector/type/target fields; original disposition is explicit. |

Level-triggered behavior must declare `pending_policy = retain`, `consume`, or
`reassert_if_line_high`. Edge-triggered duplicate/replacement creates new edge
events. Delayed interrupts preserve original priority/routing snapshot or
reroute at release according to explicit policy. No default exists.

## Storms

A storm rule generates a finite count or bounded periodic/burst sequence from an
exact event signal. Each event enters the normal controller path and consumes
modeled CPU/queue service. Maximum events obey the
[resource contract](../13-resource-and-performance-bounds.md); indefinite active
storms use a periodic generator with finite pending state, not preallocated
events.

## Ordering

At equal aggregate icount: existing scheduler-commanded RR switch, source raise,
route, fault disposition, controller priority selection, delivery, instruction
exception boundary, and return follow a declared architecture-specific total
order committed in golden vectors. Delays cannot target the past. Same-target
events tie by controller priority, source ID, event ID, then duplicate ordinal.

## Evidence and VMState

Evidence records manifest/controller version, event ID, all original fields,
matched rules/decisions, original/final phase state, queued release coordinate,
controller pending/active digests, target vCPU/RR cursor, guest exception entry,
and fingerprint. Patch 0059 serializes rules, delayed/storm queues, source
sequences, controller-associated fault state, and partial acknowledgements.

## Live microtests

1. Exercise every advertised x86 and AArch64 interrupt family/phase with guest
   counters and QEMU controller evidence.
2. Cover edge and level drop policies, delayed re-route/preserve, duplicates,
   replacement/spurious, priority interaction, and finite/periodic storms.
3. Interleave IPI, device, timer, and storm events at one icount and prove stable
   ordering under host perturbation.
4. Save/restore with delayed, active level, and storm events pending.
5. Verify unknown controller/vector/target, impossible trigger policy, past
   release, and limit failures leave state valid.
6. Revert patch and fail live gate; prove non-sim inertness.

## Licensing checklist

Interrupt-controller, CPU delivery, and plugin changes remain GPL-side and are
inactive without sim-fault rules. The host sees stable public IDs/fields only.
Preserve notices; inventory new files; DCO-sign; include microtests, series
catalog, capability vectors, and corresponding source.

- **[QFP-IRQ-1]** Capability rows MUST distinguish interrupt family, trigger
  mode, and phase; a single generic interrupt-injection bit is insufficient.
- **[QFP-IRQ-2]** A drop/delay MUST define controller pending/active state, not
  merely suppress guest callback execution.
