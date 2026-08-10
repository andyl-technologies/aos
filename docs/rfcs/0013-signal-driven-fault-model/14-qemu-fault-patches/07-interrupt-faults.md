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

The resolved target selects one source ID, controller, vector/type, target vCPU,
and command phase. Trigger mode and supported phase come from the realized
interrupt manifest. Opportunity-scoped selection is performed by the binding
runtime before the command; there is no second GPL-side probability or selector.
An interrupt event
ID includes originating device/vCPU event, controller generation, source
sequence, routing generation, and duplicate/storm ordinal.

## Phase-specific dispositions

| Disposition | Exact semantics |
| --- | --- |
| `drop` at raise | Suppress an edge assertion before controller pending state; for level sources, suppress the sampled transition but leave the external line state under device control. |
| `drop` at route | Controller accepts source state but the selected route produces no target pending event for this event ID. |
| `drop` at delivery | Guest receives no exception entry; QEMU uses the manifest's single architecture-correct pending-state treatment for that source/phase and rejects rows without one. |
| `delay` | Remove/withhold at the selected phase and enqueue the complete original event for exact virtual/icount delivery; priority, route, and target remain the captured event values. |
| `duplicate` | Create bounded child events with the same typed source and stable ordinals at declared gaps. |
| `replace` | Replace only the vector/type with the declared numeric value while retaining controller, source, and target; the original event is consumed. |

Level-triggered pending/reassert behavior is a capability-row invariant, not a
per-command policy. Edge-triggered duplicate/replacement creates new edge
events. Delayed interrupts always preserve the original priority/routing
snapshot. Unsupported source/phase combinations are rejected before install.

## Storms

A storm rule carries a positive period, positive burst, and positive finite
total count plus explicit sorted target vCPUs, priority, and pending-retention
behavior. Each event enters the normal controller path and consumes modeled
CPU/queue service. Maximum events obey the
[resource contract](../13-resource-and-performance-bounds.md). An unbounded
storm is modeled by a temporal signal issuing bounded generations, never by an
unbounded QEMU queue.

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
2. Cover edge and level drop behavior, captured-route delay, duplicates,
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
