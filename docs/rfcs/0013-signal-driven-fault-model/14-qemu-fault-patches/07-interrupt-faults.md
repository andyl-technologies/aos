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

The host declaration and QEMU-reported row use the same closed fields. All are
required: `id`, `controller`, `source`, `controller_version`, `family`,
`vector_start`, `vector_end`, `replacement_vector_start`,
`replacement_vector_end`, `trigger`,
`polarity`, sorted unique nonempty `target_vcpus`, sorted unique nonempty
`model_phases`, `priority`, `delivery_drop`, and `vmstate=true`. Admission
compares the canonical encoded rows byte-for-byte; it never widens a range or
fills in a controller default. The runtime vector is deliberately not an
immutable manifest field: IOAPIC, MSI/MSI-X, GIC, and timer routing may be
guest-programmed after admission. `vector_start..=vector_end` authenticates the
complete source domain, while each opportunity and evidence record carries the
exact observed vector or INTID.

The complete family set is:

| Architecture | Families | Vector or INTID domain |
| --- | --- | --- |
| x86-64 | `x86_local_apic_fixed`, `x86_ipi`, `x86_io_apic`, `x86_pic`, `x86_msi`, `x86_msi_x`, `x86_nmi`, `x86_timer` | PIC `0..=255`; NMI exactly `2`; all other families `16..=255` |
| AArch64 | `arm_gic_sgi`, `arm_gic_ppi`, `arm_gic_spi`, `arm_gic_lpi`, `arm_timer` | SGI `0..=15`; PPI/timer `16..=31`; SPI `32..=1019`; LPI `8192..=16777215` |

IPI, MSI, MSI-X, NMI, SGI, and LPI rows are edge-triggered. Edge rows use
`delivery_drop=consume_edge`; level rows use
`delivery_drop=repend_asserted_level`. SMI has no family row. SError belongs to
the typed exception contract in patch 0054. `controller_version` is the exact
printable realized implementation identity exported by QEMU, not a user-chosen
label.

Patch 0053 constructs this manifest from devices that actually realized. Family
registration is accepted only before the manifest is first read; a device that
tries to appear later is rejected instead of silently widening an authenticated
run. The host then binds SHA-256 identities for every row and seals the complete
table before any rule can be installed. Missing bindings, duplicate bindings,
row reordering, target-set drift, or a controller-version mismatch fail setup.

The implemented controller hooks advertise these model phases:

| Realized controller path | Families | Advertised phase |
| --- | --- | --- |
| local APIC | fixed edge/level, IPI, timer | `route`, `deliver` |
| local APIC NMI | NMI | `route` |
| IOAPIC to local APIC | edge/level IOAPIC | `route`, `deliver` |
| PCI MSI/MSI-X to local APIC | MSI, MSI-X | `route`, `deliver` |
| i8259 PIC acknowledge | edge/level PIC | `deliver` |
| GICv2 CPU interface | SGI, PPI, SPI, architectural timer | `deliver` |
| GICv3 CPU interface | SGI, PPI, SPI, architectural timer, realized LPI | `deliver` |

`deliver` is the controller's transactional acknowledge-and-deliver point: the
implementation snapshots the pending selection, applies the disposition, and
either commits the architecture controller transition or restores/re-pends the
event according to the authenticated row. It is not callback suppression after
the interrupt has already become guest-visible. Phases absent from a row are
rejected at rule admission.

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

Replacement and deferred release re-enter normal controller arbitration. They
do not write directly over a pending vector. The APIC checks both IRR and ISR
destination state and preserves trigger-mode state; PIC release resolves the
actual IRQ line before checking pending state; GICv2/GICv3 validate the target,
INTID domain, enablement, and controller-specific pending representation. A
collision or route that became invalid after admission emits a terminal fault
result and leaves the pre-existing controller event untouched.

Each pending event carries source sequence and routing generation provenance.
APIC, PIC, GICv2, and ordinary GICv3 events store it with controller state;
GICv3 LPIs and deferred events use a bounded sparse provenance table keyed by
family, target, and INTID. LPI delivery validates the live property and pending
tables, and provenance follows an ITS-directed LPI move. The central release
phase prevents a delayed or duplicate child from recursively matching the rule
that created it.

## Storms

A storm rule carries a positive period, positive burst, and positive finite
total count plus explicit sorted target vCPUs, priority, and pending-retention
behavior. Each event enters the normal controller path and consumes modeled
CPU/queue service. Maximum events obey the
[resource contract](../13-resource-and-performance-bounds.md). An unbounded
storm is modeled by a temporal signal issuing bounded generations, never by an
unbounded QEMU queue.

Storm injection uses the same registered injector and route validator as an
ordinary controller event. APIC priority is the vector high nibble; PIC maps
the full authenticated `0..=255` vector domain deterministically to IRQ line
`vector & 15` with priority `vector & 7`; GICv2 SGI storms use the lowest
realized boot vCPU as their deterministic source. Completed storms release
their timer and target array while retaining only the small completed-rule
marker needed to prevent re-arming the same generation.

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

Patch 0053 already places controller-resident provenance in the corresponding
APIC, PIC, GICv2, and GICv3 VMState descriptions. Patch 0059 owns the complete
cross-component migration transaction for the sparse LPI/deferred provenance
table, source/routing counters, pending command/impulse commit, delayed timers,
storm progress and target lists, and queued deterministic IPI provenance. Until
0059 is present, save admission must reject a run with any of that global fault
state live.

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
