# Node faults and the QEMU fault boundary

Node effects change a guest machine itself: lifecycle, vCPU service and state,
registers, instructions, interrupts, memory, guest clocks, and the
deterministic accelerator device. They are applied inside the patched QEMU at
exact retired-instruction boundaries. The Apache-licensed host decides *what*
to apply; QEMU applies it through a versioned shared-memory command protocol.

Sources: effect parameters in
[`node_effect.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/node_effect.rs);
host actions in
[`fault_action_sink.rs`](../../../../crates/crucible/crucible-qemu-host/src/fault_action_sink.rs)
and launch capability requirements in
[`fault_capability.rs`](../../../../crates/crucible/crucible-qemu-host/src/fault_capability.rs);
the public protocol in
[`crucible-qemu-shmem/src/shmem/`](../../../../crates/crucible/crucible-qemu-shmem/src/shmem/)
(`fault_command`, `fault_node`, `fault_memory*`, `fault_*_evidence`,
`fault_target_manifest`, `fault_event`); and the QEMU side in the
[atomic integration patch](../../../../pkgs/emulation/qemu-patches/README.md)
(`plugins/crucible-fault*.c`, `include/qemu/crucible-fault.h`,
`target/*/crucible-register.c`, `hw/virtio/virtio-crucible-accelerator*.c`).

## Node effects

| Effect | Behavior |
| --- | --- |
| `node.lifecycle` | `boot`, `crash`, `reset`, `power_off`, `power_cycle`, `permanent_failure`, with explicit volatile-state, device, boot, and watchdog policies. |
| `node.hang` | Progress outage of the node, a vCPU set, or a device, with explicit recovery. |
| `cpu.service` | Rational vCPU capacity under a `work_conserving` or `strict_cap` discipline. |
| `cpu.vcpu_state` | `online`, `offline`, or `stalled`. |
| `cpu.register_transform` | Architecture-resolved bit flip, stuck bits, or replacement. |
| `cpu.instruction_transform` | Result corruption, skip, or replay of selected instructions. |
| `cpu.exception` | x86-64 machine check or AArch64 hardware error / injected exception. |
| `interrupt.disposition` | Drop, delay, duplicate, or replace an interrupt across raise, route, and deliver. |
| `interrupt.storm` | A bounded generated interrupt sequence. |
| `memory.mutation` | Atomic guest-physical or guest-virtual impulse mutation at a safe boundary. |
| `memory.access_transform` | Stuck bits, read corruption, lost or torn writes, poison on fetch/load/store/DMA/page-walk. |
| `memory.ecc_event` | Corrected or uncorrectable ECC event with platform reporting. |
| `memory.region_state` | Failed, retention-decaying, or rowhammer-disturbed regions. |
| `memory.service` | Memory latency, byte-rate, and operation-rate constraints. |
| `clock.transform` | Offset, drift, jump, freeze, jitter, or wander of a guest clock source. |
| `clock.source_state` | Clock failure, fallback, source selection, and synchronization. |
| `accelerator.*` | Lifecycle (disappear, reset, reconnect), job result transforms, accelerator memory events, and compute/memory/thermal/power service caps. |

Register and memory targets are resolved before application into architecture
register IDs and guest-physical ranges, and that resolution enters the effect
record.

## Process and license boundary

```text
Apache-2.0 host                       QEMU process (GPL scope)
+-----------------------------+       +----------------------------------+
| signals, bindings, adapters |       | crucible-qemu-plugin (GPL-2.0)   |
| fault_action_sink           |       | atomic QEMU integration patch    |
|                             |       |                                  |
| crucible-qemu-shmem         |<=====>| validates commands, applies at   |
| (MIT OR Apache-2.0)         |  SHM  | exact boundaries, publishes      |
+-----------------------------+       | results and evidence             |
                                      +----------------------------------+
```

The protocol contains only fixed-width integers, byte payloads, offsets,
lengths, versions, IDs, and digests; never pointers, QEMU structures, or
callbacks. Host crates never include QEMU headers or call QEMU code. The
constants and layouts are generated into a C header from the dual-licensed
boundary crate. The governing policy is the
[licensing guide](../../../legal/licensing.md).

## Command protocol

A command is a `FaultCommandHeaderV1` (216 bytes) plus an out-of-line payload:

```text
FaultCommandHeaderV1 {
  abi_major, abi_minor: u16        FAULT_COMMAND_ABI_MAJOR / _MINOR
  command_kind: u16                FaultCommandKind
  command_flags: u16               only PREPARE_ONLY is defined
  phase: u16                       FaultBoundaryPhase
  semantic_version: u32
  command_sequence: u64
  target_node_hash: [u8; 32]
  target_icount: u64
  authorization_ceiling_icount: u64
  binding_hash, opportunity_hash,
  expected_precondition_hash,
  payload_hash: [u8; 32]
  payload_offset: u64, payload_length: u32
}
```

The result, `FaultResultHeaderV2` (196 bytes), echoes ABI version, the raw
command kind, sequence, and semantic version, and adds status, observed and
applied icount, the exact emitted tick, QEMU capability version, reached phase,
before/after/evidence hashes, and a hashed typed result payload. Payloads are
authenticated by their envelope hash before decoding.

`FaultCommandKind` covers queries (`query_capabilities`, `boundary_probe`,
`query_target_manifest`) and one command per node effect (`node_lifecycle`
through `accelerator_service`). `FaultBoundaryPhase` is `node_boundary`,
`before_instruction`, `after_instruction`, `before_memory_access`,
`after_memory_access`, `interrupt`, or `device`.

`FaultResultStatus` is `applied`, `not_applicable`, `precondition_mismatch`,
`invalid_target`, `invalid_phase`, `unsupported_capability`, `past_boundary`,
`resource_limit`, `guest_rejected`, `internal_error`, `malformed_command`,
`duplicate_sequence`, `authentication_failed`, or `prepared`. `prepared` is the
non-mutating success of a prepare-only command. Any non-`applied` status is a
loud outcome unless the effect contract expects `not_applicable`; non-mutating
results carry `applied_icount = 0` and equal before/after hashes. Ambiguous
visibility of a result is fatal and is never treated as an unchanged rejection.

Transport: commands and results travel in 256-byte slots in per-node rings
(default capacity 4,096, hard 65,536) with payloads in a bounded per-node arena.
The host reserves a slot, writes the payload, publishes with release ordering,
and rings the eventfd; the plugin validates and arms the command. Each slot
carries transport-owned reservation cursors so a consumer can release an arena
reservation even when the enclosed ABI bytes are rejected. A sequence stays
live until its result is consumed. Exhaustion fails before publishing, losing,
or overwriting anything.

### Typed node-rule payloads

Every node command except memory impulses carries a `CRUCNOD1` payload: a fixed
header binding command kind, `upsert`/`remove`/`impulse` operation, target
kind, phase, generation, and action/target/schema hashes, followed by strictly
increasing tagged fields (`P*` parameters, `T*` target fields). Structured
policies are `bytes` fields holding `CRUCJSN1` plus whitespace-free canonical
JSON with sorted keys. The public codec validates framing and canonical form;
the GPL-side handler validates the command-specific shape and rejects unknown
members before preparation can succeed. Memory impulses use a separate
batch payload (`MemoryMutationBatchV1`) with per-action evidence.

## Safe boundaries

A command names `target_icount` and an `authorization_ceiling_icount`. The
plugin arms it only if the current icount is not past the target; QEMU forces
the selected execution path to exit no later than the target and refuses to
apply before the exact target and phase. If the hook cannot occur by the
ceiling, the result is `not_applicable` (absent opportunity) or
`past_boundary` (missed).

`node_boundary` requires every vCPU stopped at the fixed round-robin cursor and
device callbacks due by the coordinate drained in canonical order.
Instruction, access, and interrupt hooks quiesce only the relevant execution
context but serialize against node-boundary mutation and VMState. Command
progress is one-way:

```text
received -> validated -> armed -> reached -> applying -> applied -> acknowledged
                     \-> canceled / not_applicable / past_boundary / rejected
```

Once applying, cancellation is impossible, and a bounded 4,096-sequence window
rejects duplicate or stale sequences. Same-boundary commands order by phase,
command kind, binding hash, opportunity hash, and sequence, independent of host
publication order. Two-command prepare/commit transactions complete at the
unchanged boundary while the scheduler ceiling stays pinned.

Virtual-time-authored node effects are refined with QEMU's concrete
retired-instruction coordinate; the refinement is authenticated in evidence and
supplied before preparation during replay so a mismatch fails before mutation.

## Capabilities and target manifests

QEMU advertises capability rows (60 bytes each: command kind, architecture or
device scope, semantic version, supported-phase mask, maximum payload, maximum
pending, required feature bits, identity hash). Scopes are `all`, `x86_64`,
`aarch64`, `virtio`, `device`, and `accelerator`. Feature bits cover memory
mutation, memory access, register mutation, instruction, interrupt, hardware
error, vCPU service, node lifecycle, guest clock, accelerator, and VMState.
Target manifests enumerate registers, interrupts, hardware-error sources,
clocks, and accelerators. The host computes an exact, canonically ordered
requirement whose digest is part of launch identity; QEMU must satisfy it
before the boot barrier is released, and the same digest is reused for
admission and replay.

## Inertness and state

Every fault hook requires `-accel sim`, the matched plugin, successful ABI
negotiation, and an armed capability. Otherwise the shared QEMU paths take the
unmodified upstream branch, and non-sim behavior equals pinned upstream QEMU.
Canonical mutations never use GDB, QMP memory or register writes, or host
timing.

Fault rules, armed commands, order keys, and partially published results are
serialized in QEMU VMState. A snapshot cannot be taken while a handler is
applying; QEMU completes or rolls back first. Restore rebuilds rule indexes from
the authenticated ledger. The node continuation also restores the round-robin
scheduler cursor and network ring cursors so a fresh QEMU process resumes
exactly.

## Changing the QEMU side

Changes update the atomic patch, the generated ABI, the corresponding-source
identity, `pkgs/emulation/qemu-patches/LICENSES.md` when files are added or
removed, and the affected live gates together, and need a DCO sign-off (see
[CONTRIBUTING.md](../../../../CONTRIBUTING.md)). Every capability needs a live
integrated-QEMU test proving the architectural or device state changed exactly
as specified, plus evidence that non-sim behavior is unchanged; mock or
test-double backends are not acceptable application evidence.
