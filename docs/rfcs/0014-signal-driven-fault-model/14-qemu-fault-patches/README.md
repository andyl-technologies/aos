# 14 — QEMU fault-mutation capability tasks

The complete node adapter and its exact-checkpoint handoff ship in the single
atomic Crucible QEMU integration patch. The files in this directory specify
numbered capability tasks within that integration. Their numbers and names are
requirement and evidence identities; they do not describe independent patches
or an application sequence.

This directory specifies engineering and licensing boundaries; it is not legal
advice. The controlling repository policies are
[`LICENSING.md`](../../../../LICENSING.md), the
[`Crucible/QEMU process boundary`](../../0010-crucible/37-licensing-process-boundary.md),
the existing [`atomic QEMU integration contract`](../../0010-crucible/11-qemu-patches.md),
and [`pkgs/emulation/qemu-patches/README.md`](../../../../pkgs/emulation/qemu-patches/README.md).

## 14.1 Capability task map

| Capability task | Responsibility | Risk |
| --- | --- | --- |
| [`0047-crucible-fault-command-abi`](01-command-abi.md) | Closed fault command/result ABI, capability registry, dispatcher shell | Feature |
| [`0048-crucible-fault-safe-boundary`](02-safe-boundary.md) | Exact-icount quiescence, authorization, command commit and acknowledgement | Determinism-critical |
| [`0049-crucible-memory-boundary-mutate`](03-memory-boundary-mutation.md) | Atomic GPA/GVA memory impulse mutation and evidence | Feature |
| [`0050-crucible-memory-access-faults`](04-memory-access-faults.md) | Load/store/fetch/DMA transforms, poison, retention, rowhammer, service | Determinism-critical |
| [`0051-crucible-register-mutate`](05-register-mutation.md) | Architecture-typed register bit/field mutation | Feature |
| [`0052-crucible-instruction-faults`](06-instruction-faults.md) | Instruction result corruption, skip/replay, exception hooks | Determinism-critical |
| [`0053-crucible-interrupt-faults`](07-interrupt-faults.md) | Drop/delay/duplicate/replace/storm across interrupt lifecycle | Determinism-critical |
| [`0054-crucible-hardware-error-inject`](08-hardware-errors.md) | x86 machine check, AArch64 hardware error, ECC/platform reporting | Determinism-critical |
| [`0055-crucible-vcpu-service-control`](09-vcpu-service.md) | Capacity throttling, stall, offline, deterministic service credits | Determinism-critical |
| [`0056-crucible-node-lifecycle-faults`](10-node-lifecycle.md) | Crash, hang, boot failure, reset, power cycle and state-loss policy | Determinism-critical |
| [`0060-crucible-block-typed-errors`](14-block-typed-errors.md) | Closed block result transport and exact guest-visible errno translation | Feature |
| [`0061-crucible-block-discard`](15-block-discard.md) | Payload-free deterministic block discard transport | Feature |
| [`0062-crucible-block-transport-reset`](16-block-transport-reset.md) | Transactional epoch, recovery, retry, duplicate-history, and re-enumeration transport | Feature plus determinism-critical lifecycle |
| [`0063-crucible-plugin-vmstop`](17-plugin-vmstop.md) | Exact plugin-boundary handoff into QEMU's native paused runstate | Determinism-critical lifecycle |
| [`0064-crucible-terminal-lifecycle-completion`](18-terminal-lifecycle-completion.md) | Two-phase authenticated lifecycle event and QMP-authorized process exit | Determinism-critical lifecycle |
| [`0065-crucible-authenticated-terminal-lifecycle`](19-authenticated-terminal-lifecycle.md) | Dedicated idempotent terminal authorization bound to action, evidence, and process generation | Determinism-critical lifecycle |
| [`0066-crucible-immutable-process-generation`](20-immutable-process-generation.md) | Launch-time immutable process identity used by terminal authorization and restore validation | Determinism-critical lifecycle |
| [`0067-crucible-core-fault-vmstate`](21-core-fault-vmstate.md) | Transactional bounded save/restore for the implemented core fault domains | Determinism-critical |
| [`0068-crucible-guest-clock-faults`](11-guest-clocks.md) | Offset, drift, jump, freeze, jitter, source failure and timer consistency | Determinism-critical |
| [`0069-crucible-accelerator-fault-device`](12-accelerator-device.md) | Production QEMU co-sim accelerator device and fault hooks | Feature plus determinism-critical service hooks |
| [`0070-crucible-fault-vmstate`](13-vmstate-and-final-gates.md) | VMState closure, terminal capability/evidence, and aggregate gates | Determinism-critical |
| [`0071-crucible-lifecycle-precondition`](22-lifecycle-precondition.md) | Lifecycle prepare/commit precondition identity | Determinism-critical |
| [`0072-crucible-typed-node-result-schema`](23-typed-node-result-schema.md) | Stable command results and separate occurrence evidence | Determinism-critical |
| [`0073-crucible-device-wait-vmstop`](24-device-wait-vmstop.md) | Exact nonblocking checkpoint-stop admission from device callbacks | Determinism-critical lifecycle |
| [`0074-crucible-arm-accelerator-result-opportunities`](25-accelerator-result-opportunity.md) | Durable one-shot accelerator result arming and canonical deferred results | Feature plus determinism-critical state |
| [`0075-crucible-restore-authenticated-fault-event-requests`](26-authenticated-event-request-envelope.md) | Mandatory request/evidence event envelopes, fresh-process reconstruction, and exact accelerator-job binding | Determinism-critical state and authentication |
| [`0076-crucible-9p-completion-wake-registration`](27-9p-completion-wake-registration.md) | Realize-time 9p completion notifier independent of plugin installation order | Determinism-critical device lifecycle |
| [`0077-crucible-serialize-rr-cursor`](28-serialized-rr-cursor.md) | Authoritative RR-turn accounting and VMState restoration | Determinism-critical scheduler state |
| [`0078-crucible-fingerprint-guest-state-domains`](29-fingerprint-guest-state-domains.md) | Guest-state-only fingerprints with target-declared transient interrupt canonicalization | Determinism-critical restore admission |
| [`0079-crucible-stopped-state-control-progress`](30-stopped-state-control-progress.md) | Level-triggered queued-work checks and bounded progress for a paused native-stop handshake | Determinism-critical scheduler lifecycle |
| [`0080-crucible-inactive-retention-clock-guard`](31-inactive-retention-clock-guard.md) | Active-rule admission before restore-sensitive memory-retention clock sampling | Determinism-critical restore ordering |
| [`0081-crucible-deferred-result-evidence-test`](32-deferred-result-evidence-test.md) | Live validation of canonical typed evidence on deferred instruction completions | Feature-contract regression coverage |
| [`0082-crucible-deterministic-instruction-input-state`](33-deterministic-instruction-input-state.md) | Cross-process-stable register preconditions with full device-state hashes retained | Determinism-critical selector identity |
| [`0083-crucible-inert-clock-restore`](34-inert-clock-restore.md) | Preserve QEMU-native timers when restored guest-clock faults are inactive | Determinism-critical restore ordering |
| [`0084-crucible-exact-restore-network-announcement`](35-exact-restore-network-announcement.md) | Suppress migration-only virtio-net announcements during exact restore | Determinism-critical network continuation |
| [`0085-crucible-register-rejection-atomicity`](36-register-rejection-atomicity.md) | Prove exact RR ownership and whole-machine architectural atomicity for rejected register commands | Determinism-critical fault rejection |
| [`0087-crucible-deterministic-rcu-quiescence`](38-deterministic-rcu-quiescence.md) | Prevent host-timed forced RCU kicks from changing guest interrupt visibility in sim mode | Determinism-critical scheduler execution |
| [`0088-crucible-deterministic-host-kick-boundary`](39-deterministic-host-kick-boundary.md) | Defer state-free latency hints while preserving committed control and interrupt progress | Determinism-critical scheduler execution |
| [`0089-crucible-exact-boundary-vcpu-introspection`](40-exact-boundary-vcpu-introspection.md) | Admit quiescent all-vCPU registers and the committed RR cursor at exact control boundaries | Determinism-critical checkpoint observation |
| [`0090-crucible-active-tcg-kick-boundary`](41-active-tcg-kick-boundary.md) | Prove active guest execution and defer host service to the finite RR boundary | Determinism-critical scheduler execution |
| [`0091-crucible-canonical-rr-genesis-cursor`](42-canonical-rr-genesis-cursor.md) | Expose the unique raw-zero scheduler coordinate before first vCPU selection | Determinism-critical checkpoint observation |
| [`0092-crucible-canonical-terminal-rr-cursor`](43-canonical-terminal-rr-cursor.md) | Project a live quantum-terminal observation onto the scheduler's next committed coordinate | Determinism-critical execution fingerprinting |
| [`0093-crucible-canonical-register-cursor`](44-canonical-register-cursor.md) | Advance after-instruction register evidence onto its canonical committed RR coordinate | Determinism-critical register evidence |
| [`0094-crucible-retention-virtual-time-origin`](45-retention-virtual-time-origin.md) | Anchor retention installation and expiry in authoritative virtual nanoseconds | Determinism-critical memory-fault timing |
| [`0095-crucible-raw-pte-update-identity`](46-raw-pte-update-identity.md) | Preserve backing PTE identity across transient corrected page-walk faults | Determinism-critical memory-fault progress |
| [`0096-crucible-physical-page-table-region-fixture`](47-physical-page-table-region-fixture.md) | Target persistent page-table regions by descriptor GPA in live tests | Feature-contract regression coverage |
| [`0097-crucible-canonical-memory-retry-identity`](48-canonical-memory-retry-identity.md) | Exclude TB-local ordinals from durable memory retry identity | Determinism-critical memory-fault retry |
| [`0098-crucible-inactive-nested-tsc-guard`](49-inactive-nested-tsc-guard.md) | Avoid nested TSC sampling when guest-clock faults are inactive | Determinism-critical inactive-path parity |
| [`0099-crucible-valid-aarch64-abort-fixture`](50-valid-aarch64-abort-fixture.md) | Exercise poison exceptions and retries with an architecturally valid AArch64 data abort | Feature-contract regression coverage |
| [`0100-crucible-aarch64-memory-exception-vectors`](51-aarch64-memory-exception-vectors.md) | Admit AArch64 memory exceptions through their matching architectural vectors | Determinism-critical memory-fault validation |
| [`0101-crucible-canonicalize-snapshot-rr-resume`](52-canonical-snapshot-rr-resume.md) | Preserve the serialized RR owner and intra-turn position after source-side snapshot creation | Determinism-critical checkpoint continuation |
| [`0102-crucible-bql-exact-register-capture`](53-bql-exact-register-capture.md) | Admit quiescent BQL-held register capture while snapshot RR reselection is pending | Determinism-critical checkpoint observation |
| [`0103-crucible-isolate-checkpoint-control-wake`](54-checkpoint-control-wake-isolation.md) | Hand native stop to the main loop without resuming parked block requests | Determinism-critical checkpoint I/O isolation |
| [`0104-crucible-preserve-checkpoint-block-durability`](55-checkpoint-block-durability.md) | Preserve volatile Apache durability state across QEMU's synthetic stop flush | Determinism-critical checkpoint durability |
| [`0105-crucible-selector-control-plane-fixtures`](56-selector-control-plane-fixtures.md) | Isolate live selector-admission fixtures from installed data-plane faults | Feature-contract regression coverage |
| [`0106-crucible-defer-active-slice-host-wakes`](57-defer-active-slice-host-wakes.md) | Defer state-free host wakes across every multi-vCPU bounded RR slice | Determinism-critical scheduler execution |
| [`0107-crucible-anchor-rr-cursor-genesis`](58-anchor-rr-cursor-genesis.md) | Establish the serialized RR cursor before the first execution budget | Determinism-critical scheduler state |
| [`0108-crucible-deterministic-network-kick`](59-deterministic-network-kick.md) | Preserve sim-mode virtio-net transmit and interrupt-notification continuation | Determinism-critical network continuation |
| [`0109-crucible-control-boundary-node-faults`](60-control-boundary-node-faults.md) | Dispatch halted-node PREPARE and APPLY commands at their exact drained control boundary | Determinism-critical node mutation progress |
| [`0110-crucible-release-halted-rr-turn`](61-release-halted-rr-turn.md) | Leave an all-halted partial RR turn and commit a cursor-zero handoff for a multi-vCPU guest `PAUSE` | Determinism-critical scheduler progress |
| [`0111-crucible-accelerator-service-schema`](62-accelerator-service-schema.md) | Admit the typed ratio-valued accelerator capacity field through the closed QEMU schema | Feature-contract correctness |
| [`0112-crucible-compile-affected-clock-sources`](63-compile-affected-clock-sources.md) | Recompile and rearm only clock sources selected by the committed rule | Transactional clock-source correctness |
| [`0113-crucible-restore-accelerator-rule-indexes`](64-restore-accelerator-rule-indexes.md) | Rebuild persistent accelerator rule indexes from the authenticated staged node ledger during VMState restore | Fresh-process continuation correctness |
| [`0133-crucible-authenticate-fault-result-payloads`](65-authenticate-fault-result-payloads.md) | Hash the exact retained payload for every queued fault result, including typed rejections | Transactional result correctness |
| [`0134-crucible-clock-impulse-read-error-policies`](66-clock-impulse-read-error-policies.md) | Persist effective impulse policies in clock VMState and expose deterministic x86 TSC read-error behavior | Guest-clock correctness |

The table order records capability dependencies. The atomic patch and its
source-level and live gates provide the implementation and evidence as one unit.
Changes update the atomic patch, generated ABI, complete corresponding-source
identity, license inventory, and affected gates together. Task numbers are
documentation identities only; they do not select runtime or packaging behavior.

## 14.2 Process and license boundary

```text
Apache-2.0 host process               QEMU process / applicable GPL scope
┌────────────────────────────┐       ┌──────────────────────────────────┐
│ signal/binding/adapters    │       │ crucible-qemu-plugin GPL-2.0-only│
│ schedules typed effect     │       │ validates command + calls QEMU  │
│                            │       │                                  │
│ dual MIT/Apache protocol   │◄═════►│ atomic integration source       │
│ fixed-width SHM entries    │ SHM   │ upstream/per-file GPL scope      │
└────────────────────────────┘       └──────────────────────────────────┘
```

- Host crates never include QEMU headers, link QEMU libraries, use QEMU structs,
  or invoke patch/plugin functions.
- The public shared-memory command/result protocol lives only in the dual-
  licensed boundary crates and contains fixed-width integers, byte payloads,
  offsets, lengths, versions, IDs, and digests—never native pointers or QEMU
  objects.
- The GPL-2.0-only plugin translates validated protocol messages into in-process
  QEMU patch calls. No Apache-only crate is linked into or loaded by QEMU.
- Modified upstream files retain their notices. New unmarked QEMU files follow
  the pinned QEMU default, currently GPL-2.0-or-later, unless an explicit
  per-file notice applies. New files update `LICENSES.md` in the same commit.
- Every commit touching the atomic QEMU patch or in-QEMU/plugin code carries a
  DCO
  `Signed-off-by` line. Commit messages and patches contain no AI attribution.
- Distribution of the patched binary includes identity-matched complete
  corresponding source: pinned QEMU, the atomic integration patch,
  plugin/QEMU-side sources, generated ABI inputs, build scripts, and notices.

- **[QFP-1]** `gate:license-boundary` MUST reject any QEMU-private type or direct
  call crossing into the Apache host and any Apache-only dependency on the GPL
  side.
- **[QFP-2]** Every atomic integration change MUST update its source identity,
  corresponding-source closure, catalog, invariant mapping, microtest inventory,
  and license inventory where applicable.

## 14.3 Common command/result protocol

The public protocol transports a closed command envelope:

```text
FaultCommandHeaderV1 {
  abi_major: u16
  abi_minor: u16
  command_kind: u16
  command_flags: u16
  phase: u16
  reserved_zero_phase: u16
  semantic_version: u32
  command_sequence: u64
  target_node_hash: [u8; 32]
  target_icount: u64
  authorization_ceiling_icount: u64
  binding_hash: [u8; 32]
  opportunity_hash: [u8; 32]
  expected_precondition_hash: [u8; 32]
  payload_hash: [u8; 32]
  payload_offset: u64
  payload_length: u32
  reserved_zero: u32
}
```

The result contains ABI major/minor, the same sequence/kind/version, status,
observed/applied icount, QEMU capability version, reached phase,
before/after/evidence hashes, a typed-result payload hash, typed result
offset/length, and reserved zero fields. The command header is exactly 216
bytes, the result header exactly 188 bytes, and a capability row exactly 60
bytes. Command kinds, statuses, phases, every byte offset, and resource ceilings
are generated into the independently consumable C header from the dual-licensed
boundary crate. Out-of-line command and result bytes are authenticated by the
hash in their envelope before decoding.

Statuses are `applied`, `not_applicable`, `precondition_mismatch`,
`invalid_target`, `invalid_phase`, `unsupported_capability`, `past_boundary`,
`resource_limit`, `guest_rejected`, `internal_error`, `malformed_command`,
`duplicate_sequence`, `authentication_failed`, and `prepared`. The only version
1 command flag is `prepare_only`; handlers that do not explicitly implement it
reject it as malformed. A result echoes the raw command-kind tag so even an
unknown kind receives a canonical rejection; an
`applied` result must name a registered kind. `prepared` is the successful,
non-mutating result of an explicitly requested prepare-only command. Any other
status except `applied` is a loud run outcome unless the effect contract
explicitly expects `not_applicable` as an opportunity result. Every
non-mutating result has `applied_icount = 0` and `after_hash == before_hash`.

The host reserves a command slot, writes payload, publishes with release order,
and rings the existing eventfd. The plugin acquires, validates, and arms it. QEMU
applies only at the exact authorized boundary and publishes one result with
release order. Each 256-byte command/result slot carries transport-owned logical
reservation-start, payload-start, and reservation-end cursors plus the encoded
header. That framing lets a consumer release a sound arena reservation even
when the enclosed ABI bytes must be rejected. The plugin may release a command
slot only after copying its payload into QEMU-owned bounded state; the host may
release a result slot only after copying the result payload. A command sequence
remains live and cannot be reused until the host acquires its result. Ring or
arena exhaustion fails before publishing, losing, or overwriting a command.

### 14.3.1 Typed node-rule payload

Every non-memory-impulse node command uses `CRUCNOD1` version 1. Its fixed
header binds the command kind, `upsert/remove/impulse` operation, target kind,
model phase, generation, action/target/schema hashes, and exact field count.
Fields are strictly increasing tagged values. `P1` through `P9` are command
parameters; `T1` through `T5` identify the resolved target. A remove carries no
fields. Unknown, missing, duplicate, out-of-order, incorrectly typed, or
noncanonical fields are malformed commands.

Policy structures use `bytes` fields beginning with the eight literal bytes
`CRUCJSN1`, followed by whitespace-free canonical JSON with lexicographically
sorted object keys. The public codec validates framing, JSON syntax, canonical
bytes, size, and the command/tag positions without importing the Apache model
crate. The GPL-side command handler then validates the exact command-specific
shape from the [policy JSON contract](00-typed-policy-json.md), rejects unknown
members and enum variants, and retains a private typed C representation before
preparation can succeed. A hash is used only for a realized manifest identity,
never as a policy lookup key.

| Command | Exact parameter fields |
| --- | --- |
| node lifecycle | `P1 transition:u32`, `P2 downtime:u64`, `P3 NodeBootPolicy:json`, `P4 volatile policy:u32`, `P5 device policy:u32` |
| node hang | `P1 scope kind:u32`, `P2 NodeHangScope:json`, `P3 recovery event:hash`, `P4 NodeWatchdogPolicy:json` |
| CPU service | `P1 sorted vCPU IDs:json`, `P2 capacity:ratio`, `P3 quantum:u64`, `P4 CpuServiceDiscipline:u32` |
| vCPU state | `P1 state:u32`, `P2 has recovery:bool`, `P3 recovery hash or zero` |
| register transform | `P1 register:hash`, `P2 first bit:u32`, `P3 bit count:u32`, `P4 mutation:u32`, `P5 mask/bytes`, `P6 has value:bool`, `P7 value or zero`, `P8 NodeOccurrencePolicy:json` |
| instruction transform | `P1 InstructionSelector:json` (including optional runtime input-state SHA-256), `P2 mutation:u32`, `P3 destination hash or zero`, `P4 RegisterMutation:json or zero`, `P5 replay count:u32` |
| CPU exception | `P1 NodeException:json` |
| interrupt disposition | `P1 mutation:u32`, `P2 delay:u64`, `P3 copies:u32`, `P4 gap:u64`, `P5 replacement vector:u32` |
| interrupt storm | `P1 source:hash`, `P2 vector:u32`, `P3 period:u64`, `P4 burst:u32`, `P5 count:u32`, `P6 InterruptRoutingPolicy:json` |
| memory access transform | `P1 start:u64`, `P2 length:u64`, `P3 mutation:u32`, `P4 mask or zero`, `P5 has value:bool`, `P6 value/selector/MemoryPoisonPolicy JSON or zero`, `P7 NodeOccurrencePolicy:json`, `P8 access-class bits:u32`, `P9 violate atomicity:bool` |
| memory ECC event | `P1 kind:u32`, `P2 address:u64`, `P3 syndrome:u64`, `P4 bank:hash`, `P5 channel:hash`, `P6 rank:hash`, `P7 MemoryEccVisibility:json`, `P8 target vCPU:u32` |
| memory region state | `P1 start:u64`, `P2 length:u64`, `P3 kind:u32`, `P4 MemoryRegionProcess:json` |
| memory service | `P1 latency:u64`, `P2 has byte rate:bool`, `P3 byte rate:u64`, `P4 has operation rate:bool`, `P5 operation rate:u64`, `P6 MemoryServiceScope:json` |
| clock transform | `P1 source:hash`, `P2 mutation:u32`, `P3 signed value:i64`, `P4 ratio`, `P5 unsigned value:u64`, `P6 freeze-release/jitter-table/ClockWanderProcess JSON or zero`, `P7 ClockMonotonicityPolicy:u32`, `P8 ClockOverdueTimerPolicy:u32` |
| clock source state | `P1 sorted source hashes`, `P2 ClockSourceTransition:json`, `P3 ClockSynchronizationPolicy:json` |
| accelerator lifecycle | `P1 device:hash`, `P2 transition:u32`, `P3 queue policy:u32`, `P4 memory policy:u32` |
| accelerator result transform | `P1 AcceleratorJobSelector:json`, `P2 AcceleratorResultMutation:json` |
| accelerator memory event | `P1 start:u64`, `P2 length:u64`, `P3 has ECC:bool`, `P4 ECC kind:u32`, `P5 has syndrome:bool`, `P6 syndrome:u64`, `P7 has transform:bool`, `P8 transform bytes or zero` |
| accelerator service | `P1 capacity:ratio`, `P2 has memory rate:bool`, `P3 memory rate:u64`, `P4 has job rate:bool`, `P5 job rate:u64`, `P6 AcceleratorThermalPower:json` |

For `clock transform`, `Apply` accepts only offset, drift, and jump and makes
their accumulated state durable. Freeze, jitter, and wander require a retained
`Upsert` binding and later `Remove`; all six kinds support that retained
lifecycle. No clock operation/kind combination is inferred or translated.

| Target kind | Exact target fields |
| --- | --- |
| node | none |
| vCPU | `T1 numeric vCPU ID:u32` |
| register | `T1 vCPU:u32`, `T2 architecture:hash`, `T3 register:hash`, `T4 first bit:u32`, `T5 bit count:u32` |
| memory | `T1 address-space identity:hash`, `T2 guest address:u64`, `T3 has vCPU:bool`, `T4 vCPU or zero:u32`, `T5 length:u64` |
| interrupt | `T1 controller:hash`, `T2 source:hash`, `T3 target vCPU:u32`, `T4 vector:u32` |
| clock | `T1 source:hash` |
| accelerator | `T1 device:hash` |

## 14.4 Common capability acceptance template

Every retained design-slice specification fixes:

1. exact capability and effect keys;
2. command and result payload fields;
3. QEMU subsystems/touch points and activation predicate;
4. boundary phase and all-vCPU/device quiescence requirement;
5. mutation/state semantics and composition with other commands;
6. failure acknowledgement and replay preconditions;
7. VMState/dirty-tracking/fingerprint obligations;
8. focused live tests, negative controls, and non-sim inertness;
9. architecture/device coverage;
10. licensing, DCO, inventory, and corresponding-source updates.

Mock, fake, and test-double backends are prohibited. Pure host algebra tests may
exercise composition without a backend, but every capability requires a live
integrated-QEMU test that proves the guest or QEMU architectural/device state
changed exactly as specified.

## 14.5 Inertness

Every fault-mutation capability in the atomic patch requires `-accel sim`, the
matched plugin, successful fault ABI negotiation, and the relevant armed
capability. Without all predicates, upstream behavior is unchanged. Pure
additive plugin exports return unsupported when not armed. Hooks in shared QEMU
paths take the verbatim upstream branch when the sim-fault predicate is false.

- **[QFP-3]** Each capability has focused source and runtime evidence that
  exercises its active path and proves non-sim behavior equals the unpatched
  pinned QEMU.
- **[QFP-4]** Empty enabled rule indexes receive dedicated overhead and
  determinism tests; inertness is not inferred from the absence of authored
  faults.
- **[QFP-5]** The integration may not use GDB, QMP memory/register writes, host
  timing, or an unversioned callback as the canonical mutation mechanism.

## 14.6 Review ownership and commits

The implementation ships as one atomic QEMU patch with identity-matched complete
corresponding source. Review and test evidence remain organized by the numbered capability tasks
above. Each capability and boundary is independently assessable within the
single distributable atomic patch.
