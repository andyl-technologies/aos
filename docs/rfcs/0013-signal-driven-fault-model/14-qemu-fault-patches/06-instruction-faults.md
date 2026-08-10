# Patch 0052 — `crucible-instruction-faults`

## Purpose

Implements instruction-result corruption, instruction skip, instruction replay,
and illegal/spurious exception injection at exact architecture instruction
opportunities. This is intentionally a separate high-risk patch because it
changes TCG translation/execution boundaries.

## Capability and dependencies

- Provides `qemu.instruction-fault.x86_64.v1` and
  `qemu.instruction-fault.aarch64.v1`.
- Depends on 0047–0051, TCG execution callbacks, safe boundary, TB invalidation,
  and architecture register manifests.

## Instruction manifest and selector

At translation, QEMU emits immutable metadata for potentially matching
instructions: architecture, virtual PC, physical code page/version, exact bytes
and digest, decoded length, opcode/class ID, control-flow class, explicit register
read/write set where known, memory/atomic/MMIO class, exception boundary, and TB
identity. The closed selector contains a virtual-PC start and positive length,
optional exact instruction bytes, optional opcode class, and `every/periodic`
occurrence policy and optional exact input-state SHA-256 precondition. The target
supplies the vCPU. The command envelope's precondition remains reserved for the
atomic prepare/commit rule-set digest and is not overloaded with runtime state.

The immutable runtime manifest is the exhaustive decoder contract, not a broad
ISA-family promise. It names the exact x86 opcode/range and ModR/M families and
the exact AArch64 mask/value pairs accepted by this patch. The bridge retrieves
the manifest bytes through
`qemu_plugin_crucible_fault_instruction_manifest`, verifies their SHA-256, and
binds that digest into every event. Admission rejects a selector whose requested
class or mutation is outside this table:

| Class | x86-64 admitted encodings | AArch64 admitted encodings | Mutations |
| --- | --- | --- | --- |
| integer | `89`, `8b`, `01`, `03`, `29`, `2b`, `31`, `33`, `39`, `3b`, `85`, `b8-bf`, `c7/0`, `ff/0-1` | masks for PC-relative, logical, add/subtract, move-wide, and data-processing-register families | result, skip, replay subject to destination/side-effect gates |
| control flow | `70-7f`, `0f80-8f`, `e8`, `e9`, `eb`, `c2`, `c3`, `ca`, `cb`, `cf`, `ff/2-5` | immediate/conditional/test branches and `br`, `blr`, `ret` masks | skip only; replay and result mutation reject |
| load | integer and admitted SSE load forms listed by the manifest | admitted load/store mask decoded as load | result, skip, replay |
| store | integer and admitted SSE store forms listed by the manifest | admitted load/store mask decoded as store | skip and replay; result mutation rejects |
| atomic | `86`, `87`, `0fb0-0fb1`, `0fc0-0fc1`, and admitted locked read-modify-write forms | exclusive/atomic family mask | replay only; skip and result mutation reject |
| FP/SIMD | admitted `0f10-11`, `0f28-29`, arithmetic, and `66`/`f3` move forms | Advanced SIMD and scalar FP masks | result, skip, replay subject to exact destination decoding |
| exception-producing | `cc`, `cd`, `ce`, `f1`, `0f0b` | exception-generation mask | skip only |
| device I/O | `e4-e7`, `ec-ef` | none in this patch | replay only |

x86 address-size overrides reject. Prefix decoding is limited to lock, operand
size, repeat, segment, and REX prefixes enumerated by the manifest. Any opcode,
prefix combination, destination, or side-effect class not decoded exactly is
unsupported and fails admission; it never falls through to a guessed class.

When any rule can match a page/range, translation emits an exact pre/post hook and
forces a boundary around the instruction sufficient to isolate its effects.
Unaffected code uses the upstream translation path except for the indexed empty-
match check covered by performance gates.

## Result corruption

Result corruption targets one exact decoded destination register/flag via the
register manifest and applies the embedded `bit_flip/stuck/replace` transform after the
instruction commits but before interrupt/next-instruction observation. Memory
load return corruption uses the load destination register here or the memory
access hook; memory stores are handled by patch 0050. If a destination cannot be
identified and the command does not name an exact writable register, admission
rejects it.

## Skip

Skip suppresses every architectural side effect of the selected instruction and
sets the architecture next PC to the decoded sequential successor. It does not
execute memory/MMIO access, raise the instruction's normal exception, update
flags, or retire its normal side effects. The sim aggregate instruction counter
still consumes one explicit `skipped_instruction` unit so scheduler/replay
progress is monotone and the event is distinguishable from execution. Skipping a
delay slot, architecturally indivisible instruction group, or instruction whose
successor cannot be decoded is rejected.

## Replay

Replay executes the complete selected instruction `replay_count` additional
times. Each replay has a stable replay ordinal and repeats all architectural
effects, including memory and modeled MMIO/device accesses, against the state
left by the previous execution. After each replay except the last, QEMU restores
only the instruction PC to the original PC; it does not roll back registers,
memory, devices, exceptions, or interrupts. A control-flow instruction replay is
rejected by this manifest. Exceptions terminate remaining replays at the first
exception and produce a fail-closed error event rather than silently completing
the requested replay count. No hidden replay-exception policy exists.

This definition intentionally models duplicated side effects. A “recompute but
commit once” behavior would be a different effect and is not accepted.
For the admitted x86 port-I/O class, every original and repeated execution must
produce a canonical `CRUCIOP1` transcript containing each dispatched direction,
port, width, exact value, and completion result in order. The transcript has an
independent domain-separated SHA-256. Missing, unsuccessful, malformed, or
altered I/O evidence converts the opportunity to a fail-closed error; a change
in broad VMState alone is never accepted as proof of a device side effect.

## Exception injection

The payload names `x86_64/aarch64`, numeric vector/class and syndrome, optional
fault address, timing `before_instruction` or after, and maskability. Exception
entry uses the guest's architectural privilege/EL state at that opportunity;
the payload cannot forge a different level. The record is
`architecture_default` for ordinary exceptions or carries the complete matching
x86 machine-check/AArch64 RAS fields defined by the common JSON contract. QEMU
uses the architecture exception entry machinery. Invalid
combinations reject before state change. Machine-check/hardware-error classes use
patch 0054 rather than this generic exception hook.
The prepare command remains pending while an exception is queued. QEMU emits
the terminal `applied` command result only after the architecture delivery hook
has verified vector, syndrome, fault address, entry PC, and post-entry state;
there is no earlier success result and no private delivery record in the result
payload.

## Ordering and self-modifying code

At one instruction: before-exception, skip decision, normal/replayed execution,
memory access transforms, result corruption, after-exception, then interrupt
delivery. Binding/order evidence retains every contributor. The instruction
result-corruption stage orders matching contributors by unsigned bytewise
`binding_hash`, then `action_hash`, then command sequence. Each contributor
observes the register state left by its predecessor and emits its own
before/after evidence and, for an impulse, its own terminal command result.
Any overlap involving skip or replay is rejected atomically. Overlapping PC
ranges are not a conflict when exact instruction-byte selectors differ, opcode
classes differ, or an exact instruction's decoded class differs from the other
selector's class.

The instruction
bytes/page generation are revalidated immediately before each execution/replay;
self-modification never applies the old decode. A selector input-state mismatch is a modeled
`suppressed` opportunity: it consumes the occurrence and executes the original
instruction unchanged. A byte/page mismatch after admission is an integrity
failure: QEMU emits `error`, stops simulation, and never executes stale decoded
metadata.

Result-corruption occurrence selection happens only after the instruction
commits a result. A naturally faulting instruction produces no result
opportunity, does not advance the result rule's occurrence counter, emits no
result-fault event, and follows the guest's normal exception path. If the guest
repairs the fault and retries the same PC successfully, that committed retry is
the next eligible result opportunity.

## VMState and evidence

QEMU emits private `CRUCINS1` version 3 records and `CRUCEXC1` version 2 delivery
records. The GPL bridge validates framing, reserved bytes, payload SHA-256,
binding, generation, action/target identity, manifest identity, selector bytes
and class, input digest, vCPU, phase, PC, replay fields, destinations, complete
CPU/RAM/migration-VMState/system digests, device-I/O transcripts, and actual
exception entry. It republishes only the
pointer-free permissive `CRUCIEV1` or `CRUCEEV1` record defined by
`crucible_shmem_abi.h`. Instruction outcomes are exactly `applied`,
`suppressed`, or `error`; exception evidence exists only after completed
architectural entry.

Canonical evidence includes metadata manifest/hash, exact bytes, PC/GPA code
pages, vCPU, the selector's expected input-state digest, the separately
authenticated actual state against which that selector was evaluated,
operation kind, replay ordinal, decoded
destinations, register detail, before/after CPU, RAM, migration-VMState and
composite system fingerprints,
byte counts, authenticated device transaction transcripts, and exception
delivery state. The migration-VMState stream is broad context and may contain
registered CPU sections; it is not used as the proof that port I/O occurred.
Patch 0059 serializes rules, occurrence counters, active
replay state, and pending hooks. Snapshot is prohibited mid-instruction and
occurs only at the next safe boundary.

## Live microtests

1. x86-64 and AArch64 guests cover integer, branch, load/store, atomic, FP/SIMD,
   exception-producing, and modeled MMIO instruction classes where supported.
2. Prove result corruption changes only named destinations.
3. Prove skip creates no normal side effects and advances exact successor/counter.
4. Prove replay duplicates register, RAM, atomic, and modeled device effects in
   replay-ordinal order.
5. Verify self-modifying code, wrong bytes/input digest, invalid control-flow,
   unsupported indivisible groups, and exception mismatches fail loudly.
6. Prove single and ordered result transforms with matching input-state
   selectors, and prove a naturally faulting result-selected load leaves the
   rule armed until a committed retry.
7. Saturate the bounded event queue while a result contributor is active and
   prove one canonical terminal record, safe re-entrant unwind, and fail-closed
   stop.
8. Check checkpoint before/after rule and between distinct instructions.
9. Benchmark disabled, empty, sparse non-match, and active hooks.
10. Revert patch and fail live gate; prove non-sim inertness.

## Licensing checklist

TCG translators/execution and architecture exception changes are GPL-side,
preserve upstream licensing, and are gated structurally on sim-fault rules. The
public host protocol contains only decoded stable metadata/values, not TCG ops,
CPU structs, or translator callbacks. DCO, microtests, license inventory,
catalog, and corresponding source update atomically.

- **[QFP-INSN-1]** Skip and replay semantics MUST be architecture-conformant and
  live-tested per advertised instruction class; unclassified instructions fail.
- **[QFP-INSN-2]** Replay MUST expose every repeated side effect with a stable
  replay ordinal; QEMU may not optimize repeated execution into one result.
