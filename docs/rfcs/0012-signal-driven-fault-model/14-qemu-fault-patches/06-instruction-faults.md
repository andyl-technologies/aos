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
digest, decoded length, opcode/class ID, control-flow class, explicit register
read/write set where known, memory/atomic/MMIO class, exception boundary, and TB
identity. The host selector resolves to PC/range, bytes digest or opcode class,
vCPU, occurrence ordinal, and optional input-state precondition.

When any rule can match a page/range, translation emits an exact pre/post hook and
forces a boundary around the instruction sufficient to isolate its effects.
Unaffected code uses the upstream translation path except for the indexed empty-
match check covered by performance gates.

## Result corruption

Result corruption targets one or more decoded destination registers/flags via
the register manifest and applies a registered bit/field transform after the
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
allowed only when its manifest declares a deterministic sequential re-entry
contract; otherwise it is rejected. Exceptions terminate remaining replays
unless the effect explicitly selects an exception policy registered for that
architecture.

This definition intentionally models duplicated side effects. A “recompute but
commit once” behavior would be a different effect and is not accepted.

## Exception injection

The payload names architecture exception ID/vector/class, syndrome/error fields,
fault address where applicable, privilege/EL target, timing `before` or `after`,
and maskability. QEMU uses the architecture exception entry machinery. Invalid
combinations reject before state change. Machine-check/hardware-error classes use
patch 0054 rather than this generic exception hook.

## Ordering and self-modifying code

At one instruction: before-exception, skip decision, normal/replayed execution,
memory access transforms, result corruption, after-exception, then interrupt
delivery. Binding/order evidence retains every contributor. The instruction
bytes/page generation are revalidated immediately before each execution/replay;
self-modification mismatch returns `precondition_mismatch` and never applies the
old decode.

## VMState and evidence

Evidence includes metadata manifest/hash, bytes, PC/GPA page, vCPU, occurrence,
input-state digest, operation kind, replay ordinal, register/memory/device side-
effect digests, exception state, before/after fingerprints, and retired/skipped
counter treatment. Patch 0059 serializes rules, occurrence counters, active
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
6. Check checkpoint before/after rule and between distinct instructions.
7. Benchmark disabled, empty, sparse non-match, and active hooks.
8. Revert patch and fail live gate; prove non-sim inertness.

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
