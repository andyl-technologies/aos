# 0085 - Register rejection atomicity

## Purpose

This patch closes the observation and rejection contract for architecture
register faults. It adds no alternate mutation path. It strengthens the one
manifest-driven implementation introduced by patch `0051` and the rejection
matrix completed by patch `0082`.

## Admission and ownership

Live canonical or single-register observation is permitted only when all of the
following are true:

1. the `sim` accelerator is running deterministic single-thread TCG;
2. the caller is inside an exact plugin callback or the internal deterministic
   fault-boundary dispatcher;
3. `current_cpu` exists; and
4. `current_cpu->cpu_index` equals the serialized RR owner.

A stale `current_cpu`, a scheduler handoff, an ordinary plugin callback, MTTCG,
and an unowned main-loop context fail closed. For both node and instruction
phases, the central internal dispatcher brackets the complete
prepare/commit/completion transaction with the same nestable exact-boundary
token, so validation and reentrant completion cannot fall out of the admitted
ownership context. The only other admitted context is a
non-running VM observed while the caller holds the BQL. This stopped path is for
terminal-state export and may inspect every realized vCPU.

The fault-register reader additionally requires the requested vCPU to be the
serialized owner. Register-manifest seal, fault-register read, mutation decode,
and state fingerprint each compare every row - including names, widths, groups,
phase masks, capability bits, side-effect bits, and all four bit-class masks -
for every realized vCPU against the sealed model manifest.

## Whole-machine rejection observation

`qemu_plugin_crucible_register_rejection_observe` constructs one SHA-256 digest
from the canonical GDB export of every realized vCPU in numeric order. Framing
binds the domain, vCPU index, encoded length, retired-instruction field, register
descriptor names and features, register lengths, and register bytes. The export
uses architecture GDB readers only; in particular, x86 MXCSR observation uses
the pure getter and cannot synchronize state as a read side effect.

The same observation snapshots six monotonic counters, indexed by the existing
register side-effect bitmap. A thread-local audit scope is entered only around
an admitted architecture register write. Production primitives increment the
counters only while executing in that call chain, so ordinary interrupts,
translation maintenance, and vCPU exits cannot be misattributed to a register
mutation:

| Index | Effect | Instrumented production operation |
| --- | --- | --- |
| 0 | TLB | `tlb_flush` |
| 1 | TB | `tb_flush` |
| 2 | flags | architecture flags/FPU status recomputation |
| 3 | interrupt | interrupt request/reset and architecture reevaluation |
| 4 | timer | reserved and required to remain zero because no supported register advertises a timer side effect |
| 5 | control flow | `cpu_exit` |

The user-mode build receives inert inline scope and observation hooks because
Crucible register faults exist only in system emulation. System emulation
records the real production operations reached from the mutation call chain;
tests do not substitute a model or fake counter source. Scope depth is
thread-local so unrelated I/O-thread or main-loop activity cannot enter the
audit accidentally, and an unbalanced scope is a fatal QEMU invariant failure.

## Rejection transaction

For every decoded register command, the node handler captures a complete
observation before any preparatory rejection can occur. Immediately around
architecture validation it captures and compares another observation. Before
returning a later precondition or framing rejection it captures and compares a
third observation. Any digest or counter difference converts the result to
`INTERNAL_ERROR`; it is never reported as an atomic rejection.

An architecturally invalid command returns the equal, nonzero canonical digest
as both result hashes. A synchronous inconsistent-identity envelope is rejected
before node preparation, so the live plugin captures and compares the same
observation around the reentrant submit/completion call. Every rejection also
requires zero `applied_icount`, empty typed evidence, no emitted fault event,
and an unchanged full selected-register value.

## Files and license scope

- `plugins/api-system.c`, `plugins/api.c`, and public plugin headers expose and
  enforce exact-boundary RR ownership.
- `plugins/crucible-fault.c` owns exact admission for the full internal boundary
  transaction.
- `plugins/crucible-fault-register.c` owns manifest-wide validation, canonical
  hashing, and effect counters.
- `plugins/crucible-fault-node.c` owns fail-closed rejection transactions.
- `target/i386/crucible-register.c` and `target/arm/crucible-register.c` report
  architecture-derived flags and interrupt effects.
- TLB, TB, interrupt, and CPU-exit production primitives report their actual
  invocations.
- `tests/tcg/plugins/crucible-register.c` exercises the live implementation.

All changes remain in the QEMU/applicable GPL process. No QEMU object, native
pointer, or counter crosses into the Apache host or shared-memory ABI. Existing
files retain their per-file licenses; the patch creates no QEMU source file and
therefore adds no `LICENSES.md` row.

## Required gates

The register matrix must run every supported x86-64 and AArch64 mutation and
rejection case against patched QEMU. It must prove ownership rejection outside
an exact serialized callback, full-manifest divergence rejection at read and
decode, exact canonical digest equality for delayed failures, side-effect
counter equality for every failure, and reentrant equality for malformed
identity. Patch regeneration, ABI conformance, non-sim inertness, VMState
continuation, and license-boundary gates remain mandatory.

- **[QFP-REG-3]** Live register observation MUST prove exact-callback depth and
  serialized RR ownership; execution-mode checks alone are insufficient.
- **[QFP-REG-4]** A rejected register command MUST preserve every canonical GDB
  register byte and every declared mutation-derived side-effect counter.
