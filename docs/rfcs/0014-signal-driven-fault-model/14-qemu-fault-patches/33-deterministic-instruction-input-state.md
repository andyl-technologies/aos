# Patch 0082: deterministic instruction input-state selectors

## Capability

`input_state_sha256` binds an instruction transform to the canonical
architecture-register state at the matched instruction boundary. The
surrounding instruction selector independently binds the vCPU-visible program
counter range, exact instruction bytes and/or immutable opcode class, and
occurrence. The digest domain is
`crucible.instruction-input-state.v1`.

Whole guest RAM and raw non-RAM VMState are deliberately not part of this
selector digest. Whole RAM contains unrelated firmware and runtime state, so
including it would make a local instruction selector depend on bytes the
selected instruction cannot observe. Raw device serialization contains device
bookkeeping that requires host-side canonical normalization. Full CPU, RAM,
and device before/after hashes and byte counts remain present in authenticated
instruction-occurrence evidence and the host canonical fingerprint, preserving
replay and restore admission.

This optional selector is specifically an architectural-register precondition,
not a total semantic-input predicate. For a load, store, atomic operation, or
device access it binds address-producing registers but does not bind the bytes
at the resulting memory or MMIO location. Those bytes can change without
suppressing the transform; occurrence evidence and the replay oracle record the
different whole-state hashes. Scenarios that need a memory-content precondition
must express it through the memory-fault or assertion surfaces rather than
treating `input_state_sha256` as an operand-value digest.

## QEMU changes

The instruction fault engine computes the input digest immediately after the
safe-boundary system snapshot and uses it consistently for single and composed
result transforms, mismatch suppression, and conflict evidence. Unknown or
mismatched digests remain fail-closed and produce the existing typed suppressed
event rather than applying a transform.

The observed digest is copied into the common matched-instruction metadata
before dispatching result, skip, or replay behavior. Consequently every
instruction occurrence records the actual input-state identity, including
immediate skip/error events that do not pass through the deferred execution
completion path.

The register engine exposes an internal register-state fingerprint that hashes
the architecture manifest values in stable CPU-index and numeric-register-ID
order. Unlike the existing execution fingerprint, this digest deliberately
excludes icount and round-robin scheduler coordinates. The instruction engine
domain-separates that register digest as the input-state identity. The existing
execution fingerprint is unchanged and remains the stronger
time-and-scheduler-bound value in full occurrence evidence.

When an instruction needs both identities, the register engine derives the
execution and register-state digests from one ordered register read. This is a
semantic no-op, but avoids sampling the same architecture state twice and
keeps high-frequency persistent faults practical without weakening either
digest domain.

The live cross-process selector cases run with two vCPUs on both architectures,
so the acceptance matrix exercises stable CPU-index ordering rather than only
the single-vCPU special case.

The live result-fault retry fixture begins with its deliberately faulting load
disarmed. It executes that same load against a valid address to establish its
real translated-instruction boundary, then the plugin writes the one-shot
guest trigger only after QEMU reports the rule commit as installed. The next
execution faults naturally, the guest exception handler repairs the operand,
and the still-armed production rule applies on the committed retry. This
ordering prevents either the guest exception or the rule installation from
racing the other; it is test coordination around the production mutation, not
an emulated fault path.

The saturation fixture uses the minimum-size x86 bare-metal guest and installs
a periodic selector whose first occurrence is one and whose count is exactly
the production queue capacity. The queue is shared architecture-independent
node infrastructure, while separate x86-64 and AArch64 cases cover the
architecture-specific selector and evidence paths. Event wakeups do not drain
the queue during the saturation run: ordinary events do not issue those
wakeups. The typed terminal event does notify the completion callback, which
drains and validates the full queue and requests normal shutdown before QEMU
services the terminal internal-error stop. This also ensures
persistent-selector tests encode a large occurrence *count*, rather than
accidentally delaying their first match.

The live validator independently counts exactly 4,095 applied events before
accepting exactly one terminal capacity event. It also requires the terminal
record to report that same count and the production capacity of 4,096; the
terminal record cannot prove saturation merely by self-reporting it.

The same live test source previously treated the nonzero
`architecture_default` exception-record discriminator as reserved zero bytes.
Patch 0082 corrects that expectation to discriminator `1` followed by zeroed
reserved bytes because the expanded acceptance matrix reaches this existing
version-2 exception envelope before validating the new selector behavior.

The implementation modifies `include/qemu/crucible-fault.h`,
`plugins/crucible-fault-register.c`,
`plugins/crucible-fault-instruction.c`, and the GPL-side live test plugin
`tests/tcg/plugins/crucible-instruction.c`. The bare-metal guest fixtures and
Nix harness remain Apache-side test inputs. The patch adds no process-boundary
ABI and no new file, so the existing per-file licenses and
corresponding-source inventory remain unchanged.

## Acceptance

The live instruction matrix captures a digest in one patched-QEMU process and
successfully reuses it in a fresh process for both single and composed x86-64
and AArch64 result transforms. Its explicit mismatch case remains suppressed,
the naturally faulting load proves install-before-fault retry semantics, the
full 4,096-slot event queue is saturated using a minimum-size bare-metal guest,
and stock QEMU remains unable to load the fault plugin. The patch microtest is
`checks.crucible.phase2.gates.patchMicrotests` and records `T-QEMU-0082`.
