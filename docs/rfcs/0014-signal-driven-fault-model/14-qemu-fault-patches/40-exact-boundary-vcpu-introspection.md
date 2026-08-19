# 0089 - Exact-boundary vCPU introspection

## Purpose

Exact checkpoint capture can run from QEMU's main-loop control callback after
the running vCPU has returned to the BQL. At that point every vCPU register file
and the serialized RR owner and cursor are committed and stable, but
`current_cpu` is intentionally absent. The live-instruction introspection
contract introduced by patch `0077` rejects that context, causing otherwise
valid checkpoint fingerprint capture to fail.

Patch `0089` admits authoritative all-vCPU register files and the committed RR
cursor at an exact deterministic plugin boundary. It does not add fallback
state and does not weaken arbitrary-context rejection.

## Admission contract

`qemu_plugin_read_vcpu_regs()` selects one of three closed read contexts:

1. During active serialized RR execution, `current_cpu` must match the
   authoritative RR owner and QEMU's exact-boundary scope must be active.
2. During an exact main-loop control callback, no vCPU is current, the BQL must
   be held, and QEMU's exact-boundary scope must be active.
3. During terminal state capture, the VM must be non-running and the BQL must
   be held.

`qemu_plugin_rr_cursor()` similarly admits the active serialized RR owner or an
exact deterministic boundary. At the main-loop boundary it reads the committed
cursor in `TimersState` instead of an in-flight current-vCPU observation.

Both cursor paths still require a nonzero pinned RR quantum, an in-range owner,
and a cursor strictly inside the quantum. Every register or cursor caller
outside the listed contexts is rejected. The exact-boundary scope is QEMU-owned
thread-local state entered and left around deterministic plugin callbacks; it
is not asserted by the plugin or transported across the process boundary.

## Checkpoint semantics

The control callback holds the BQL and runs after the preceding TCG slice has
committed icount, all register changes, and RR accounting. Reading every vCPU
and `TimersState` therefore samples one quiescent coordinate and the same cursor
that VMState serializes. The resulting fingerprint is valid for uninterrupted
execution and fresh-process restore; it never depends on a stale
`current_cpu` pointer.

## Files and license scope

The patch modifies `plugins/api.c` and `include/qemu/qemu-plugin.h`, preserving
their existing licenses. It creates no QEMU source file and changes no Unix
socket or shared-memory protocol.

## Required gates

1. Exercise production two-VM World networking through an exact checkpoint,
   fresh-process restore, and next-quantum comparison with fingerprinting on.
2. Require the checkpoint control callback to publish complete all-vCPU
   registers and an RR cursor, then acknowledge native pause within its bound.
3. Run the four-vCPU exact-horizon fingerprint workload twice and require all
   live-instruction register and cursor samples to remain valid and identical.
4. Prove plugin-install or other unowned register and cursor reads still return
   nonzero rejection statuses.
5. Rebuild every patch prefix and pass regeneration, ABI, license, inertness,
   and corresponding-source gates.

- **[QFP-INTROSPECT-BOUNDARY-1]** An exact deterministic main-loop boundary
  holding the BQL MUST read all quiescent vCPU register files and the committed
  serialized RR cursor without requiring `current_cpu`.
- **[QFP-INTROSPECT-BOUNDARY-2]** Every context outside the active RR owner,
  exact BQL-held control boundary, and stopped BQL-held terminal boundary MUST
  remain rejected.
