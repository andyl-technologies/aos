# Patch 0071 — `crucible-lifecycle-precondition`

Patch `0071` makes terminal node lifecycle impulses use the same live VM-state
digest during prepare and commit. It is required because lifecycle transitions
observe and mutate RAM, device state, virtual time, and process state rather
than only the persistent-rule registry.

## Problem and invariant

The generic typed-command prepare path computes a digest of the installed rule
registry. A lifecycle impulse, however, returns evidence whose `before_sha256`
is computed from live guest RAM and serialized non-RAM device state. Using the
registry digest as the command precondition makes a valid prepare and a valid
apply disagree even when no intervening execution occurred.

For `NODE_LIFECYCLE` with operation `APPLY`, QEMU must therefore:

1. stop at the requested node boundary;
2. compute the lifecycle snapshot digest from guest RAM and volatile/device
   VMState;
3. return that digest as both halves of the prepare-only evidence;
4. require the apply command's expected precondition to equal a newly computed
   lifecycle snapshot digest at the same frozen boundary;
5. execute the transition only after that comparison succeeds; and
6. retain the same digest as the transition occurrence's before-state.

Every other typed command keeps its existing command-specific precondition.
The patch must not weaken, skip, or special-case the host's two-phase commit
validation.

## QEMU changes

The patch exports the GPL-side helper
`qemu_crucible_fault_lifecycle_precondition()` in the tracked
[`0071` patch](../../../../pkgs/emulation/qemu-patches/0071-crucible-lifecycle-precondition.patch).
The helper accepts only a lifecycle impulse, computes the existing lifecycle
snapshot, and fails with `-EINVAL` or `-EIO` for an invalid request or snapshot
failure. The lifecycle digest deliberately excludes Crucible's control-domain
VMState: command sequence and result bookkeeping advance between prepare and
apply, so including that transport state would make every valid two-phase
command invalidate its own precondition. The aggregate fault VMState and system
identity independently authenticate the control domain; excluding it here does
not remove it from compatibility or replay identity.

`plugins/crucible-fault-node.c` invokes the helper before the generic expected
precondition comparison. Snapshot failure produces `INTERNAL_ERROR`; it never
falls back to a rule-registry digest. The implementation reuses
`crucible_lifecycle_snapshot()` so prepare, apply, and terminal occurrence
evidence cannot drift into separate digest algorithms.

## Required proofs

- The per-patch microtest requires the helper, lifecycle specialization, and
  fail-closed error status.
- Patch-prefix attribution proves the helper first appears with patch `0071`.
- Patch regeneration proves the committed bytes, tree, DCO, and tracked bundle.
- The live signal-driven lifecycle gate issues prepare and apply through the
  production host runtime, authenticates QEMU's occurrence event, authorizes
  the exact child generation, and observes exit status `70`.
- The same gate performs a separate real-QEMU transaction, advances the guest
  after `PREPARE`, submits `APPLY` at the new boundary with the old VM-state
  digest, requires `PRECONDITION_MISMATCH`, proves the process remains live,
  and only then runs the canonical signal-driven crash transaction.
- Before either proof, a discovery process is shut down and a separately
  launched process must reproduce its register, interrupt, hardware-error,
  clock, accelerator, and derived capability manifests exactly. It must also
  reproduce the complete system manifest: QEMU build ID, ordered patch-series
  hash, generated shared-memory-header hash, VMState format version, section
  count, and section-name/version digest. The exact-replay constructor rejects
  a requirement missing any mandatory binding, so a caller cannot enable
  discovery bypass with a discovery-only requirement.

The patch modifies only QEMU/GPL-side files and crosses the Apache host boundary
through the existing versioned shared-memory command, result, and event
protocols.
