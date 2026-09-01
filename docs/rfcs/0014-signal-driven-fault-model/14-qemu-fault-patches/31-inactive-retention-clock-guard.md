# Patch 0080: inactive retention clock guard

## Responsibility

`0080-crucible-inactive-retention-clock-guard.patch` prevents the node-memory
retention boundary from reading QEMU virtual time when no memory fault rule is
active. The boundary callback runs for every node boundary, including the first
boundary after a checkpoint is loaded into a fresh QEMU process. During that
restore transition, QEMU may use a negative signed virtual-time value as an
internal sentinel until precise-icount execution is re-established. That value
is not a valid unsigned fault-model coordinate.

An inactive retention subsystem has no deadline to evaluate and no event to
emit. Sampling its clock before the active-rule check is therefore both
unnecessary and incorrect. The patch zero-initializes the local boundary-count
record, returns through the existing inactive-rule guard, and samples
`node_virtual_now()` only after that guard admits real retention work.

## Ordering invariant

The node-boundary sequence is:

1. reject phases other than `CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY`;
2. reject a boundary while memory matches are already in use;
3. reject the boundary when
   `qemu_crucible_fault_memory_rules_active()` is false;
4. sample the virtual clock; and
5. count and apply due retention events.

Steps 1 through 3 perform no clock read and mutate no fault state. When a rule
is active, steps 4 and 5 preserve the existing timestamp, deadline, event, and
counter semantics exactly.

## Failure prevented

The authenticated VMState test checkpoints a pending node-boundary command,
destroys the original QEMU process, restores into a new paused process, and
continues to the command coordinate. It deliberately installs no memory fault
rule. Before this patch, the generic node boundary entered
`node_memory_retention_boundary()`, evaluated `node_virtual_now()` while
constructing a local initializer, and aborted on the restore-time signed clock
sentinel before the inactive-rule guard could return.

The failure was deterministic and looked like a command-continuation failure,
but the command and its restored reservation were intact. The first faulty
operation was the irrelevant memory-retention clock read.

## Verification

The per-patch microtest requires all three properties in the isolated diff:

- the boundary-count record is safely zero-initialized;
- the active-memory-rule guard remains fail-closed; and
- `count.now = node_virtual_now()` follows that guard.

The same microtest then runs the real patched QEMU fresh-process snapshot
round trip. It requires the restored pending command to apply exactly once at
its original icount, requires its canonical result to be emitted once, and
requires QEMU to stop again after the continuation proof. The test also checks
that a corrupted authenticated fault envelope is rejected and that stock QEMU
does not emit Crucible VMState.

Existing live memory-retention tests provide the positive control: active
retention rules still sample virtual time, schedule deadlines, mutate selected
cells, and emit their bounded evidence.

## Boundary and licensing

The change is confined to `plugins/crucible-fault-node.c` in the QEMU/GPL
process. It changes no shared-memory layout, command ABI, result ABI, callback
surface, or Apache host code. The corresponding source is retained as a
separate DCO-signed commit in the QEMU patch bundle.
