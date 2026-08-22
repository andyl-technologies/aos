# Patch 0109: dispatch exact control-boundary node faults

Patch `0109-crucible-control-boundary-node-faults.patch` closes the halted-node
command deadlock in the production QEMU mutation path.

## Problem

The host publishes a typed node-fault command and rings the shared control
doorbell without authorizing guest progress. A running guest reaches another
node-boundary dispatch naturally, but a halted guest returns through QEMU's
drained control callback. Before this patch that callback let the plugin enqueue
the command only after the existing node-boundary dispatcher had run. The host
then waited for a result while correctly refusing to advance the guest, leaving
the command permanently pending.

## Contract

QEMU samples the raw retired-instruction coordinate once for the control
callback. After the plugin returns, QEMU checks specifically for due
node-boundary commands at or before that coordinate. If one exists, it runs the
normal node-boundary dispatcher before leaving the exact-boundary scope.

The phase-qualified pending check is mandatory. A device- or instruction-phase
command must remain owned by its actual phase seam and cannot be made executable
merely by an unrelated control wake.

PREPARE and APPLY therefore use the same production handler, validation,
evidence, and result queues as running-node execution. The control callback does
not fabricate a result and does not advance virtual time or retired
instructions. A later control wake lets the plugin transfer QEMU's completed
result into the lossless shared-memory result ring.

Lifecycle evidence embeds QEMU's raw retired-instruction coordinate, while the
plugin publishes scheduler-logical coordinates. Terminal QMP authorization
therefore hashes the fixed CRUCLIF evidence after zeroing that one coordinate
field on both sides. The separately authenticated action and event header bind
the exact logical coordinate; this normalization keeps fresh-process offsets
from changing the terminal authorization identity.

## Evidence

The shared-cause live gate drives a real two-node QEMU world to an exact virtual
event while the target guest is halted, applies a production lifecycle mutation,
and requires both the primary execution and a fresh-process restore to produce
the same mutation and storage consequences. The plugin regression separately
requires every drained control callback to pump commands before release-
acknowledging its host token.
