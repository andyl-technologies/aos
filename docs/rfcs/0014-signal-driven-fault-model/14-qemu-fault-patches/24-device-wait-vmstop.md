# Patch 0073 - `crucible-device-wait-vmstop`

Patch `0073` admits an exact checkpoint stop requested from a device-completion
callback without blocking that callback or allowing the guest to execute past
the requested coordinate.

## Required behavior

Device completions can publish fault results or occurrence evidence while QEMU
is servicing its main-loop callback path. That path cannot synchronously wait
for the plugin control thread: doing so would deadlock the very loop that must
finish the stop. The patch therefore records a bounded pending stop request,
wakes the main loop, and transitions through QEMU's native paused runstate only
after the current callback and its event publication have drained.

The admission path is idempotent. Multiple requests for the same boundary
coalesce; an earlier request cannot be replaced by a later coordinate; and a
request after terminal fault state is rejected. No guest vCPU, device timer,
bottom half, or DMA completion may run between the admitted stop coordinate and
the paused-state acknowledgement.

## State and failure contract

The pending stop marker is process-local control state, not guest VMState. A
checkpoint is legal only after the marker has been consumed and QEMU reports
the native paused runstate. Restore begins paused and recreates no synthetic
callback. Queue exhaustion, an invalid runstate transition, or a callback that
cannot drain enters terminal fault state and produces authenticated terminal
evidence; it never resumes execution as a fallback.

## Required proofs

- A live device completion requests a stop and the resulting checkpoint's
  node-icount is exactly the callback boundary.
- The event/result rings are drained before paused-state acknowledgement.
- Repeated admission is idempotent and a later coordinate cannot supersede an
  earlier pending stop.
- Removing patch `0073` makes the live device-boundary checkpoint gate fail.
- Patch regeneration verifies its commit, tree, DCO, catalog row, and thin
  corresponding-source bundle.

The change remains entirely within QEMU and its GPL-side plugin. It adds no
process-boundary field or host callback.
