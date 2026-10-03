# Device-completion advance capability

Status: IMPLEMENTED AND LIVE-CERTIFIED in the atomic QEMU patch.

## Deterministic completion boundary

Crucible block requests publish a device-I/O hold and their request coordinate
before the submitting vCPU leaves its current TCG reservation. The host derives
the completion deadline from that coordinate and modeled latency, then
release-publishes the earliest outstanding deadline through
`NodeSlot.device_completion_deadline_icount` and signals the node wake fd.

When a block poll reports `PENDING`, the QEMU driver invokes the registered
block-wait callback and yields through its ordinary `CoQueue`. The plugin queues
an advance to the published deadline. QEMU commits logical time while the
RR-thread ordering barrier remains armed, clears that barrier, wakes the device
waiters, and kicks the vCPU. If the host response is not physically present,
the coroutine parks and retries at the same logical icount. Host timing can
therefore affect only how long QEMU waits, never the guest-visible delivery
coordinate.

The driver performs no independent icount-to-nanosecond conversion. The plugin
uses the same virtual-time mapping that produced the host deadline, avoiding a
second rounding domain. The shared slot always carries the minimum deadline of
the in-flight requests; each poll republishes the next earliest deadline after
a completion.

## Admission and inertness

The callback is registered only for an active Crucible sim-mode session. With
no registration, the QEMU callback pointer is null and ordinary QEMU devices
and launch profiles do not enter this path. The completion notifier reuses the
existing queued-advance barrier and wake fd; it creates no independent timer or
polling mechanism.

## Verification

`checks.crucible.phase2.qemuDeviceCompletionAdvance` validates the capability
against the authoritative atomic artifact. It reconstructs the exact commit,
checks the stock-QEMU negative surface, and verifies the pending-poll callback
and post-commit waiter resume in source.

The live leg performs a positive-latency guest block read through the mapped
shared-memory ring and records one processed and delivered frame, progress past
the block operation, and advancement to the scheduler ceiling. A delayed-host
leg produces the same guest-visible projection as the fast run, while a
deadline-publication race still wakes, retries, and completes. The QEMU
inertness and Layer-0 determinism gates cover the unregistered path and the
guest-visible ordering contract.
