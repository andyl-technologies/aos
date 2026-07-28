# 0040 crucible-9p-sync-kick — IMPLEMENTED AND LIVE VALIDATED

## Problem

The `crucible-9p-shmem` transport deterministically models a request after
QEMU enters `handle_9p_output`, but the guest's initial virtqueue kick still
used ioeventfd. Under the sim accelerator the vCPU could run beyond that kick
while main-loop dispatch remained pending. A mounting guest then blocked without
ever publishing a request to `SLOT_9P_IO`.

The TCG control leg proved the guest issued a real 9p operation, while the sim
leg consistently observed zero forwarded frames. The missing boundary was
therefore QEMU's kick dispatch, not the guest workload or 9p message model.

## Selected mechanism

The first implementation extended `virtio_pci_ioeventfd_enabled`, but a
diagnostic build proved that predicate is not consulted for this virtio-9p
queue: its `host_notifier_enabled` bit remains set. The validated patch instead
changes the generic `virtio_queue_notify` dispatch point. When icount and the
sim accelerator are active and the device is `VIRTIO_ID_9P`, it bypasses the
host notifier and invokes the queue handler inline. QEMU therefore enters the
existing raw-message submit/poll callbacks on the requesting vCPU thread.

This is deliberately narrower than globally disabling ioeventfd:

- virtio-rng keeps the synchronous rule introduced by patch 0032;
- virtio-9p gains synchronous *initial dispatch*, while its completion remains
  an exact event owned by the deterministic 9p sub-node;
- each launched `crucible-shmem` virtio-blk device independently sets
  `ioeventfd=off`, making request observation synchronous while patch 0039
  supplies its coroutine/device-wait completion barrier;
- plain TCG, sim without icount, and every other virtio device retain the
  upstream predicate.

## Required evidence

`checks.crucible.phase2.gates.patchMicrotests` reconstructs the prefix through
patch 0039 and executes the exact `virtio_queue_notify` function before and
after patch 0040. It distinguishes sim-mode icount 9p while proving the rng,
block, plain-TCG, and sim-without-icount dispatch cases unchanged.

The standalone `checks.crucible.phase2.qemu9pSyncKick` realization passes on the
Linux builder with the exact-source controls above. The full patched QEMU
package also builds hermetically from source.

`checks.crucible.phase2.qemuLive9pIo` must then prove the end-to-end boundary:

1. a real mounting guest publishes nonzero request frames to `SLOT_9P_IO`;
2. the host sub-node publishes and delivers a future completion horizon;
3. the guest progresses to its scheduler ceiling;
4. a second run under host load reproduces the same modeled completion latency;
5. delaying the due response's physical ring write changes only wall time.

Both gates pass. The live run forwards Linux's `Tversion`, computes an
821-icount completion latency, delays response publication by 100 ms under host
load without changing that latency, releases the device-I/O hold, and reaches
the 3.2-billion-instruction scheduler ceiling. `T-PLUG-13` is complete.
