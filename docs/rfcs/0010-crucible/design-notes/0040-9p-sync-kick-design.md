# 0040 crucible-9p-sync-kick — IMPLEMENTED, LIVE VALIDATION PENDING

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

Patch 0040 extends `virtio_pci_ioeventfd_enabled` to return false for
`VIRTIO_ID_9P` when both icount and the sim accelerator are active. QEMU then
handles the kick synchronously on the requesting vCPU thread and immediately
enters the existing raw-message submit/poll callbacks.

This is deliberately narrower than globally disabling ioeventfd:

- virtio-rng keeps the synchronous rule introduced by patch 0032;
- virtio-9p gains synchronous *initial dispatch*, while its completion remains
  an exact event owned by the deterministic 9p sub-node;
- virtio-blk retains asynchronous dispatch because patch 0039 supplies its
  coroutine/device-wait completion barrier;
- plain TCG, sim without icount, and every other virtio device retain the
  upstream predicate.

## Required evidence

`checks.crucible.phase2.gates.patchMicrotests` reconstructs the prefix through
patch 0039 and executes the exact ioeventfd predicate before and after patch
0040. It must distinguish sim-mode icount 9p while proving the rng, block,
plain-TCG, and sim-without-icount cases unchanged.

The standalone `checks.crucible.phase2.qemu9pSyncKick` realization passes on the
Linux builder, including a complete build of QEMU from the 40-patch bundle and
all exact-source controls above.

`checks.crucible.phase2.qemuLive9pIo` must then prove the end-to-end boundary:

1. a real mounting guest publishes nonzero request frames to `SLOT_9P_IO`;
2. the host sub-node publishes and delivers a future completion horizon;
3. the guest progresses to its scheduler ceiling;
4. a second run under host load reproduces the same icount-domain observations;
5. delaying the due response's physical ring write changes only wall time.

Only after both gates pass may `T-PLUG-13` be marked complete.
