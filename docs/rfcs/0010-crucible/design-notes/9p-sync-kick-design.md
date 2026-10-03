# Atomic 9p sync-kick design

## Problem

The `crucible-9p-shmem` transport deterministically models a request after
QEMU enters `handle_9p_output`, but the guest's initial virtqueue kick used
ioeventfd. Under the sim accelerator the vCPU could run beyond that kick while
main-loop dispatch remained pending. A mounting guest then blocked without
ever publishing a request to `SLOT_9P_IO`.

The TCG control leg proved the guest issued a real 9p operation, while the sim
leg consistently observed zero forwarded frames. The missing boundary was
therefore QEMU's kick dispatch, not the guest workload or 9p message model.

## Selected mechanism

The atomic QEMU integration handles the boundary at `virtio_queue_notify`.
When icount and the sim accelerator are active and the device is
`VIRTIO_ID_9P`, QEMU bypasses the host notifier and invokes the queue handler
inline. QEMU therefore enters the existing raw-message submit and poll
callbacks on the requesting vCPU thread.

This scope is narrower than globally disabling ioeventfd:

- virtio-rng keeps its synchronous deterministic-delivery rule;
- virtio-9p gains synchronous initial dispatch, while completion remains an
  exact event owned by the deterministic 9p sub-node;
- each launched `crucible-shmem` virtio-blk device independently sets
  `ioeventfd=off`, while its coroutine and device-wait completion barrier
  preserves the measured block-idle behavior;
- plain TCG, sim without icount, and every other virtio device retain the
  upstream predicate.

## Required evidence

`checks.crucible.phase2.gates.patchMicrotests` reconstructs the atomic artifact
and exercises the exact `virtio_queue_notify` implementation. Its negative
controls prove that rng, block, plain-TCG, and sim-without-icount dispatch keep
their intended behavior.

The standalone `checks.crucible.phase2.qemu9pSyncKick` realization validates
the source-level dispatch cases. `checks.crucible.phase2.qemuPluginNinePIo`
supplies the matching host/plugin contract evidence: bounded request and
response rings, exact delivery coordinates, backpressure, and a device-I/O
hold that spans the whole burst.

These focused gates cover the component contracts but do not complete
`T-PLUG-13`. A loaded Linux guest must still authenticate `Tversion`, the
completion icount, the whole-burst freeze and release, delayed publication
under host preemption, and later guest progress in one production flight.
