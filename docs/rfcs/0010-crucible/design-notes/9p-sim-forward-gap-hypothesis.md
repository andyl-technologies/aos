# 9p-under-sim forward gap diagnosis

Status: CONFIRMED by diagnostic QEMU builds and closed at the QEMU dispatch and
plugin-contract layers in the atomic QEMU integration artifact.

## Observed failure

The same diskless Linux guest that mounted 9p under plain TCG produced no 9p
frames under the sim and plugin harness. The plugin registered its 9p callbacks,
block I/O continued to forward through the same plugin, and the guest kept
executing. Neither the Crucible forwarding branch nor the stock synth branch of
`handle_9p_output` ran, which localized the gap to virtqueue kick dispatch.

The queue's host notifier remained enabled under sim. Its kick therefore waited
for asynchronous main-loop dispatch while the sim accelerator owned virtual
time on the vCPU thread. That scheduling gap prevented the request from ever
reaching the deterministic 9p sub-node.

## Resolution

The atomic patch handles the actual dispatch point in `virtio_queue_notify`.
For sim plus icount plus `VIRTIO_ID_9P`, QEMU bypasses the host notifier and
invokes the queue handler inline. The request is observed at the exact icount
where the guest issued it, after which the existing 9p shared-memory delivery
and device-wait boundary owns completion.

Block, rng, plain-TCG 9p, and sim-without-icount 9p retain their intended
dispatch behavior. In particular, block remains governed by its measured
idle-preservation contract: broad synchronous dispatch reduced the number of
operations that reached guest HLT and violated the S2 idle evidence. The 9p
scope corrects a path that never reached its sub-node and does not alter that
block behavior.

## Evidence

`checks.crucible.phase2.qemu9pSyncKick` proves the exact source-level dispatch
scope. `checks.crucible.phase2.qemuPluginNinePIo` proves the paired bounded ring,
callback, backpressure, and whole-burst device-hold contract. The atomic patch
microtests bind those checks to the reconstructed artifact and retain negative
controls for block, rng, plain TCG, and sim without icount.

The current focused gates do not claim a real Linux `Tversion` flight. That
production flight must authenticate request delivery, completion icount,
whole-burst freeze and release, delayed publication under host preemption, and
later guest progress together.
