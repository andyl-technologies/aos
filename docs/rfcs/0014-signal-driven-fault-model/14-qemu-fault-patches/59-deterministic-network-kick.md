# Patch 0108: preserve deterministic virtio-net continuation

## Capability

The Crucible sim accelerator observes each guest-transmitted network frame at
the guest instruction count that kicks the virtio-net transmit queue. A cold
VMState restore therefore produces the same frame bytes, producer sequence,
emit coordinate, link decisions, and delivery coordinate as uninterrupted
execution.

## Failure closed by this patch

Upstream virtio PCI may route a queue notification through ioeventfd and a host
main-loop notifier. The ordinary virtio-net kick handler then schedules a
second host-dispatched TX bottom half. That bottom half can combine a different
number of guest descriptors after a cold restore, even when the kick itself is
handled inline. The migratable `tx_waiting` flag does not include whether that
bottom half is scheduled: stopping for a snapshot cancels it, and resuming
normally schedules it through the host main loop again. The frame bytes and
link RNG stream remain equal while the modeled emit and delivery coordinates
diverge. Direct translation-block chains and blocks shortened by their initial
icount budget are also process-local execution-history state. Finally, upstream
VMState deliberately invalidates the virtqueue's `signalled_used` notification
cursor on load. The first completed TX after restore consequently raises an
extra guest interrupt even when the uninterrupted queue would suppress it,
moving every later system call by the interrupt handler's instruction cost.

Treating this as equivalent would make packet continuation host-timing
dependent. Quantizing the frame later on the Apache host would also violate the
QEMU/plugin contract that the outbound ring carries the guest's transmit
instruction count.

## QEMU changes

For `-accel sim` with icount enabled, virtio PCI disables ioeventfd for
virtio-net in addition to the already deterministic RNG and block devices. The
generic virtio notification path dispatches network kicks through the ordinary
inline device handler, alongside the existing 9p and block exceptions. In sim
mode, virtio-net drains the TX bottom-half work synchronously from that handler,
including every full burst, instead of returning it to the host main loop. It
also drains a serialized `tx_waiting` queue synchronously when VMState resume
marks the queue runnable, and applies the same rule to asynchronous completion
bursts. QEMU commits the raw icount once at that synchronous device boundary
and supplies it as an argument to the registered Crucible network-TX callback.
The plugin adds its restored logical-time offset without re-sampling QEMU, then
retains the existing frame and sequence handling. After a successful sim-mode
snapshot, QEMU marks the source continuation for canonical TB dispatch; loading
the serialized RR cursor marks the restored continuation the same way. Before
either VM resumes, both the successful save path and successful load path flush
their translation caches symmetrically. Both continuations then disable direct
TB chaining and limit each translated block to 32 instructions, while
preserving any smaller scheduler budget. They therefore return to the
deterministic interrupt check at cache-independent boundaries. Demand
translation and lookup caching remain enabled after the checkpoint, so the
bounded policy excludes process-local block shape and chain topology without
forcing one-instruction execution. An optional sim-only VMState subsection also
serializes `signalled_used` and `signalled_used_valid` for every virtqueue. The
ordinary load path still resets those cache fields for all other accelerators;
an exact Crucible restore instead retains the source queue's precise interrupt
suppression state.

These policies are inert for every non-sim accelerator. They add no QEMU file,
shared-memory field, or incompatible base VMState version; the new optional
subsection is emitted only by sim-mode RR execution. They evolve the GPL-side
QEMU plugin callback signature together with the matched plugin and
build-identity handshake; no Apache host code links or calls that interface.
It does not change the corresponding-source license inventory.

## Acceptance

The production two-VM live-network gate captures a durable exact checkpoint,
continues until a guest-generated checkpoint frame consumes fresh link fault
decisions, restores both QEMU processes from the canonical closure, and
requires the entire bounded outcome sequence to match byte for byte. The gate
also requires positive packet and link-decision evidence after the checkpoint;
an unrelated or inert equal quantum cannot pass.

Patch regeneration verifies that this isolated DCO-signed QEMU commit applies
at the recorded stack position and that the corresponding-source bundle and
manifest identities match the complete series.
