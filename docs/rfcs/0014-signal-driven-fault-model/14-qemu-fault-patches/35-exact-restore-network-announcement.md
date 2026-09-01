# Patch 0084: suppress migration announcements on exact restore

## Capability

An exact Crucible checkpoint restore returns a node to the same modeled
network, including the authenticated link state, queued frames, and every
producer and consumer cursor. The restore must therefore resume with the next
guest-originated frame that uninterrupted execution would have produced. It
must not synthesize migration traffic merely because the VMState was loaded in
a fresh QEMU process.

Ordinary QEMU migration has a different contract: the guest may have moved to
a new physical network attachment, so upstream virtio-net behavior requests a
guest announcement after load. This patch preserves that behavior outside an
active Crucible exact-load transaction.

## Failure closed by this patch

Upstream `virtio_net_post_load_device()` unconditionally resets and arms the
guest-announcement timer when the guest negotiated `VIRTIO_NET_F_GUEST_ANNOUNCE`
and `VIRTIO_NET_F_CTRL_VQ`. During exact restore, Linux responds to that
synthetic request by transmitting IPv6 multicast-listener reports. Those
frames do not exist in the uninterrupted execution and each one consumes the
normal link signal, selector, mutation, and evidence decisions. Restoring all
ring cursors is necessary but cannot remove traffic that QEMU creates only on
the restore path.

Treating exact restore as ordinary migration would therefore violate packet
continuation, fault-decision continuation, and replay identity. Disabling
announcements globally would instead change ordinary QEMU migration semantics.
The distinction must be made inside QEMU while the central VMState load
transaction is active; it is not a host-side heuristic and does not cross the
process boundary.

## QEMU changes

`migration/migration.c` exposes a locked query for the existing nested
Crucible-load counter. The query is true only while QEMU is inside the exact
VMState deserialization transaction bracketed by
`migration_crucible_load_begin()` and `migration_crucible_load_end()`.

`hw/net/virtio-net.c` consults that query in the negotiated guest-announcement
post-load path. During exact load it deletes any announcement timer owned by
the newly restored device and sets its remaining round count to zero. Outside
exact load, the original reset, immediate arm, and empty-schedule cleanup run
unchanged.

On the host side, exact restore accepts QEMU's successful `cont` reply before
publishing the next scheduler ceiling. It deliberately does not issue an
immediate `query-status`: an idle simulator can park on the restored plugin
barrier before servicing that query, while the host cannot publish the ceiling
until node assembly returns. The first bounded node step proves execution after
the ceiling is published. Ordinary typed QMP `cont` remains available for
callers that can safely perform an immediate status probe.

The change adds no process ABI, shared-memory field, VMState version, QAPI
command, or new QEMU file. It modifies existing GPL-scope QEMU implementation
and internal-header files and does not change the corresponding-source license
inventory.

## Acceptance

The production live-network gate is the regression test. It boots two real x86
QEMU nodes, establishes bidirectional traffic, captures an exact checkpoint,
and records the uninterrupted packet and fault-decision continuation. It then
terminates the original processes, restores both nodes into fresh processes,
and requires byte-for-byte equivalent output sequencing and identical link
decision consumption. In particular, the first restored quantum must not
contain migration-only multicast-listener reports.

The same gate is a positive control for ordinary guest traffic: suppressing the
announcement must not suppress frames that were pending in the authenticated
transport state or frames the restored guest would naturally transmit. The
aggregate patch-series and regeneration gates additionally require the
isolated patch to apply at the recorded stack position, the DCO-signed branch
commit and tree to match `_series.nix`, and the corresponding-source bundle to
regenerate byte-for-byte. The implementation task is `T-QEMU-0084`.
