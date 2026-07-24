# 9p-under-sim forward gap — confirmed diagnosis and resolution

Status: CONFIRMED by diagnostic QEMU builds and closed by patch 0040 plus the
live `SLOT_9P_IO` certification gate. The original hypothesis is retained below
as investigation history.

## Resolution

The diagnostic build showed that changing
`virtio_pci_ioeventfd_enabled` did not affect this queue:
`virtio_queue_notify` still observed `VIRTIO_ID_9P` with
`host_notifier_enabled = true`. Patch 0040 therefore applies at the actual
dispatch point. It bypasses the host notifier only for
sim+icount+`VIRTIO_ID_9P` and invokes the queue handler inline. Block, rng,
plain TCG 9p, and sim-without-icount 9p retain their prior dispatch behavior.

The exact-source `checks.crucible.phase2.qemu9pSyncKick` microtest proves that
scope. `checks.crucible.phase2.qemuLive9pIo` then proves a real Linux
`Tversion` crosses `SLOT_9P_IO`, completes with the same 821-icount modeled
latency under host load and a 100 ms response-publication delay, releases the
device hold, and lets the guest reach its scheduler ceiling. All temporary
diagnostic logging was removed.

## Historical investigation

## 1. Observed (live, builder-hil1-87eb5b00)

The same diskless guest (a `linuxWith` 9p=y kernel + a tiny `mount -t 9p crucible`
initrd) that mounts 9p under plain tcg (QEMU emits its `msize` degraded-perf
warning; `9pnet`/`v9fs` install) produces, under the sim+plugin harness:

- `frames_processed = 0` on `SLOT_9P_IO` (the request never reaches the host servicer),
- ZERO plugin 9p callbacks (`ninep_burst_start`/`ninep_submit` file-traced, never fire),
- ZERO `msize` on QEMU stderr (the request never reaches the stock synth backend either),
- the guest still boots and idle-jumps to the ceiling (not a boot hang).

The plugin registers 9p correctly: `qemu_plugin_register_9p_cb` runs
(`REGISTER_NINEP calling`+`returned` traced, same install path as the working
`REGISTER_BLOCK`). BLOCK I/O forwards fine under sim with the identical plugin
(`BLOCK_SUBMIT` fires, `frames_processed=1`) — so it is not the Rust side and not a
general sim/plugin fault; it is specific to the stock virtio-9p device under sim.

## 2. Both 9p code paths live in one handler that isn't running

`hw/9pfs/virtio-9p-device.c :: handle_9p_output()` is the virtio-9p virtqueue
handler (registered by patch 0019 realize: `virtio_add_queue(vdev, MAX_REQ,
handle_9p_output)`). Patch 0019 makes it branch on
`crucible_9p_callbacks_ready()` (patch 0018 = all four cb pointers non-NULL, set by
`qemu_plugin_register_9p_cb`):

- callbacks ready → `virtio_9p_forward_crucible()` → `crucible_9p_submit_cb()` (writes SLOT_9P_IO)
- callbacks not ready → `pdu_submit()` (stock synth server → the `msize` warning)

Since register_9p_cb ran, `crucible_9p_callbacks_ready()` is true, so a running
`handle_9p_output` would take the forward branch and the servicer would see the
frame. It sees nothing AND there is no `msize`. **Neither branch executes ⇒
`handle_9p_output` is never entered for the guest's mount kick.**

## 3. The seam: patch 0032 leaves virtio-9p on async ioeventfd under sim

`0032-crucible-det-virtio-ioeventfd.patch` → `hw/virtio/virtio-pci.c ::
virtio_pci_ioeventfd_enabled()` (patched lines 37-43):

```c
if (icount_enabled() && strcmp(current_accel_name(), "sim") == 0) {
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    if (vdev != NULL && vdev->device_id == VIRTIO_ID_RNG) {
        return false;   // rng: kick serviced SYNCHRONOUSLY on the vCPU thread
    }
}
return (proxy->flags & VIRTIO_PCI_FLAG_USE_IOEVENTFD) != 0;  // blk/9p: stays async
```

Its own comment states the design assumption verbatim: *"virtio-blk/9p completions
are already pinned by the crucible blk/9p shmem substrate (patches 0015-0019),
which is built assuming the stock async kick dispatch. Forcing those devices
synchronous here would double-synchronize a kick path they rely on being async..."*

So under sim, virtio-9p keeps ioeventfd ENABLED: the guest's vring kick is posted to
an `EventNotifier` and dispatched **asynchronously on the main-loop AioContext**
(`virtio_queue_host_notifier_read` → `handle_9p_output`), NOT on the vCPU thread.

**This "stock async kick dispatch works under sim" assumption was validated for
virtio-blk (block forwards) but is UNVALIDATED for virtio-9p, and the live evidence
falsifies it for 9p.** Under sim the plugin owns virtual time and the vCPU thread
holds the BQL through the quantum (the T-PLUG-7 main-loop-starvation class); the 9p
kick's async main-loop dispatch never gets serviced, so `handle_9p_output` never
runs.

## 4. Why block differs from 9p (the one piece still needing a C-probe)

Not yet pinned by reading alone. Leading explanation, consistent with all data:
- block's forwarding kick lands at icount ~0 (the virtio-blk partition probe fires
  at device realize / very early boot — block_node_gate measured
  `first_request_icount=0`), when the main loop still cycles during bring-up;
- the 9p kick lands only when userspace runs `mount` (~16M+ icount, mid-quantum),
  by which point the plugin owns time and the main loop is starved.

i.e. block may share the same latent async-dispatch fragility but happens to kick
early enough to be serviced. Confirming this needs a diagnostic QEMU build with a
one-line `fprintf` at the top of `handle_9p_output` and `virtio_blk_handle_output`
plus the ioeventfd read callback — established fast-loop pattern, but a local build,
so flagged for the window rather than done now.

## 5. Fix direction (window, SECOND after 0039)

Primary candidate, minimal and mirroring the existing rng carve-out: extend the
sim ioeventfd-disable in `virtio_pci_ioeventfd_enabled` (patch 0032) to also cover
`VIRTIO_ID_9P`, so the 9p kick is serviced synchronously on the requesting vCPU
thread at a deterministic icount — exactly as done for virtio-rng. Then
`handle_9p_output` runs inline on the mount, `crucible_9p_submit_cb` fires, the op
reaches SLOT_9P_IO, and 0039's device-wait/delivery-resume mechanism advances the
halted guest past the completion. The two patches validate together in the same
window (this fix makes the op reach the plugin; 0039 makes the guest advance to it).

Open question for the patch author: 0032's comment claims blk/9p "rely on being
async" and that syncing them would "perturb their throttled-IO idle timing." The 9p
live evidence contradicts the async assumption; whether block should ALSO move to
sync (if §4 shows its async path is only incidentally working) is the design fork to
settle with a C-probe before touching the series. If block genuinely needs async
while 9p needs sync, understand why before diverging them.

## 5b. Fix shape CONSTRAINED by the S6 seal (main ruling, [[rfc-0010-s6-virtio-rng-delivery-seal]])

Recorded campaign history on this exact seam constrains the fix:
- **NEW patch `0040-crucible-sim-9p-sync-kick` (or similar) — do NOT edit 0032.**
  Reasons: one-concern-per-patch drop-one attribution; the S6 seal's language
  pins 0032 as rng-scoped; and 0032's `detVirtioIoeventfd` microtest may assert
  its rng-scoped shape (CHECK — an edit would red it).
- **Block STAYS async (do NOT extend the sync carve-out to virtio-blk).** The S6
  seal ruled 0032 rng-scoped for a MEASURED reason: a broad ioeventfd disable
  REGRESSED `s2HltBusyPoll` — synchronous virtio-blk dispatch let ~2 throttled
  reads complete inside the iops burst budget without the guest HLT-idling
  (`block_idled_operations` 32→30). So "should block also move to sync" has a
  recorded answer: NO, unless a later C-probe proves the async fragility bites
  block too AND s2HltBusyPoll is re-validated.
- **Cite the seal in the patch header:** the seal EXCLUDED 9p on the assumption
  "blk/9p completions are pinned by the crucible shmem substrate, which assumes
  the stock async kick" — the 9p live evidence FALSIFIES that premise (the op
  never reaches the substrate). Extending the sync carve-out to `VIRTIO_ID_9P`
  is consistent with the seal's LOGIC while correcting its factual premise; the
  seal's S2 regression was blk-specific, and 9p sync dispatch is required for the
  op to reach the substrate at all.
- **VALIDATION SET (must all pass together in the window):** the 9p progress
  proof (0040 makes the op reach SLOT_9P_IO; then 0039 advances the halted guest)
  PLUS no-regression on `s2HltBusyPoll` (blk-side) and the S6 gates
  `s6KaslrAslr`, `detRngDelivery`, `detVirtioIoeventfd`.
- **Window queue:** 0039 → 0040 (9p sync-kick), validated together with s2/s6.

## 6. Determinism note

Making the 9p kick synchronous is determinism-improving, not -harming: the kick is
then serviced at the exact icount the guest issued it (on the vCPU thread), rather
than at a main-loop-scheduling-dependent icount. This is the same argument patch
0032 already makes for virtio-rng. Classification if it lands: determinism-critical,
gate:qemu-inert + gate:layer0-determinism + the 9p node harness as micro-test.
