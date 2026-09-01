# 0039 crucible-blk-device-completion-advance

Status: IMPLEMENTED AND LIVE-CERTIFIED.
Author: m4-cp2.

Implementation resolution: Part A uses the dedicated block-wait callback. For
R1, the driver re-fires that callback on every pending poll after the scheduler
wake fd resumes the coroutine, so a deadline-publish race retries without
guest-visible progress. Part B uses B2: after the callback queues an advance,
the block coroutine yields through QEMU's ordinary `CoQueue`, returning control
to the AioContext main loop so it can drain either the deadline-publication wake
fd or the queued advance and ordering barrier. The completion callback commits
logical time while QEMU's RR-thread pending barrier remains armed; QEMU then
clears that barrier, notifies wake-fd-backed device waiters, and kicks the vCPU.
A response that is still physically absent simply parks and retries at the same
logical icount, satisfying R3 without a second
icount-to-nanosecond conversion in the block driver.

Request observation has a matching deterministic boundary. The launch sets
`ioeventfd=off` only on the `crucible-shmem` virtio-blk device so QEMU invokes
its submit callback synchronously from the requesting vCPU path. The callback
release-publishes the request and device-I/O hold, then forces the current TCG
reservation to exit. Until the host pins a nonzero completion deadline,
`max_advance_icount` clamps to the published request coordinate; afterward it
clamps to that deadline. Host wall time can therefore delay dispatch or
completion, but cannot move the request or delivery coordinate.

## 1. Problem (observed, live)

A guest blocked on crucible-shmem block I/O never makes progress. Root cause is
two coupled QEMU-side gaps that no Rust seam can close (proven by exhausting
servicer-delivery, max_advance, and a block_poll-initiated advance):

1. **Delivery-side gap (0015 driver).** `crucible_shmem_wait_one_poll()` is a
   bare `qemu_coroutine_yield()` with NO scheduled resume. When
   `crucible_blk_poll_cb` returns `PENDING`, the block coroutine suspends and
   nothing ever re-enters it. Even if virtual time advanced, the coroutine would
   not re-poll.
2. **Advance-trigger gap (sim accel).** The model REQUIRES strictly-positive
   latency (SCHED-6/20, crucible-device error.rs:173), so
   `delivery_icount > request_icount` always. The guest must advance virtual
   time from the request to the completion, but it is halted on the I/O. The
   0025 all-vCPU-idle callback does NOT fire in this state (observed:
   IDLE_ENTRY=0) because an outstanding crucible block coroutine keeps the sim
   RR loop from classifying the node as fully idle. So the plugin never gets a
   callback in which to advance time, and `max_advance_icount` is never queried
   (observed: MAXADV=0 during a device-I/O halt vs 78k for a busy guest).

Evidence chain: raw block_io_gate — guest submits 1 read, polls PENDING once,
parks; a plugin-initiated `qemu_plugin_advance_time_ns` from block_poll is
ACCEPTED (enqueue status 0) but never COMPLETES (main-loop starved, guest holds
BQL). Node harness — bring-up stalls at priming (MAXADV=0, VCPU_INIT=0) because
the guest blocks on the probe read before it can be primed off the boot barrier.

## 2. Fix shape (two coupled parts, both inert unless sim-mode + plugin owns time)

### Part A — device-I/O-wait callback (advance trigger)

Add a plugin callback fired when a crucible block poll coroutine is about to
yield on PENDING, so the plugin can advance virtual time to the host-published
completion deadline.

Implemented export (mirrors 0025's
`qemu_plugin_register_vcpu_idle_resume_cb`):

```c
/* Fired from the crucible-shmem block poll loop just before it yields on a
 * PENDING poll. request_id identifies the in-flight request. The plugin
 * responds by advancing virtual time to the host-published device-completion
 * deadline for this node (crucible-shmem NodeSlot.device_completion_deadline_icount,
 * already landed at ABI offset 48). Inert: only fired by the crucible-shmem
 * driver, which only exists in sim mode; NULL cb => classic yield behavior. */
typedef void (*qemu_plugin_blk_wait_cb_t)(unsigned int request_id,
                                           void *userdata);
void qemu_plugin_register_blk_wait_cb(qemu_plugin_blk_wait_cb_t cb, void *userdata);
static inline void qemu_plugin_maybe_fire_blk_wait_cb(unsigned int request_id);
```

Fire site: `crucible_shmem_wait_one_poll()` in block/crucible-shmem.c, BEFORE
`qemu_coroutine_yield()`. Alternative (less new surface): instead of a new
callback, extend 0025's idle classification so the all-idle idle callback also
fires when the only outstanding work is a crucible block coroutine — but that
entangles the well-tested 0025 idle path; a dedicated blk-wait callback is
cleaner and independently inert.

Plugin side (Rust implementation): on the callback, read
`device_completion_deadline_icount` (via PluginShmemOrdering, reader landed) and
enqueue an advance to it — the block_poll probe path I already proved is
ACCEPTED by QEMU. The merge rule from commit 1e9679392 is reused verbatim for
the target: min(completion_deadline, next-timer-deadline), retraction=0 skip,
past-clamp-to-current.

**R1 (REQUIRED, observed as "PROBE skip: no deadline cur=0"): deadline-publish
race + retry.** blk_wait can fire before the host servicer has published the
deadline (the field reads 0). A skip-with-no-retry reproduces today's hang, so
this MUST have a defined retry path. The implemented driver re-fires blk_wait
after every pending re-poll. The host servicer signals the node wake fd after
publishing via `wake_for_device_io_release`; QEMU drains that fd from its main
`AioContext`, resumes the generation-protected `CoQueue`, and the next poll
re-reads `device_completion_deadline_icount`. A 0/retracted read therefore
parks without advancing but cannot become a yield-forever state.
Determinism note for the patch header: this wall-timing race is guest-invisible
and determinism-safe — the guest is frozen at the SAME icount regardless of when
the host publishes, and the deadline VALUE is a deterministic function of the
request icount + modeled latency. Only hang-vs-progress (liveness) is at stake,
never the guest-visible result. Say so explicitly in the header.

### Part B — completion resume at delivery_icount (delivery side)

The yielded block coroutine must be re-entered when virtual time reaches
`delivery_icount`. Two mechanisms were evaluated:

- **B1 (not selected): virtual-clock timer.** In `crucible_shmem_wait_one_poll()`,
  arm a `QEMU_CLOCK_VIRTUAL` timer at the host-published delivery deadline whose
  callback does `aio_co_wake(qemu_coroutine_self())`, then yield. When the
  plugin advances vtime to the deadline (Part A), the timer fires, the coroutine
  resumes, re-polls, the servicer has delivered (poll returns bytes), the block
  request completes, and virtio-blk raises the completion IRQ by its existing
  path (no new IRQ code needed — the vIRQ is virtio-blk's, we only unblock its
  completion). This keeps delivery ordering pinned to the deterministic
  `delivery_icount` the host already computes.
- **B2 (selected): sim-advance-completion hook.** The block-wait callback runs
  before the ordinary coroutine queue wait. The coroutine then yields to the
  AioContext main loop, which can drain the deadline-publish wake fd or execute a
  queued advance. Patch 0039 wakes the coroutine after the plugin completion
  callback commits the logical-time offset and uses the existing wake-notifier
  path rather than introducing a second timer conversion.

**R2 (satisfied by avoiding a driver conversion): single icount<->ns
domain-conversion definition.** The ABI
field `device_completion_deadline_icount` is an ICOUNT; a QEMU_CLOCK_VIRTUAL
timer arms in NS. If the driver's icount->ns conversion rounds even 1ns
differently from the plugin's advance target, the timer deadline and the vtime
the plugin advances to never coincide and the coroutine sleeps forever — the
same 1ns/bias class the warp hunt just closed. Require ONE shared conversion,
identical to the servicer's `vt()` that produced `delivery_icount`:
`delivery_icount = ceil(vt(request_icount) + latency)`, and the timer arms at
`vt_ns(delivery_icount)` using that SAME `vt()` (icount << icount_shift, the
established scale). State the single formula in the patch header and add a
compile-time or startup micro-assert that the driver's conversion and the
plugin's advance-target conversion agree (e.g. both derive ns from
`icount << icount_shift`). No independent rounding on either side. The selected
B2 path keeps this conversion in the Rust plugin's existing queued-advance
implementation; the QEMU block driver never converts the shared-memory icount
deadline.

**R3 (REQUIRED): guest-visible delivery invariant.** A response must become
guest-visible at `delivery_icount`, independent of when its host-side ring write
finishes. The selected implementation permits another internal PENDING poll
after logical time reaches the deadline, but the coroutine immediately parks
again without retiring a guest instruction or advancing virtual time. The
host's next wake re-polls at the same icount, so wall timing changes only how
long QEMU is parked and never the guest-visible completion point. Test: a
deliberately slowed servicer must produce the byte-identical guest-visible
sequence as the fast servicer.

Minor (noted): the single slot field holds `min(next in-flight completions)`
(`next_exact_local_event()`), which is exactly the earliest-due request — correct
for the first in-flight request the guest is blocked on. Multiple concurrent
in-flight requests are handled by re-arming per poll-loop iteration (each
service() republishes the new earliest), so the field is always the next thing
the plugin must advance to. State this in the header.

Resolved (was open question): no QEMU_CLOCK_VIRTUAL timer is armed by the block
driver. The queued-advance completion notifier resumes the ordinary block
`CoQueue` after logical time commits. The live positive-latency block-I/O gate
exercises delivery and the virtio-blk completion path end to end, so no
synchronous-delivery shortcut is part of the evidence.

## 3. Shmem/ABI touchpoints

- `NodeSlot.device_completion_deadline_icount` @ offset 48 — ALREADY LANDED
  (ae1ae1938). Host block servicer publishes `next_exact_local_event()` each
  service(); plugin reads it. No new ABI field needed for Part A.
- Part B needs the delivery_icount visible to the block driver / its timer. It
  is already computed host-side; expose it to the guest-side driver either via
  the same slot field (the driver reads it) or pass it through the blk_wait
  callback. Prefer: the driver reads the slot field it already maps.
- No new shmem ring; SLOT_BLK_IO stays as is.

## 4. Inertness argument (satisfies [PATCH-1..], [INV-7])

- The block-wait callback is a pure additive plugin-API export and is NULL by
  default. Only the explicitly selected `crucible-shmem` driver consults it.
  Without registration, that driver retains its wake-fd-backed event wait; every
  other block driver and launch profile is unchanged.
- The selected B2 mechanism reuses the existing plugin advance-completion
  barrier and wake notifier. It adds no timer or polling path outside an active
  registered Crucible block wait.
- Classification: **determinism-critical** (it changes when/how a guest advances
  past device I/O — a Layer-0 timing behavior). Needs the strongest inertness
  argument + gate:qemu-inert + gate:layer0-determinism, plus a per-patch
  micro-test.

## 5. Verification

The standalone `checks.crucible.phase2.qemuDeviceCompletionAdvance` realization
passes on the Linux builder against the complete carried QEMU package. It:

- compiles a stock-QEMU negative control for the block-wait API;
- applies the authoritative series with zero patch fuzz;
- compiles the patched callback declaration;
- verifies the pending-poll wait hook and post-commit waiter resume in the
  reconstructed source.

- **Behavioral live gate:** in sim mode with the plugin registered, a guest read
  of sector 0 completes through the mapped production hot path and reserved
  block ring. The gate records `frames_processed=1`, `frames_delivered=1`,
  `guest_progressed_past_block_io=true`, and advancement to the 12,000,000
  icount scheduler ceiling.
- **R3 stress leg:** a deliberately-slowed servicer (wall delay before writing
  the response frame) produces the same guest-visible diagnostic projection as
  the fast run under bounded scheduler preemption. Host `service_calls` is deliberately
  excluded because it measures polling cadence rather than guest state.
- **R1 race leg:** start the servicer so the deadline publish lags the first
  blk_wait fire. The driver's wake/resume/re-fire path still reaches progress,
  proving no skip-and-hang.
- **Inertness micro-test:** build the SAME source without sim mode / without the
  plugin; a crucible-shmem block op falls back to classic yield (or the driver
  is absent), and gate:qemu-inert's corpus is byte-identical to pinned upstream.
- Discriminator for the delivery half: with the resume mechanism present a
  read/flush completes; without it the guest STALLS at the first block I/O
  (exactly today's observed behavior) — a clean progress-vs-stall discriminator,
  same shape as m2's 0017 PENDING 0->-2 sentinel.

## 6. Sequencing / dependencies

- Patch 0039 and its Rust callback trampoline are present in the deterministic
  carried stack. The certifying live block-I/O run and byte-for-byte patch
  regeneration gate both pass on the Linux builder.
