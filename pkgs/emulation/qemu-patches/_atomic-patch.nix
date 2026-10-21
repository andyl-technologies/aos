# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "65f50c0de805ffde162dddb2c49722c229865da3f0b22a8087c41bed9801ffda";
  subject = "Re-deliver coalesced RR control wakes and claim them before idle waits";
  body = "A host doorbell becomes an RR control request. While the RR thread has not claimed the outstanding request, later doorbells coalesce into it, but the coalesced path returned before notifying the dispatch ceiling or kicking the CPU. The outstanding generation got exactly one kick, so a kick that reached the RR thread before it could claim the request was never repeated, and the host's periodic doorbell could not repair it.\n\nThe request's own kick also publishes an RR wake, which moves the RR state from IDLE to IDLE_WAKE_PENDING or from ACTIVE to ACTIVE_WAKE_PENDING. Both control claims required IDLE, and only the wake boundary or TCG preparation collapses that state. The icount retry, the main-loop handoff and the VM-stop park loop back to the outer claim without either one, which left the request unclaimable. rr_wait_io_event also fired the plugin idle callback before it collapsed the wake or checked for a control request.\n\nThe idle control-boundary bridge also bound its target request once per idle callback. Cancellation completes a request without delivering a callback, so the control-boundary generation does not advance. A bridge bound to a cancelled target ignored the newer request, parked again on the scheduler clamp, and every later doorbell coalesced behind the unclaimed request: the node stopped publishing while the host waited for it.\n\nA coalesced request now re-delivers the dispatch notification and the CPU kick without advancing the generation. Sim RR defers kicks to its deterministic boundary, so a repeated kick cannot move a guest coordinate. When every vCPU is halted, the outer claim and rr_wait_io_event settle a pending request's own wake and claim it at IDLE, and rr_wait_io_event does so before any idle callback. No translation block can run at that seam and the idle wait consumes the same wake anyway, so no guest-visible coordinate moves; a runnable vCPU keeps its wake for the TCG boundary. The bridge re-binds a completed target to the newest outstanding request only when no callback was delivered in that bridge; a delivered callback keeps its original exit. Idle arm refuses to wait while an RR request is unclaimed, because in sim RR the request's kick sets no exit_request and has no armed futex word to wake, and the bridge then claims the request first.\n\ntest-crucible-control-deferred runs the production arm and bridge over one halted CPU. Each new case fails without its fix: two doorbells before acknowledge kick twice at request generation one; arm refuses a pending request; and a clamped bridge whose target is cancelled claims the next request instead of parking behind it.\n\ntest-crucible-rr-sim-barriers now also extracts the RR wake boundary, the claim settlement and the outer loop's claim statement, and takes the wake state machine from its header. A request is published with its own IDLE or ACTIVE kick while every vCPU is halted and the idle callback provider aborts. The wait returns at IDLE without a callback, and the outer claim acknowledges the request; a runnable vCPU keeps its wake. Without the settlement the wait reaches the idle callback and the outer loop never claims, which the new unsettled-control-claim negative control reproduces.\n\nA published logical ceiling is now an upper bound rather than a stop. The RR loop crossed the final partial instruction to MIN(deadline, ceiling), crediting the gap below the ceiling to the guest, and a stalled node jumped to the ceiling, so guest time depended on where the host split quanta. qemu_plugin_register_sim_shmem_settlement_cb registers a settled-publication callback and a callback that reports the plugin's next exact event: an inbound delivery, a device completion, or a ceiling the host declared exact. The partial-instruction advance now targets only a timer or fault deadline at or before the ceiling. A runnable vCPU never moves its clock without a retirement, so it never crosses to a plugin event: it takes the event at its first boundary at or after it, and the event does not hold a boundary unsettled. A dispatch boundary whose next retirement would cross the ceiling, with no timer or fault deadline before it, is published as settled through the ceiling QEMU sampled, including an exact-event ceiling it cannot land on, and the final post-execution ceiling completion defers to the advance while such a deadline is pending. A stalled node advances only to events at or before the ceiling, publishing each one, and otherwise settles at its current clock. A sim node whose plugin dispatches ceilings without registering the callbacks is refused before its first guest instruction, and no fallback treats its ceiling as an exact stop or publishes a plain boundary as settled. The in-tree sim test plugins register the callbacks and declare their own ceilings exact events. The timer/icount migration section moves to version 6, so streams that may carry credited bias are refused, and the shared-memory ABI headers move to version 32. test-crucible-net-stop-chain stubs the boundary publication. The new test-crucible-rr-bound-ceiling extracts the production advance, stalled-deadline, publication, launch-refusal and predicate bodies; six negative controls restore the old ceiling credits, the crossing to a plugin event, or the fallbacks and fail. An exact-event ceiling and an inbound delivery inside the final gap settle the boundary with the clock at its last retirement. Its cases include host ceilings one and 49 ticks ahead of the clock, which leave a zero raw budget: the clock stays at its last retirement and the boundary settles through the ceiling, while a timer inside a one-tick gap is reached before the boundary settles. The new test-crucible-icount-vmstate-version runs the production subsection loader and version gate over the production timer/icount descriptor: version 5 and older streams are refused before any hook runs, and two negative controls that accept them fail.\n\nA vCPU's synchronous block I/O polls the main loop on the RR thread itself, mid-instruction, so a queued time advance runs and completes there. Completion left the advance in SETTLE_READY for the outer RR loop, which cannot run again until the guest access returns. When the blocked access needed a second advance, because the first stopped at a virtual timer below the device deadline, every later enqueue found the first advance outstanding and returned -EBUSY. The waiter retried for ever and the node stopped advancing. A completion that runs nested inside RR guest execution now releases the advance barrier itself, after the plugin committed the advance and before the device waiters are re-entered, so the waiter can enqueue the advance to its deadline. The RR thread is executing rather than parked, so this path publishes no durable idle wake; completions on the main loop still settle at the outer RR idle boundary. test-crucible-control-deferred adds a nested-io case: a waiter re-entered by the first completion enqueues a second advance, which is accepted and completes, and no idle wake is published. The nested-settle negative control leaves the completion to the outer loop and reproduces the -EBUSY refusal.\n\nA runnable vCPU also never moves its clock to a QEMU-owned deadline. The RR loop crossed the final partial instruction to a virtual timer or a fault or preemption deadline, so the guest's clock moved without a retirement. Now it fires each one at the vCPU's first instruction boundary at or after its deadline: the timer instruction limit, the boundary-deadline clamp, the fault and preemption budgets round up to that boundary, and the partial-instruction advance only runs a timer that is already due. A boundary whose next retirement would cross the ceiling settles through it with a QEMU deadline still pending in the gap, and the deadline fires at that boundary in the next quantum. The firing boundary depends only on the clock and the deadline, not on where the host split quanta. A fault command whose target lies less than one retirement before the boundary is applied there, and only a later boundary reports PAST_BOUNDARY. A commanded preemption is applied at the first boundary at or after its tick, and one a whole retirement late still aborts. An all-halted node, which cannot retire, still idles exactly to a QEMU-owned event in the gap, and the stalled-node and nested device-wait advances are unchanged. test-crucible-rr-bound-ceiling adds a runnable vCPU with a timer, a fault deadline and a preemption 24 ps ahead, each met at the next boundary with no clock move, a halted node idling to a timer in the gap, and a preemption a whole retirement late that still aborts. Four new negative controls restore the time-only crossing, the floored deadline budget, the floored timer limit and the exact preemption tick, and each fails. test-crucible-tcg-fast-paths applies fault targets 24 ticks ahead of and 999 ticks behind the boundary, and reports one a whole retirement behind as PAST_BOUNDARY.";
  commit = "45e08b2107cc9603fd6e00b5e649da80bd0f72f6";
  tree = "f88245d8fa743eb03bfa2f8cbf45026fe4834e65";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/sched12-timer-boundary-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "d0eaaf1e20b0600709f5d679eac113fcda8b8bf9f051460d0baf2688d57a4481";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-21T21:57:45Z";

  additionalCapabilities = [
    {
      catalogName = "rr-switch-quantum";
      carriedBy = "crucible-qemu-11.1.1.patch";
      class = "D";
      enforces = "PATCH-44,DET-1,QEMU-43";
      capability = "round-robin vCPU switch boundary pinned to node-icount";
    }
    {
      catalogName = "crucible-plugin-advance-barrier";
      carriedBy = "crucible-qemu-11.1.1.patch";
      class = "D";
      enforces = "PATCH-19,DET-1,INV-10";
      capability = "normal-mainloop barrier orders timer bottom halves before queued advance completion";
    }
    {
      catalogName = "crucible-plugin-device-wake";
      carriedBy = "crucible-qemu-11.1.1.patch";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "event-driven device completion through the registered wake fd and normal main loop";
    }
    {
      catalogName = "crucible-net-direct-inject-api";
      carriedBy = "crucible-qemu-11.1.1.patch";
      class = "F";
      enforces = "PATCH-32,DET-18,E18";
      capability = "lossless RX direct-injection status API with no QEMU-private retention or stale private-queue backpressure latch";
    }
  ];
}
