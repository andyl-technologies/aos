# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "c19e885a08793f03abe3546c3b27447aa268945c9c8c3de5997979ffcc2202f5";
  subject = "Re-deliver coalesced RR control wakes and claim them before idle waits";
  body = "A host doorbell becomes an RR control request. While the RR thread has not claimed the outstanding request, later doorbells coalesce into it, but the coalesced path returned before notifying the dispatch ceiling or kicking the CPU. The outstanding generation got exactly one kick, so a kick that reached the RR thread before it could claim the request was never repeated, and the host's periodic doorbell could not repair it.\n\nThe request's own kick also publishes an RR wake, which moves the RR state from IDLE to IDLE_WAKE_PENDING or from ACTIVE to ACTIVE_WAKE_PENDING. Both control claims required IDLE, and only the wake boundary or TCG preparation collapses that state. The icount retry, the main-loop handoff and the VM-stop park loop back to the outer claim without either one, which left the request unclaimable. rr_wait_io_event also fired the plugin idle callback before it collapsed the wake or checked for a control request.\n\nThe idle control-boundary bridge also bound its target request once per idle callback. Cancellation completes a request without delivering a callback, so the control-boundary generation does not advance. A bridge bound to a cancelled target ignored the newer request, parked again on the scheduler clamp, and every later doorbell coalesced behind the unclaimed request: the node stopped publishing while the host waited for it.\n\nA coalesced request now re-delivers the dispatch notification and the CPU kick without advancing the generation. Sim RR defers kicks to its deterministic boundary, so a repeated kick cannot move a guest coordinate. When every vCPU is halted, the outer claim and rr_wait_io_event settle a pending request's own wake and claim it at IDLE, and rr_wait_io_event does so before any idle callback. No translation block can run at that seam and the idle wait consumes the same wake anyway, so no guest-visible coordinate moves; a runnable vCPU keeps its wake for the TCG boundary. The bridge re-binds a completed target to the newest outstanding request only when no callback was delivered in that bridge; a delivered callback keeps its original exit. Idle arm refuses to wait while an RR request is unclaimed, because in sim RR the request's kick sets no exit_request and has no armed futex word to wake, and the bridge then claims the request first.\n\ntest-crucible-control-deferred runs the production arm and bridge over one halted CPU. Each new case fails without its fix: two doorbells before acknowledge kick twice at request generation one; arm refuses a pending request; and a clamped bridge whose target is cancelled claims the next request instead of parking behind it.\n\ntest-crucible-rr-sim-barriers now also extracts the RR wake boundary, the claim settlement and the outer loop's claim statement, and takes the wake state machine from its header. A request is published with its own IDLE or ACTIVE kick while every vCPU is halted and the idle callback provider aborts. The wait returns at IDLE without a callback, and the outer claim acknowledges the request; a runnable vCPU keeps its wake. Without the settlement the wait reaches the idle callback and the outer loop never claims, which the new unsettled-control-claim negative control reproduces.";
  commit = "87a5fa7ab41a212d277365d3f70e50787505e893";
  tree = "6f1b4169a489102f9c98dca32345dc3cc6e0253c";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/rr-idle-control-claim-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "dfc7158f701de7e6bbe7334a61ccc12990163bbd1c7c99857a7ad3cda36966ea";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-18T02:54:25Z";

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
