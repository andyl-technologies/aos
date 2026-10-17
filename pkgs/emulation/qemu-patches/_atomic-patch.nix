# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "1870bc803eff037c58a26e161971a05d1d61a265e509b5238a2a32c897f6b5f9";
  subject = "Re-deliver coalesced RR control wakes and re-bind cancelled idle targets";
  body = "A host doorbell becomes an RR control request. While the RR thread has not claimed the outstanding request, later doorbells coalesce into it, but the coalesced path returned before notifying the dispatch ceiling or kicking the CPU. The outstanding generation got exactly one kick, so a kick that reached the RR thread before it could claim the request was never repeated, and the host's periodic doorbell could not repair it.\n\nThe idle control-boundary bridge also bound its target request once per idle callback. Cancellation completes a request without delivering a callback, so the control-boundary generation does not advance. A bridge bound to a cancelled target ignored the newer request, parked again on the scheduler clamp, and every later doorbell coalesced behind the unclaimed request: the node stopped publishing while the host waited for it.\n\nA coalesced request now re-delivers the dispatch notification and the CPU kick without advancing the generation. Sim RR defers kicks to its deterministic boundary, so a repeated kick cannot move a guest coordinate. The bridge re-binds a completed target to the newest outstanding request only when no callback was delivered in that bridge; a delivered callback keeps its original exit. Idle arm refuses to wait while an RR request is unclaimed, because in sim RR the request's kick sets no exit_request and has no armed futex word to wake, and the bridge then claims the request first.\n\ntest-crucible-control-deferred runs the production arm and bridge over one halted CPU. Each new case fails without its fix: two doorbells before acknowledge kick twice at request generation one; arm refuses a pending request; and a clamped bridge whose target is cancelled claims the next request instead of parking behind it.";
  commit = "94720b4f693fdaa064b3bb6744d1089265665407";
  tree = "ed1208001b54ef586ee1233cb678453c559d40ba";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/rr-idle-control-claim-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "a7973dd7da09ccdb86e47ee2fa4f7151bfdc17d078d482aa0d60a0dc94929587";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-17T02:49:28Z";

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
