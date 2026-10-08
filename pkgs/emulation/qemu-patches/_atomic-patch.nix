# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "f2528b7caee5479b864b0cc7bf0e129c1b23f229cd069765db6f6339937571c7";
  subject = "Integrate paged RAM and native execution fast paths";
  body = "Retain authenticated paged RAM, independent writer epochs, scoped RAM\nidentities, transactional simulated memory faults, checkpoint source\nprotocols, staged restore ownership and native worker quiescence.\n\nCarry guarded native mutex waiter updates, sorted inline TCG page-lock\ncollections with stable spill ownership, derived crossing memberships,\nand validated thread-private TSC search positions. Preserve every guest\naccess, invalidation range, clock value, replay observation, virtual\ncoordinate, callback order and public process protocol.\n\nRetain RAM pause registration and native thread identity accessors while\ncombining the original fast-path source changes. Preserve per-file\nlicenses and all existing source, causal-control and guest SMC fixtures.\nKeep the separate selected-dirty-client iterator candidate unapplied.";
  commit = "792413f18873f0a6a68a275d600f2cb60ad29973";
  tree = "1161c6f38ca64c2a8c8e0a6985fdb0fbf2063236";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-ram-fast-path-integration";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "bb782b56b266a21b7bcdc90f896daa98f215f4ca6407f19bc70c4478609a0339";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-07T21:11:57+00:00";

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
