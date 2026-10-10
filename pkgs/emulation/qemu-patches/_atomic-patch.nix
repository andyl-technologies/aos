# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "d4712671443b744eb7c6d67374a4990aaa38f5d4899c2cf27239295afd6ee604";
  subject = "crucible: retain initial source and procfd descendant custody";
  body = "Retain the initial installer's original deadline, cancellation event and\nmodule custody, with installer-qualified parent park callback registration.\nPreserve descriptor blocking flags on selected plain UNIX monitor sockets\nand inspect their immutable receive configuration. Include the x86\ndescriptor-table identity fields and the matching native fixture coverage.\n\nKeep the procfd fixture's original ten-second execution bound. Retain its\nowned process group under a Linux subreaper and verify actual descendant\nwait statuses within a separate three-second physical cleanup bound.\nPreserve every ordinary case, extracted production body and assertion.\n\nLater original dispatch, receiving namespace admission, workspace-purpose\nclaims and separately admitted child Source acceptance remain unavailable.\nThe callback registration and configuration predicate do not grant them.";
  commit = "aa2d3d44b90bb166f69117800eb156b0312bfa2f";
  tree = "3337d2c450f83e3b34dc0eff24905961ccae2a78";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-procfd-descendant-custody";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "5977183a3584f9b926167c6b8ed9cfe3bfb8236c5c0bcfa67199a65a54e47495";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-10T13:33:59+00:00";

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
