# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "ce6fc3af0da264f7f927dedd7b9d87b0707c35d5aeed341578c3b2f8cdec1815";
  subject = "plugins: retain startup custody and physical workspace ownership";
  body = "Capture the complete startup Source, Native callback lifecycle, nominal\nregistration groups and receiving custody with their owning SDK surfaces.\nPreserve physical workspace backing and mapping ownership, setup exchange\ncount validation, and genuine declaration ownership across the configured\nSource and preexec producers. These physical holders do not issue operating\ndigest, whole-Park, standing or action authority.\n\nKeep the workspace transfer on the existing public Runtime v3 nominal alias.\nDefine the absent-workspace unit provider after the generated canonical\nSource storage, retaining its genuine earlier prototype and output identity\nchecks. Preserve all 141 scenarios and rebind the owning extractor inputs.\n\nThe source remains inactive; complete operating and terminal joins are\nseparate. Include the actual generator inputs and corresponding-source\nnotices without claiming runtime or complete payment qualification.";
  commit = "230fd5b6740d793b21d4708c5e7ff4ca1ed228ea";
  tree = "f349af153c42be10816227eef190388eb6313f67";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-workspace-fixture-cumulative";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "7bab2934af4e4d33a133ec44bcfa0f3a781a4a4b683ce18fe733544f4e62c4f0";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-15T02:17:44-07:00";

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
