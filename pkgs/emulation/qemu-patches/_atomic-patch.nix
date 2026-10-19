# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "55c54aeed918bbec2ed3f0942e9630b5d9a88d006e7f6f84dd257d6a5b7bc805";
  subject = "Integrate Crucible ownership and parent Park Original checks";
  body = "Retain the Source, checkpoint, parent Park and resident Root integration\nwith versioned transport, physical custody journals and paid fixed storage.\n\nExport callback-scoped checks and bounded slice queries for both parent Park\nOriginals. Bind each synchronous borrow to the dispatcher-held request,\ninvocation, callback and userdata; retire it before dispatch advances.\nReobserve both live Originals after failures, preserve first errors, refuse\nreentrant or foreign calls and leave failed query outputs unchanged.\n\nAdd negative controls for absent callback scope and foreign threads and\nprocesses without manufacturing positive native custody. Unavailable live\nMonitor and cancellation peers fail if reached. Refresh direct and transitive\nliteral-source fingerprints through the production preinit extraction chain\nwhile retaining existing assertions and controls.\n\nThe signed atomic commit remains based solely on the pinned QEMU source base.\nCompilation and runtime qualification remain separate; these negative controls\ndo not establish positive entered-request or receiver activation coverage.";
  commit = "5881e27347250bd969b6235110aed6f56f72a0cd";
  tree = "5c30b30acaf37ec05c9545cef701e46750609dac";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/parent-park-slice-initialization";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "fa2e0892c42842bd2f3ba7cccae0959428fe98c5cff461a0bd81d3ca6a1b9f2f";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:00Z";

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
