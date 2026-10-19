# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "5ca4c6140478a3e946ce89686325384ab904f5c5580afa80ff2b71b1af56dcd9";
  subject = "Integrate Crucible ownership and ordered parent Park disposition";
  body = "Retain the Source, checkpoint, parent Park and resident Root integration\nwith versioned transport, physical custody journals and paid fixed storage.\nPreserve callback-scoped checks and bounded queries for both Park Originals.\n\nFinish the exact Native capture and return request-owned block, async and\nRCU census/storage before invoking plugin DISPOSITION. Keep the real Source\nloan and native writer gate held across that callback. Verify the completed\ncapture identity, sequence and child; reject active capture, physical debt\nand prior run, capture or return failures. Preserve independent cleanup\njournals and suppress healthy plugin disposition after a failed run.\n\nRefresh the affected direct and transitive source fingerprints without\nchanging assertions, test cases, inventories or qualification limits.\n\nThe signed atomic commit remains based solely on the pinned QEMU source base.\nCompilation and runtime qualification remain separate. This ordering change\ndoes not implement a fork/thread transaction or an actor Original producer,\nand it does not establish positive entered native phase-order coverage.";
  commit = "76eeebb5f2a2f9e4fdf3c732340bdc8de4f1fa83";
  tree = "f4aa9344b91ccbbe7d3b8d91e16120907c8ff75b";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-park-disposition-order";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "9d7da21330139ddad1c2d5b4a1e68ba2eb28a992d0c4825030eb471eb7770c8f";
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
