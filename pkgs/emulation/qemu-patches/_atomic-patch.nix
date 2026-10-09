# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "80d3bea774901044fef950a135a3777d4a05eede2f8f58e8c45361e04d8cfce8";
  subject = "Keep hot-fork operation state outside reclaimed monitor stacks";
  body = "The OOB monitor command submits a pointer to its local operation while the\nmain loop forks. In the child, libc makes vanished pthread stacks reusable.\nStarting the replacement monitor can therefore reuse the operation's storage\nwhile reconstruction still holds its pointer.\n\nAllocate the complete operation before submission. The parent frees its copy\non command return; the child frees its independent copy only after publishing\nretained state, rebinding the monitor basis and releasing private input. Keep\nall reconstruction guards, resource ownership and callback ordering intact.\n\nAdd a source-derived lifetime regression using real fork and pthread stack\nreuse. The original declaration overlaps the replacement stack and refuses;\nthe heap declaration stays outside thread stacks and preserves its immutable\nwitness and interior pointer. The test never dereferences inherited stack\nstorage or writes into another thread's stack. Its reduced payload does not\nestablish native callback behavior or attribute a physical crash.\n\nValidation: AOS compiler and the actual linked libc/GLib, warnings denied;\noriginal ownership refusal and heap success both observed. Full canonical\nnative/package and physical guest qualification remain separate requirements.";
  commit = "6349c51b5a57babce7a58340eda74f85fedff4ac";
  tree = "43ca925bd8efcbe6cba0a9de8ea2628f17ee15c3";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-hot-fork-operation-ownership-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "e6135b64eacb646c6a51171284bca52413377dedbc396c8e118182dfccacb2a9";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-09T11:52:46Z";

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
