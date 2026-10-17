# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "abb22b0739ecb7c55889095ae8ece2b4808675965bdf434a66f7ea6cdc59ccf2";
  subject = "Integrate Crucible ownership and resident Root closure";
  body = "Integrate the retained Source, checkpoint request, metadata and parent Park\npaths with versioned public transport and factual physical return journals.\nPreserve the current SDK, preexec, export and configured fixture fixes.\n\nAcquire resident background closure from the actual entered Main Root before\nits writer. Retain a Source-owned service absence loan and constructor gate,\nfreeze empty service and zero-actor thread membership, and run the existing\nparticipant, kernel-task and descriptor checks. Return writer, native closure\nand Source custody in order while retaining partial debt and independent\nfirst, post and cleanup errors. The lifetime loan stores stable generations\nand creator identity without retaining an Original pointer. Price its actual\ninline storage and prevent publication settlement while owners remain held.\n\nRefresh the affected literal extraction fingerprints. All 28 baseline and\nomission-control source products generate with the existing assertions and\ncontrols preserved. Compilation and runtime qualification remain separate;\nthis source integration does not establish receiver ingress activation,\nproduction resident module enrollment or dirty-iterator positive coverage.";
  commit = "a41786431da54103482f23ae56d78430972f2467";
  tree = "cc38d470d2d4b639da32868efa24b8760039bceb";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/resident-root-absence";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "541f8676a270383cc2b551be4ed073f3a9a27e2d855832c7ad9bb4a675258a8d";
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
