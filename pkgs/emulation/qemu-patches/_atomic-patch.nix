# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "7d54d41a29a330656b2fe62c16b8359ed8297c6341df1de6f45bb1e7abc92a31";
  subject = "crucible: integrate deterministic QEMU execution";
  body = builtins.concatStringsSep "\n" [
    "Co-locate the versioned plugin protocol, exact checkpoint, retained hot-fork,"
    "asynchronous-worker, and device-fingerprint implementation as one atomic,"
    "reconstructible QEMU 11.1.1 integration boundary."
    ""
    "Rearm pending main-loop work after a deferred reset consumes its original AIO"
    "wake, allowing repeated require-ready watchdog resets to complete without"
    "external QMP activity. Make the fingerprint projection test wait for an"
    "executed guest TB before checking the outside-boundary marker result."
    ""
    "Preserve sim-only virtio-rng rate-limit and HPET comparator history across"
    "exact VMState restore. Version the continuation projections that canonicalize"
    "native QMP pause flags and disabled UART THRI state while retaining strict"
    "guest-visible and active device state. Keep ordinary non-sim virtio ioeventfd"
    "policy unchanged."
    ""
    "Preserve each virtqueue's notification latch in the current Crucible-only"
    "checkpoint subsection so sim RX polling resumes with the source state."
    ""
    "Adopt pinned launch images into live block roots before hot fork,"
    "retiring verified startup fdset bookkeeping without closing the"
    "block-owned descriptors."
    ""
    "Service CPU stop and unplug events while the RR thread waits for a main-loop"
    "handoff or its poll priming. This lets synchronous VM stop complete without"
    "advancing guest instructions or admitting another deterministic RUN interval."
  ];
  commit = "081dd3b4c690931130fabdf76eb02a147d99ef25";
  tree = "4a4df1abc19bc366bdabced21c6e288b2ee84a16";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "crucible/qemu-11.1.1";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "c502c8d9e2c860c09cc4f90ba9508eb94fd49c27ae42a041d2b6322342bd2957";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";

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
