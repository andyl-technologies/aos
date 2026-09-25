# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "296218452896c99fc3a445ce2dbf84fe30e00b22e92eebcab8f1c38a59b69747";
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
    ""
    "Reopen pinned fdset-backed native sources through their live descriptors"
    "while freezing and restoring. Launch adoption can retire the fdset namespace"
    "without losing the validated file identity."
    ""
    "Allow the retained RCU barrier owner to perform accounted reporting reads"
    "until fork transaction sealing. Keep callback and registry admission closed,"
    "and reject fork while any owner read remains active."
    ""
    "Report bounded source restoration and release failures through the"
    "versioned template QMP failure stage and detail."
    ""
    "Complete instruction-rule and lifecycle translation invalidation on the"
    "serial vCPU before leaving a fault boundary. Avoid rebuilding the"
    "instruction index for unrelated node rules."
    ""
    "Preserve active serial transmit timing, virtio-blk backend cache mode,"
    "and virtio legacy first-kick state in versioned sim VMState continuations."
    "Require a subsection name component boundary so nested virtio state does"
    "not consume outer virtio-blk subsections."
    ""
    "Require serial timing, virtio-blk backend WCE, and virtio first-kick"
    "subsections on sim restore. Reject invalid serialized UART timing"
    "instead of resuming from recomputed or reset state."
    ""
    "Count Crucible sim time in fixed 125 ps ticks, retaining fractional phase"
    "across guest instructions, absolute timer deadlines, idle jumps, and"
    "denied CPU-service windows. Reject legacy nanosecond bias in sim mode."
    "Version the icount VMState and fingerprint projection, and require the"
    "exact-tick plugin advance API with no nanosecond compatibility path."
    ""
    "Reject PMU-enabled ARM CPUs at sim realization because the ARM retired"
    "instruction overflow IRQ still uses a nanosecond timer. An explicit"
    "pmu=off profile fails closed before guest code without affecting normal"
    "QEMU or other ARM CPU features."
    ""
    "Require the one fixed sim launch profile, shift=0 with alignment and"
    "realtime sleep disabled. Reject manual legacy icount selections"
    "before guest execution while leaving generic QEMU unchanged."
    ""
    "Wait for the baseline hot-fork thread registry to become forkable before"
    "the mutex-corruption fixtures run, so they test the intended sticky"
    "mutex rejection rather than RCU thread startup ordering."
  ];
  commit = "9da7a44fce5bc84e19d2e63a2127c4452a546745";
  tree = "53bdea4138a019bbbf35b5c3ff27d055c229e5a7";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "crucible/qemu-11.1.1";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "efe64c4495f299e0697636a4d71a23f397b7f85e8ee2c0d024ca191c38d4ebe3";
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
