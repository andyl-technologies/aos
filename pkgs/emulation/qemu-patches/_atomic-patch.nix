# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "0c9ed358bd465d5c03a5849d65da86da2cef27aa8f2cf14655c459403284455b";
  subject = "crucible: preserve native runtime and sealed template admission";
  body = "Preserve the native graph and descriptor implementation with the\ndeterministic runtime and schemas. Restore ordinary zero-budget execution\nand queue translation invalidation through exclusive CPU work. Retain\nmain-loop physical completion and drain RR queues before guest execution\nor stop acknowledgment while preserving idle timer ordering.\n\nConvert denied service instructions to exact sim ticks with signed-range\nchecks. Version service clock evidence and retain production-body unit\ncoverage for rate, phase, interruption, ordinary mode and refusal paths.\n\nAuthenticate retained native block seals under BQL during OOB template\npreparation. Acquire BQL before the template mutex, retain both through\nadmission and state publication, and preserve inherited BQL ownership.\nKeep all receipt and barrier checks and other template action scopes.";
  commit = "a3eae68365be5839dd341bbf9829febd418eb097";
  tree = "415594efada238fc49e0022c54d0b9dce1cb9472";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-template-seal-handoff-94";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "293c9c5f0d2bb0c1dd32a0acb946cbeeb58b64c0ae6c0f2be4863e3e5009fa09";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-01T16:33:32-07:00";

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
