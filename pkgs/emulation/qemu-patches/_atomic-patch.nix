# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "267905c00d69552d300f8725ce681913a45eaf2b0a5adb6b1186500ef5149fef";
  subject = "crucible: validate deferred-control emitter callers";
  body = "Retain the complete Crucible integration and isolated native components\non the sole pinned QEMU upstream base. Change only the two derived\ncontrol fixture callers; preserve every other source blob and mode.\n\nBefore stopped-control-rearm or template-control-drain creates output,\nvalidate the shared emitter's ten literal production inputs through its\nexisting validator. Pass that same mapping to production_bodies and\nforward it unchanged through the template fixture constructor. This\nrepairs the two stale no-argument calls without a fallback or pin bypass.\n\nPreserve all opaque composition, providers, production APIs and ABI,\nlicenses, input pins, assertions, causal mutations, limits and support\npolicy. The normal owning runner must establish subsequent compilation,\ngenuine provider linkage and unchanged runtime predicates; this call-shape\nrepair does not qualify those obligations.\n\nNo selected Source or CPU activation, genuine Main/Original admission,\npositive physical CPU-pin return, RCU, launched lifecycle or performance\nqualification is implied. Preserve their mandatory failures and gates.";
  commit = "c1c525a232b485acf878439c1d3049d6224086b3";
  tree = "a83fb8a4182251457c8ebbd121220169ef4f43ee";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/control-source-callers-v1";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "f047f745bce4af3c6aba2b5ef92d7471f089781000d51862a24a39e9609e8700";
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
