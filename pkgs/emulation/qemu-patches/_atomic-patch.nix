# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "b271a55a6abeb26639e3a2ff04371f375bffa348178e3339a84abcfb02cc61e5";
  subject = "crucible: retain deferred-control component object";
  body = "Retain the complete Crucible integration and all existing RAM metadata,\nsettle-prepark and deferred-control behavior on the sole pinned QEMU base.\nChange only the deferred-control emitter's compile/link tail; preserve\nproduction, providers, APIs, ABI, licenses, limits and support policy.\n\nCompile the generated component into a retained control-deferred.o with\nthe same configured compiler prefix, then consume that actual object in\nthe existing utility-source link order. Record both checked command\narrays. Preserve link-only arguments, checked failures and the runtime\ncommand, along with every input pin, assertion and causal mutation.\n\nThe retained final-link input supports object inventory during the next\nnormal native check without another opaque extraction. Actual object_unref\nprovider closure, symbol ownership, genuine QOM linkage and component\nruntime qualification remain pending. No provider is substituted here.\n\nNo selected Source or CPU activation, genuine Main/Original admission,\npositive physical CPU-pin return, RCU, launched lifecycle or performance\nqualification is implied. Preserve their mandatory failures and gates.";
  commit = "bc75333383c5d64014b2d91044e370b45aaf2d95";
  tree = "5a7a796f50dc6afa5f348d062d4e44c6bc04b681";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/control-deferred-object-v1";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "9277672c5fefedefd69b709707e6f7b8a18a2aae3c1be3b11052dcf21ce9fc2f";
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
