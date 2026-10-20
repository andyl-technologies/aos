# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "bc28f7eab3638a729760aff0486f630b1465a4588c1b94aebfa03dc41474e3e3";
  subject = "crucible: isolate deferred-control component symbols";
  body = "Retain the complete Crucible integration on the sole pinned QEMU base.\nChange only the deferred-control component namespace; preserve all other\nsource blobs, modes, production providers, APIs, ABI, licenses, configured\nlimits and experimental support policy.\n\nMap the 124 observed component definitions except main to fixed private\nnames before the first component include. Keep all 28 observed undefined\nprovider names unmapped, including object_unref and notifier_list_notify.\nApply the namespace only to the component translation unit so independently\ncompiled QOM and utility providers retain their genuine symbols.\n\nPreserve every existing production selection, input pin, opaque composition,\nassertion, causal mutation and retained-object compile/link/runtime command.\nThe actual owning runner must still verify resulting symbols, types,\nrelocations, genuine QOM/support linkage and positive/exact-mutant runtime\nbehavior. Source metadata review does not qualify those obligations.\n\nNo selected Source or CPU activation, genuine Main/Original admission,\npositive physical CPU-pin return, RCU, launched lifecycle or performance\nqualification is implied. Preserve their mandatory failures and gates.";
  commit = "a6bd0cc8571ad77bc4a08a7d684b84536a879878";
  tree = "f3a03f1d792efeeb6206d4ca6f57d6b9cee09d3f";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/control-deferred-namespace-v1";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "96360dd17439a66f34256717df4b074663a677d1738a887ad7960f7018903621";
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
