# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "394fd6e0eeb7eecfe801ffc4d4aa291e7b3155df73adb70207597fe48795e4bc";
  subject = "crucible: preserve cleanup ownership integration and Source compilation";
  body = "Retain the complete Crucible Source integration, Core bank borrowers, fixed\nModule callbacks, opaque frame acquisition and bounded provider ownership\ninterfaces as one complete source tree over the selected base.\n\nProvide application-paid guarded stack custody, checked expanded fixed-control\npayment and separately charged startup and libc arena backing. Connect actual\nunarmed caller-backed storage and the retained stack interior to native provider\ninitialization, preserving factual outcomes before independent posts. Unarmed\ncreation refuses before effects and has no worker-entry binding operation.\n\nAdd once-only initialized-but-never-created native resource return through real\nprovider retirement, exact backing receipts and canonical startup unlink.\nRetained request/account/process/payment identity authorizes only teardown of\nthe same resources after refusal. Independent last-use posts precede physical\nunmap, and application charges return last. Preserve every partial outcome and\nindependent return failure without overwriting the initiating child failure.\n\nMark the deliberately disconnected quantum_rr_actor_birth producer unused and\nexplain the closed CPU admission boundary. Preserve its complete body, every\nadmission refusal and all warning flags. Refresh extraction hashes from final\nbytes. No invented call site or additional execution permission is introduced.\n\nThe existing synchronous Main continuation remains subject to its exact caller,\nMain/BQL and retained-owner contracts. Complete execution-profile ownership,\ngenuine containing prebirth payment, loader/initial-TLS closure, workload bounds,\nallocator/context/cache/RCU terminal joins and external collection remain absent.\nNo worker/kernel/TLS terminal or independent guarded-stack last-use is inferred.\n\nFresh source-built configuration and actual owning Source object compilation\npass. Direct default and authentic-header bounded-provider compile-only Source\nobjects both pass without diagnostics, as do six existing syntax checks and\nSource extraction coherence. Earlier component evidence remains unchanged.\nNo test, provider/startup experiment, guest or runtime activation is executed.";
  commit = "4b64466043bf4cc0386ca8f547af393c9673a5b8";
  tree = "d445af4cb5c3a2dbfb5cb895d6f1ae59d37a7803";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/cleanup-source-compile-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "a6224fa094bd731b66da40eb662a1469365d556b8c3f7c9bd36020a822a230fa";
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
