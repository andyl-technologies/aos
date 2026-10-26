# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "7a76cf82503f4a441a997e59759fbad56aabda7efc80a354e2ea3a8016a602c8";
  subject = "crucible: preserve ownership integration with guarded Cleanup stacks";
  body = "Retain the complete Crucible Source integration, Core quantum bank borrowers,\nfixed Module callbacks, opaque frame acquisition and bounded provider storage\ninterfaces in one source tree over the selected base.\n\nAdd a canonical application-paid guarded Cleanup stack mapping owner with\nonce-only physical-effect journals, checked complete fixed-control payment,\nand separate provider, terminal and outer-stack-last-use prerequisites.\nKeep physical unmap before settlement and the final gated debit return.\n\nComplete terminal execution-profile ownership is still unavailable. Missing\ncontaining prebirth payment, TLS/allocator consumers and actual outer last-use\nproduction remain fail-closed; one-MiB component geometry and worker join do\nnot qualify a complete execution profile or authorize admission.\n\nSource extraction and owning-source syntax checks pass. The owning-object\nbuild still rejects the existing unused quantum_rr_actor_birth helper with\nthe unchanged warning policy. No successful object build or runtime activation\nis claimed.";
  commit = "3b099f055ec0c3715c509c39adc5ad68d0d914a5";
  tree = "849797ff3dd3567fcc2a1d0cc5cc4625401e93cc";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/guarded-cleanup-stack-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "050be6beb90cc90f926148bf20b3846498b93e7b80220ba1375788f304afba68";
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
