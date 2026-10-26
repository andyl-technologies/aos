# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "c9564187aef44c8652c078ef7de838b5057bb034340346198f29b83f5be92b93";
  subject = "crucible: preserve ownership integration with uncreated Cleanup return";
  body = "Retain the complete Crucible Source integration, Core quantum bank borrowers,\nfixed Module callbacks, opaque frame acquisition and bounded provider ownership\ninterfaces as one complete source tree over the selected base.\n\nProvide application-paid guarded stack custody, checked expanded fixed-control\npayment and separately charged startup and libc arena backing. Connect real\nunarmed caller-backed storage and the retained stack interior to actual native\nprovider initialization, preserving both-span outcomes before independent posts.\nThe existing armed constructor still requires an entry; unarmed creation\nrefuses before physical effects and has no entry-binding operation.\n\nAdd a distinct once-only initialized-but-never-created return operation. It\nauthenticates retained canonical request/account/process/payment coordinates\nwithout repeating permission Current after refusal. Actual provider retirement\nand exact uncreated backing receipts precede canonical startup unlink, separate\nresource last-use posts and both physical unmaps. Each application charge\nreturns last. Fixed snapshots and independent return failures preserve every\npartial outcome without changing the initiating child failure or issue state.\n\nNo worker/kernel/TLS terminal facts or guarded-stack last use are fabricated.\nComplete-profile ownership, genuine containing prebirth payment, complete\nworkload bounds, allocator ownership and actual Cleanup execution/terminal\nproducers remain missing. This source progress enables no accepting admission,\nworker birth, new Original or complete Cleanup return.\n\nSix Source/native/control syntax checks and four native/control object checks\npass in default and authentic-header provider compile-only configurations.\nSource extraction passes. Source objects retain the existing unused\nquantum_rr_actor_birth diagnostic with the warning policy unchanged. No\ncomponent, provider/startup experiment, guest or runtime activation is executed.";
  commit = "ac77c71918f9fabef298e9134ff0754eaf9c54d7";
  tree = "b055bc9c00457049f72e2cd2098372bb466a04f6";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/uncreated-cleanup-return-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "b92f28f4646c34a2b906f4d0cee944599e23dd7ff12056b51839a00026a0b425";
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
