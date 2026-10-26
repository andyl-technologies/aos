# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "3fd687914c83de266e6bf0494f78e477202882137b654e63b48fd71e36dace33";
  subject = "crucible: preserve ownership integration with unarmed Cleanup backing";
  body = "Retain the complete Crucible Source integration, Core quantum bank borrowers,\nfixed Module callbacks, opaque frame acquisition and bounded provider ownership\ninterfaces as one complete source tree over the selected base.\n\nProvide canonical application-paid guarded stack custody, checked expanded\nfixed-control payment and separately charged native startup and libc arena\nbacking. Connect the retained stack interior and real caller-backed unarmed\nstorage to the actual bounded provider initializer. Preserve exact outputs and\nonce-only journals before independent posts, including both ranges consumed\nby one initialization. Keep the existing armed constructor's entry contract;\nunarmed creation refuses before physical effects and has no binding operation.\n\nComplete-profile Current, containing prebirth payment, workload bounds,\nallocator ownership and genuine terminal producers remain unavailable. This\nresource component enables no Cleanup worker or accepting admission. Physical\nreturn still requires distinct provider, context/cache/RCU and final outer\nlast-use production; byte geometry or a successful join cannot supply them.\n\nSource syntax checks pass in default and authentic-header provider compile-only\nconfigurations. Native owner and component-control objects compile in both;\nSource objects retain the existing unused quantum_rr_actor_birth diagnostic\nwith the unchanged warning policy. Source extraction passes. No component,\nprovider/startup experiment, guest or runtime activation is executed.";
  commit = "0703c5dfef1633a397e8f73d2d94874eec7d6a5f";
  tree = "71b8c259ca754ff199775c2e3f891fb394873041";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/unarmed-cleanup-worker-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "27640b31214a89e4286a0e864346a080989ebf5dd10a85e5d00eb6c573d8b101";
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
