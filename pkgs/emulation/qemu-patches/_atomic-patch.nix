# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "02fcfc2bd5cb0ddf5db14482afb7c9c421b5bd7c6e44d206afd10bdeb938547c";
  subject = "crucible: preserve startup Source fixture provider ownership";
  body = "Add the startup Source lifecycle owners, bounded physical histories and\nproduction-provider companion while preserving the registered fixture's\nscenarios and assertions. Keep ordinary and unissued-state companion\nobservations distinct from accepting lifecycle or profile qualification.\n\nGive the legacy fixture and its exact selected utility closure explicit\nprivate namespaces. Preserve genuine system providers and renamed real\nmain ownership, verify transformation metadata and relocation identities,\nand restrict private dynamic visibility to the existing worker lookups.\n\nLet Meson derive the private static fixture's PIE compilation from b_pie\ninstead of forcing and duplicating its compiler flag. Preserve pic:false,\nselected sources, dependencies, registrations, roots and assertions.\n\nVerify each dynamic fixture export against its canonical recorded type,\nbinding and visibility, preserving the two layout data objects and eleven\ncallback functions. Reject missing, duplicate, undefined or changed exports\nand retain the private-prefix locality and visibility requirements.";
  commit = "7b817c94baa67cd2537d4ca01643c604be4caf86";
  tree = "b26b7645af433ea531a7f341fa10baf072ccdf63";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/legacy-fixture-export-extent-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "60f7da8f9fde6b06d093afc96c3a97a5833ed3094275836b5847fda47dda0b67";
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
