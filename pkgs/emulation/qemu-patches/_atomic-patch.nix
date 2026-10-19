# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "fe52faedfdc2ad2f23515be96eb3ed80d9a0604dd8da370aa48616cba3c3971e";
  subject = "Integrate Crucible native worker and retained material custody";
  body = "Retain versioned Source, checkpoint, parent Park and resident Root\nintegration with physical custody journals and paid fixed storage. Preserve\ncallback Original checks, ordered Native disposition and canonical\nregistration cleanup joins, including decoded standing identity controls.\n\nAdd Source-owned worker and material custody through the runtime v6 roster,\nmatched installer exports and fixed typed storage. Retain physical birth\nbefore fallible constructor posts, distinguish entry, close, join and\nowning destruction, and preserve negative-return owners and independent\ncleanup status. Keep the bounded pthread stack separate from runtime\ncontrol and historical provider-backing reservations.\n\nCarry borrowed material outputs through capture v3 and retain actual\nidentity until explicit physical return. Adapt the observer and registered\nABI controls without introducing successful worker or lifecycle providers.\nKeep the diagnostic path independent; an unmatched native worker pipeline\nremains unsupported. Preserve existing assertions, limits and failures.\n\nReconstruct the real Source closure with its worker fragment and linked\nPOSIX provider, and refresh every affected direct and transitive source\nfingerprint. Preserve upstream attributes and per-file licenses.\n\nThis single signed integration commit has only the pinned upstream base as\nparent. Provider-backing completeness, activation, VM lifecycle, physical\ncleanup and performance remain unqualified by these artifacts. In\nparticular, instrumentation, module TLS/TSD/destructor behavior, early\nresolution failures and loader namespace changes remain provider-audit\nobligations; a numeric reserve is not proof of that closure.";
  commit = "86656812f330296a24ee7e4ecf1e3d5a6861536b";
  tree = "1f737d0492abfc93b1760fe15421ee2f773824c1";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-worker-integration";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "6a3a4e9dc868ec025272ce62702131cf06e637665299372b82378c4df7c5d727";
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
