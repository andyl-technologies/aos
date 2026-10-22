# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "0b76c7668f9c170e4536cc2a96bd74bc5de2c408ed0a0929b81f05e5b5ee483d";
  subject = "crucible: retain stack debt and bounded-thread runtime custody";
  body = "Keep canonical same-parent Main/RR stack lenders, factual return journals and\npaid external startup/registry storage. Add the optional installed bounded\npthread consumer for genuine supplied-stack birth and kernel/TLS/notifier/\nregistry retirement, preserving the ordinary pthread route.\n\nRetain the actual stack-closure helper in constructor and RR-parent literal\nfixtures, expose captured constructor compiler diagnostics, and bind their\nfinal transitive extraction fingerprints. Complete Source application and\nstack issuance, finite RR allocation and stop/drain closure, physical parent\nretirement and external Main reap remain required before profile admission.";
  commit = "2564b502e49f7d164d07fcd64fdd4ec2bfad9545";
  tree = "a5bf76c20ff8ac6d08704cfe5a792503ede92555";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/quantum-stack-consumer-fixture-public-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "fd7802da3811d84ac73fe4e966e929a6b5b9dac4ffc74ddcc9f8fcecab1bcb56";
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
