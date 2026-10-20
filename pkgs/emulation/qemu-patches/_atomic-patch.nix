# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "bef02942d600ef6e0c2b3678508e62dfbfc7dd066489c52a759a895d9810de40";
  subject = "crucible: complete RAM-worker literal dependencies";
  body = "Retain the complete Crucible integration on the sole pinned QEMU base.\nComplete only the RAM-worker component's literal Source, Native and\nthread dependency selections and their genuine existing fingerprint pins.\nPreserve every other source blob and mode.\n\nSelect the actual Source dispatch getter, Native hint, frame identity and\nCPU-pin return bodies in dependency order. Select the unchanged bounded\nRAM-pause helper before its real actor-pause caller. Keep actual identity,\nObject return, finalization, relock and bounded-record checks. Introduce no\nlist storage, empty census, scalar grant or accepting provider.\n\nRefresh the changed fixture's real Source pin and all six incoming literal\nedges to their actual fixed point. Seven values change across six existing\nmaps; retain all inventories, order, validators and non-map bytes. The\napproved graph remains eight maps, 167 edges and 130 inputs, with the\nseparate settle consumer yielding 175 edges and 132 inputs. Preserve every\nexisting assertion, causal mutation, limit, ABI, license and support policy.\n\nCanonical bounded-list storage and registration producers, actual QOM\nlinkage, symbol ownership and runtime controls still require the normal\nowning runner. No selected Source or CPU activation, Main/Original\nadmission, positive physical return, RCU, launched lifecycle or performance\nqualification is implied. Preserve their mandatory failures and gates.";
  commit = "6c982d259cad79b6f0ecfac8fe973f9a84ebef9a";
  tree = "c1f63b87e4a9d1e6cfa3953d57a67d8caf0d96db";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/ram-worker-helper-pins-v2";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "3729c9fbba71e7209077cf85008f13ce42b49ebd286dac3e198eb266c4e96082";
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
