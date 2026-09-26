# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "91e76eb180eeace408af67bfe87072261207e18f396ea519558c71a2753c38b8";
  subject = "crucible: integrate deterministic QEMU execution";
  body = builtins.concatStringsSep "\n" [
    "Integrate Crucible's versioned GPL-side plugin protocol, exact checkpoint,"
    "retained hot fork, fault models, and device fingerprints as one atomic,"
    "reconstructible QEMU 11.1.1 source artifact."
    ""
    "Store converted QEMU_CLOCK_VIRTUAL deadlines internally in picoseconds"
    "for deterministic sim and ordinary TCG. Preserve generic TCG's long timer"
    "horizon, carry exact ns-plus-phase device state through migration, and"
    "ceil-project that state when crossing to a non-TCG accelerator."
    ""
    "Model sim at 50 ps per retired instruction and carry exact phase through"
    "CPU budgeting, idle advance, fingerprints, fault events and results."
    "Project an authenticated 4 GHz x86 TSC and retain calendar clock epochs."
    ""
    "Reject malformed clock state and active PPC PMU migration before guest"
    "continuation. Preserve inactive and instruction-only PMU migration,"
    "ordinary-QEMU compatibility, and the GPL/Apache process boundary."
  ];
  commit = "ea82c841a85f07021cab97915e03ce92cecad029";
  tree = "ff221d70aeaf70e7e5fdfefbfa39fd53abb83c42";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "crucible/qemu-11.1.1";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "4830f762a3fdb5007a5e680692b04f9acf79061c8211fe3be6dcf82abc07c7c2";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";

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
