# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "c632f74a99e481cd9bb2547e5b6111e64a23b38f5b29fe9bb0f10c268fe4bbde";
  subject = "plugins: retain startup custody and nested writer intervals";
  body = "Capture the complete startup Source, Native callback lifecycle, nominal\nregistration groups and receiving custody with their owning SDK surfaces.\nPreserve physical workspace backing and mapping ownership, setup exchange\ncount validation, and genuine declaration ownership across the configured\nSource and preexec producers. These physical holders do not issue operating\ndigest, whole-Park, standing or action authority.\n\nKeep workspace transfer on the existing public Runtime v3 nominal alias.\nDefine the absent-workspace unit provider after canonical Source storage,\nretaining its genuine prototype, output identity checks and 141 scenarios.\n\nReuse genuine enrolled CPU and IO writer intervals for nested cached stores.\nPromote outstanding nested writes before returning their enclosing admission,\nand preserve read-only close, foreign drain, alias and copied-custody guards.\nRegister 25 literal-body scenarios and ten targeted omission controls using\nthe configured compiler and explicit physical operand adapters.\n\nThe source remains inactive; complete operating and terminal joins are\nseparate. Include actual generator inputs and corresponding-source notices\nwithout claiming runtime performance or complete payment qualification.";
  commit = "ab97de831c930939a20d88fca873c5b6db68833e";
  tree = "652e811df2d31fa8f8542de3979f502f202317ac";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-cached-writer-cumulative";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "13cdcb48b43cae87be2190ef01a0308d9d63a49a3f9adcfc4aef4f544bfd24f0";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-15T04:44:51-07:00";

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
