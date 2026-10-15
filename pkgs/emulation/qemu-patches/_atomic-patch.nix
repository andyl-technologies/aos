# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "db95cf5ec6f028f501add7f0c32ae0b27761d65fef2ac54641a5c65505576807";
  subject = "plugins: retain startup custody and nested writer intervals";
  body = "Capture the complete startup Source, Native callback lifecycle, nominal\nregistration groups and receiving custody with their owning SDK surfaces.\nPreserve physical workspace backing and mapping ownership, setup exchange\ncount validation, and genuine declaration ownership across the configured\nSource and preexec producers. These physical holders do not issue operating\ndigest, whole-Park, standing or action authority.\n\nKeep workspace transfer on the existing public Runtime v3 nominal alias.\nDefine the absent-workspace unit provider after canonical Source storage,\nretaining its genuine prototype, output identity checks and 141 scenarios.\n\nReuse genuine enrolled CPU and IO writer intervals for nested cached stores.\nPromote outstanding nested writes before returning their enclosing admission,\nand preserve read-only close, foreign drain, alias and copied-custody guards.\nRegister 25 literal-body scenarios and ten targeted omission controls using\nthe configured compiler and explicit physical operand adapters.\n\nKeep the regression operand scaffolding in readable structs, function blocks\nand primitive macros while preserving token behavior and exact test outcomes.\n\nThe source remains inactive; complete operating and terminal joins are\nseparate. Include actual generator inputs and corresponding-source notices\nwithout claiming runtime performance or complete payment qualification.";
  commit = "2c946782538467b1c98770e32988412b65c8b903";
  tree = "6f342d113bcb02e7b9cc111538276e1d483f86a3";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-cached-writer-message";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "2459856af4dc3d68f0b1694cb3658e147e14db403d5197f488b3eefb35ef1bad";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-15T05:00:45-07:00";

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
