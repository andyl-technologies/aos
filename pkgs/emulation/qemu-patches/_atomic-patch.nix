# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "f1ef214cdefe01062bdaf0437e98906a517528e36b2591b0dec0277b7bed34f3";
  subject = "plugins: retain startup custody and complete ordinary providers";
  body = "Capture the complete startup Source, Native callback lifecycle, nominal\nregistration groups and receiving custody with their owning SDK surfaces.\nPreserve physical workspace backing and mapping ownership, setup exchange\ncount validation, and genuine declaration ownership across the configured\nSource and preexec producers. These physical holders do not issue operating\ndigest, whole-Park, standing or action authority.\n\nKeep workspace transfer on the existing public Runtime v3 nominal alias.\nDefine the absent-workspace unit provider after canonical Source storage,\nretaining its genuine prototype, output identity checks and 141 scenarios.\n\nReuse genuine enrolled CPU and IO writer intervals for nested cached stores.\nPromote outstanding nested writes before returning their enclosing admission,\nand preserve read-only close, foreign drain, alias and copied-custody guards.\nRegister 25 literal-body scenarios and ten targeted omission controls using\nthe configured compiler and explicit physical operand adapters.\n\nKeep the regression operand scaffolding in readable structs, function blocks\nand primitive macros while preserving token behavior and exact test outcomes.\n\nComplete ordinary negative QMP writer allocation/observation and string\nappend/prepend/erase providers without issuing selected Source custody or\nchanging the generic GLib visitor and JSON writer paths.\n\nRebind the genuine unit and preexec extraction guards to these complete\nprovider inputs while preserving selected bodies and registered scenarios.\n\nThe source remains inactive; complete operating and terminal joins are\nseparate. Include actual generator inputs and corresponding-source notices\nwithout claiming runtime performance or complete payment qualification.";
  commit = "3b602e38e51605944f3b9ed7f6c253b055090a17";
  tree = "b50cfcbd0cc7d745ff59663c875dcc7ff8f4855e";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/qmp-negative-cumulative";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "2f83b0678a1d1a3d603a0673a7412b26eb4011f7928702d7448be7c94500e607";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-15T06:27:26-07:00";

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
