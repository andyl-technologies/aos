# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "4e06a4517ca2d66ff8cf92c221d941d09d9c3c88ed817ed70a6d408226f75d02";
  subject = "Integrate Crucible native pipeline and exec-only OpenRISC importer spawn";
  body = "Retain versioned Source, checkpoint, parent Park and resident Root\nintegration, callback Original validation, ordered Native disposition and\ncanonical registration cleanup. Preserve standing fixture inputs, existing\ncontrols, bounds, independent failure journals and per-file licenses.\n\nCarry fixed Material and Work cells through serial-checked capture, pending,\nactive and completed custody. Retain cancellation, physical byte completion,\nreturn receipts, sticky close uncertainty and control lifetime uncertainty.\nCheck caller Ref and output spans before access and preserve standing identity,\nworkspace storage, worker ownership and live Original observations.\n\nKeep the genuine Source extraction closure and its direct and transitive\nfingerprints. Preserve upstream attributes and retain only the pinned upstream\nbase as the parent of this complete-source integration commit.\n\nBracket the standalone OpenRISC clock fixture's synchronous exec-only importer\nspawn with the existing balanced RCU atfork disable and enable API. Restore\nparent fork support before asserting the actual spawn result, including the\nfailure path. The new executable initializes its own RCU state; rebuilding an\ninherited worker before exec can wait on copied process-private locks.\nPreserve all arguments, output capture, assertions, vectors and test limits.\n\nThis source integration does not establish native activation, actual worker\nexecution, concurrent lifecycle, complete provider backing or performance.\nBuilds and execution tests remain unrun.";
  commit = "ceee01b060bbdfe90b3710ae04cefaafefd63c80";
  tree = "330024fcccfbb1fc245d8c95558fb0eb2b563088";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/openrisc-exec-spawn";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "7906a9cbbf02d407fc54a68b53976461b0127396506eb90fa6195b64eebc965e";
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
