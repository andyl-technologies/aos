# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "e79676347799aa5140a345061805609a1f80e0fe1ba9b7e7d9edda421783ba8f";
  subject = "Integrate Crucible retained native fingerprint pipeline";
  body = "Retain versioned Source, checkpoint, parent Park and resident Root\nintegration, callback Original validation, ordered Native disposition and\ncanonical registration cleanup. Preserve decoded standing fixture inputs,\nexisting controls, bounds, independent failure journals and per-file licenses.\n\nCarry three fixed Material cells and two Work cells through serial-checked\ncapture, pending, active and completed custody. Permit Main to return one\ncompleted Material while the actual worker owns another, retain born\nnegative results, and distinguish pending cancellation from physical byte\ncompletion. Retain exact return receipts, sticky close uncertainty and\ncontrol lifetime uncertainty through final destruction checks.\n\nCheck caller Ref and output spans against retained Source and workspace\nstorage before reading or writing them. Publish immutable standing identity\nonly during construction; runtime readers observe through local scratch.\nAmortize only repeated Material fstat under the matched module's borrowed-only\nno-close, no-dup, no-rebind and no-flag-change contract plus real Work and byte\npins. Preserve live standing, cancellation, clocks and Original observations.\n\nRefresh the genuine Source extraction closure and all affected direct and\ntransitive fingerprints. Preserve upstream attributes and the single signed\nintegration commit with only the pinned upstream base as parent. Native\nactivation, actual worker execution, concurrent lifecycle, complete provider\nbacking and measured performance remain separate qualification obligations.";
  commit = "7cc483e5a0ffdaef4a1b0e1393afa2088df4ed8b";
  tree = "8aef2d5ab0b074fa13c7222ddd6a8ef598115430";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-fingerprint-pipeline";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "092c8f6232490f45482866e102b857fe82a28786cd51f79728b628b05afd0f8f";
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
