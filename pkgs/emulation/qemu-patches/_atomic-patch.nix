# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "51633afcd990b54c290f4d251263d6dfecc7730718df38637150d52a958d0814";
  subject = "Integrate deterministic execution and private fork I/O custody";
  body = "Retain versioned process control, deterministic virtual coordinates,\nprivate child resources, and canonical guest-state projection. Drain\nthe original registered reader and native callback before admitting\ntemplate barriers. Preserve stopped-owner generation, exact time,\nconnection lifetime, and descriptor failure refusal.\n\nEnd an admitted current-CPU stop at the TCG chain while retaining the\nasynchronous runstate transition. Reconstruct each child's private\nLinux epoll backend under the original authenticated fork barrier,\npreserving active and standby modes and the parent's kernel object.\nValidate retained handler membership and inherited descriptor identity\nbefore starting child workers.\n\nObserve stop admission, publication, rearm refusal, and original wake\nreader outcomes only under the existing delivery trace opt-in. Keep\nunowned architecture and unlocked runstate fields unavailable, retain\nlate generations, and preserve native operation and error semantics.\nCarry production-body regressions and explicit causal negatives.\nDeclare extracted public entry points with their original types so\nconfigured prototype diagnostics remain enforced in the fork fixture.\n\nTransfer an outstanding running-owner control request at genuine stopped\npublication to the existing paused owner. Preserve the original request\ncounters, stop-clearing rearm, flush and callback ownership checks.\nExercise reader-before-publication and reader-after-publication ordering,\nno-request behavior, and nested next-generation exactly-once completion.\n\nPreserve plugin fatal shutdown as a failed process exit through the normal\nrunstate path, while retaining clean quit and the original vCPU kick.";
  commit = "4f3db5e70c9d0a166d4f966e8838872c2e279304";
  tree = "c3808f77cbff0dd7adb1a7c58ea73e0c10577806";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-plugin-failed-exit";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "ce5591b4e7493cb1607fe2eddf18c0ea50e79b1a65e3699b1cb084128638e95e";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-06T00:36:41+00:00";

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
