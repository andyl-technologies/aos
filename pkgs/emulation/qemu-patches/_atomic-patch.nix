# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "97460c40943302b664af2d5c9c0b270a52265abd4d0afdb2cb40031c491a469e";
  subject = "crucible: retain RAM metadata return custody";
  body = "Retain the complete Crucible integration on the sole pinned upstream base.\nBind actual RAM metadata births to the retained Source payer, process,\naccount and partition. Move real receipts into the two existing inventory\nrows and paid intrusive dirty-header ownership before publication. Replace\nall four void retirement losses with canonical status-bearing journals,\nnonreplayable physical effects and retry-only completed-debt settlement.\n\nUse a private flexible inventory with exact small-VM capacity, the existing\n4096 maximum, checked geometry and stable paid merge-sort workspace. Keep\nordered block refusals, MR references and topology checks. Resume only\nactual grace-complete dirty headers through a captured finite horizon;\nretain arbitrary outstanding generations without another cap or requeue.\n\nSeparate consumed projections, returned physical effects and settled debt\nat capture, publication and logical cleanup terminals. Retain cleanup-only\ntickets, protect Main MR callouts from CPU actors, and refuse active-effect\nor cleanup reentry without replaying ACK, Original or end callbacks.\nPreserve valid RR+BQL eligibility, live checks, SDK80, physical ABI, failure\ncontrols, experimental support policy and per-file licenses.\n\nRetain complete literal Native/MR dependencies and genuine QOM finalizers in\nthe component fixture. Refresh all seven fingerprint maps to their actual\ndependency fixed point and match the owning Source Meson inputs. The ten\nadded cleanup controls and invalid-capacity replacement pass under explicit\nmodeled retained inputs. Production syntax and fixture compile/link checks\npass; the full Source fixture still refuses required-role registration.\nSource activation, positive RCU execution, launched capture lifecycle and\nperformance remain unqualified. Preserve their mandatory failures and gates.";
  commit = "64e15551afefa730e3919aa4c63dd3d1139637e4";
  tree = "4cd514b03f2551e906a0236cdf82cd6858926ae8";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/ram-metadata-return-v1";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "5d910f1d0f236547cd22a2d925debaa7c2dae52ddf4833532753af949e2cfe72";
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
