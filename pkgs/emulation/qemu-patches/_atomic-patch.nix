# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "6359ab47150593ab0d5594165ce46704cfab077418bbd964a212a0be2dfd1a23";
  subject = "Integrate deterministic execution and inline TCG page collections";
  body = "Keep small TCG invalidation page-lock sets in four caller-owned sorted\nentries. Create the tree only on the fifth distinct existing page and\ntransfer held and busy state into stable heap entries without releasing\nlocks. Retain discovery acquisition order, ascending retry and release,\nopposite-page deduplication, and precise-SMC cleanup before nonlocal exit.\n\nRetain versioned process control, exact virtual coordinates, independent\nchild resources, canonical guest-state projection and complete matching\nsource integration. Preserve stopped-owner generations, registered reader\nand callback custody, FIFO barriers, fault settlement and descriptor\nfailure refusal across snapshot, restore and retained fork operations.\n\nPreserve accelerator instance classification, cold continuation checks,\nempty fault-queue admission, active instruction-context observation,\ndirect register-rule presence, cached tick-mode admission and native\nmutex owner identity. Keep tracked waiter updates under the existing\nregistry guard, with unsigned wrap, underflow refusal, condition waiter\nidentity and retained fork transaction ordering unchanged.\n\nKeep ordinary RR event ordering and Sim flush fixed points. Preserve all\nguest accesses, invalidation ranges, PageDesc and TB membership, dirty\naccounting, callback order, replay clock observations and scheduling.\n\nExercise actual page collection, native fast invalidation, locked range\nhandling and native page removal with explicit providers. Compare exact\nbaseline lock traces for zero, missing, duplicate, boundary and spilled\nsets, including busy trylocks and precise-SMC nonlocal cleanup. Carry\ncausal controls for omitted pages, lost spill state, missing cleanup,\nreversed iteration, absent first-page admission and eager tree creation.\n\nExtend the system-mode x86 SMC regression with a shared first physical\npage and five distinct second pages, patches through both memberships,\nspilled current-TB cleanup and restored temporary mappings. Retain the\nstrict public prototypes and compiler macros in the native waiter proof.\n\nStrict source-built syntax checks pass for the prototype, baseline and\nall six mutations. The inline collection remains a prototype pending\nconfigured native execution, guest, replay and performance qualification.\n\nKeep a page-locked derived count of recorded TB memberships requiring a\nsecond distinct physical page. Skip only the preliminary lock-discovery\nwalk when that count is zero after acquiring the page lock. Preserve\nnonzero and unknown traversal, retry ordering and actual invalidation.\nSaturate at UINT32_MAX, retain unknown until the list is empty or fully\ncleared, and update only insertion, successful tagged unlink and full flush.\nKeep physical aliases at zero and invalid retained memberships counted.\n\nExtract native insertion, duplicate-QHT rollback, hash invalidation and\nrecursive list-clear bodies into focused proofs. Verify both list tags,\nmixed lists, final crossing removal, sticky saturation, empty and flush\nrecovery, retry after a competing membership change, precise-SMC cleanup\nand retained process fork copies. Strict source-built compilation and\nexecution pass. Seven causal controls fail runtime native assertions;\nsealed-baseline collection stdout matches exactly. Guest SMC, MTTCG,\nreplay and performance remain unqualified for this prototype.\n\nPlace the crossing count directly after QemuSpin, before the tagged list\nhead. The extracted native QemuSpin and PageDesc definitions measured with\nthe source-built 64-bit compiler retain the baseline 16-byte descriptor,\nusing the existing four-byte padding rather than enlarging it to 24 bytes.\nThis layout probe is not a full configured QEMU compilation. The same nine\nfocused proof cases pass after the layout correction.";
  commit = "79a6ab2419c6bd4f1c8e44a23a43c171b9a3fd22";
  tree = "0bb49a2b3855c2b47f519b78da1450a4ec9b40d8";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/page-crossing-membership-count";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "416138affa9e0539475c9ee968530e1d4a82cca0aff57507ad079f3573371eca";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-06T22:17:47-07:00";

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
