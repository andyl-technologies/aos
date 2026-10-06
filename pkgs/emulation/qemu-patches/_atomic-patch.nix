# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "ba2ef7381c1b3bfd868bb65f2793b85be4a98c7d8af9f6fe7acf4a1d7cbb5556";
  subject = "Integrate deterministic execution and inline TCG page collections";
  body = "Keep small TCG invalidation page-lock sets in four caller-owned sorted\nentries. Create the tree only on the fifth distinct existing page and\ntransfer held and busy state into stable heap entries without releasing\nlocks. Retain discovery acquisition order, ascending retry and release,\nopposite-page deduplication, and precise-SMC cleanup before nonlocal exit.\n\nRetain versioned process control, exact virtual coordinates, independent\nchild resources, canonical guest-state projection and complete matching\nsource integration. Preserve stopped-owner generations, registered reader\nand callback custody, FIFO barriers, fault settlement and descriptor\nfailure refusal across snapshot, restore and retained fork operations.\n\nPreserve accelerator instance classification, cold continuation checks,\nempty fault-queue admission, active instruction-context observation,\ndirect register-rule presence, cached tick-mode admission and native\nmutex owner identity. Keep tracked waiter updates under the existing\nregistry guard, with unsigned wrap, underflow refusal, condition waiter\nidentity and retained fork transaction ordering unchanged.\n\nKeep ordinary RR event ordering and Sim flush fixed points. Preserve all\nguest accesses, invalidation ranges, PageDesc and TB membership, dirty\naccounting, callback order, replay clock observations and scheduling.\n\nExercise actual page collection, native fast invalidation, locked range\nhandling and native page removal with explicit providers. Compare exact\nbaseline lock traces for zero, missing, duplicate, boundary and spilled\nsets, including busy trylocks and precise-SMC nonlocal cleanup. Carry\ncausal controls for omitted pages, lost spill state, missing cleanup,\nreversed iteration, absent first-page admission and eager tree creation.\n\nExtend the system-mode x86 SMC regression with a shared first physical\npage and five distinct second pages, patches through both memberships,\nspilled current-TB cleanup and restored temporary mappings. Retain the\nstrict public prototypes and compiler macros in the native waiter proof.\n\nStrict source-built syntax checks pass for the prototype, baseline and\nall six mutations. The inline collection remains a prototype pending\nconfigured native execution, guest, replay and performance qualification.";
  commit = "1f935d63cef769d115d82467d4b7239649403e61";
  tree = "377d7b5c375e60dbfc2ab818c848cda977572c46";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/inline-tcg-page-collections";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "3d58960d8b9ba67d7a0e167abe005b8e922c2741039980ca4fbf1c244bb99414";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-03T07:08:17+00:00";

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
