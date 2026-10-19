# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "3197c7e44c3bb6a98328a32e078226ea7f284b1b971c99f53934013057391d5c";
  subject = "Integrate Crucible ownership and literal cleanup controls";
  body = "Retain Source, checkpoint, parent Park and resident Root integration with\nversioned transport, physical custody journals and paid fixed storage.\nPreserve callback Original checks and ordered Native census disposition.\n\nKeep the canonical registration owner and its sole child pin held while\nNative proves terminal registration custody. Close admissions permanently,\nserialize return on the existing child latch, and release the Source mutex\nbefore Native revoke, current and terminal calls. Revalidate the exact held\nowner before consuming its holder and pin; preserve same-owner continuation\non refusal. Later child cleanup reobserves physical registry facts without\nquerying the consumed owner or resetting native_prepared.\n\nAuthenticate the Source-selected registry and held owner outside Native's\nmutex. Check every canonical group, member and legacy record, distinguish\nprepared-only and failed-before-binding attempts from registered history,\nand retain real module, descriptor, frame and borrower obligations.\n\nCompose the complete unchanged descriptor-terminal and module-release\nclosure into the registered Source fixture, including loader retirement\nbranches and its CFI annotation. Keep unavailable CPU and TCG endpoints\nfatal. Add actual descriptor placement and module-user return controls over\nexplicit modeled retained inputs. Corroborate cleanup account geometry\nwith the same decoded standing record. Preserve every existing assertion\nand bound, and refresh the unchanged literal-source fingerprint inventory.\n\nThe signed atomic commit has only the pinned upstream source base as parent.\nCompilation and runtime qualification remain separate. These component\ncontrols do not qualify initial Source activation, retirement scheduling,\nphysical destructor/free, launched VM lifecycle, an actor Original producer\nor a fork/thread transaction.";
  commit = "3f8b4b8e36f599259b00092cb0c6067b2ae57b16";
  tree = "883f7ac866056a01db372342feaf51bb0089c632";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/cleanup-fixture-linkage";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "fe77fa79e7ea1bc791eaac4a083e614dbf8cbc6b61ed3438fdd11db627e8d28f";
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
