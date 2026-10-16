# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "7f15c84b5f34dfcd194e81f2048d7912edffdcee7c8e099c70694e25595bce33";
  subject = "Integrate Crucible QEMU control and parent Park ownership";
  body = "Preserve the existing emulator, checkpoint, observation and plugin\nintegration together with its SDK exports, C++ template field and corrected\npreexec selector. Add the production two-phase parent Park request path\nwith retained original request, prepared Source and Monitor identities.\n\nKeep real Native admission, capture, page-rounded metadata accounting and\nphysical return under their owning subsystem barriers. Publish versioned\nSource terminal facts only after final Original and local identity return.\nExpose authenticated closed-request evidence after writer and retained\nMonitor release, and admit fresh authenticated requests only after complete\nprior local closure while preserving debit, replay and failure history.\nPublisher action-membership and process Source retirement remain separate\nowners.\n\nBind checked region equations to the exact public generated ABI33 header\nas an external include input: 768-byte node slots and a separate Park\nreturn journal. Document QAPI, callback and terminal contracts, the pinned\npermissive protocol input, and remaining owning marshalling, source-built\nlink, consumer and runtime qualification obligations.\n\nUse the current exported cancellation observer in candidate entry as well\nas the shared receiving paths, retaining independent cancellation identity\nchecks and retained metadata, uncertain-close and post-status journals.\n\nAllow actual owning storage to supply its strong sizeof getter alongside\nthe grouped unavailable Native operations. Only the passive absent-extent\nfallback is weak; operational identity, storage and gate providers remain\nstrong and unchanged, with no admission issued by storage observation.\n\nEmit the current standing3 framing in the purpose8 syntax fixture while\npreserving positive field checks and every existing malformed-record and\nlegacy-purpose refusal case. Production decoding accepts no old standing\nalias and the fixture supplies no issued purpose or effective contract.\n\nKeep configured literal-source extraction bound to the current exported\ncancellation observer, guarded Source fragments and actual Native request\nstorage. Update the standing fixture to its current schema while retaining\nall 68 Source roots, assertions, limits and causal omission controls.\n\nSource-built Python generation passes for all 41 existing products and all\n132 fingerprint bindings match. Owning compilation, compiled negative-case\nclassification and runtime qualification remain pending.";
  commit = "370189d531defc907a2be52a36e348a9f9bbd524";
  tree = "9812af53bc2b4e0dc4f7c332e1e49db784f8fee7";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/parent-park-purpose-integration";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "cddd8cac203191410c5055874e5dcb31fd4c64ad2ac0bf0f73119433ac8b36bb";
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
