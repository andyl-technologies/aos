# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "2a26034ffa4829d3cc52ce929d8573874975bf8a4af9e73301a01433af039a56";
  subject = "Complete standalone cached-writer disposition declarations";
  body = "Retain the complete reviewed Crucible source integration, including the native\nfingerprint pipeline, required workers, readiness closing disposition, physical\nreturn journals, literal Source dependencies, selector component and exec-only\nOpenRISC importer correction. Preserve source licenses, upstream attributes,\nall existing assertions, controls, bounds and mandatory qualification gates.\n\nThe standalone cached-writer fixture copies QemuThreadRamPauseTransaction from\nthe real thread header. Its new end field embeds QemuRamPauseEndDisposition by\nvalue, so select that real typedef before the containing transaction. The\nshared assembly prefix supplies the normal fixture and all ten omission\nvariants without inventing a layout or changing their bodies or assertions.\nThe owning thread header is already pinned and tracked by the existing Meson\ninputs; the extractor itself is the command-file regeneration dependency.\nOther direct clients already include the real owning header before use.\n\nThis is the exact reviewed two-line source correction atop the prior signed\nsource tree, repackaged with only the pinned upstream base as parent. No further\nproduction or dependency changes are included. Source-only audits preserve\nall 147 declared hash edges, 117 distinct inputs and exact Source/Meson scope.\nNo generator, model, build or execution test was run for this successor; the\nreported missing-type compile failure is addressed in source but compilation\nhas not been rerun or claimed successful here.\n\nLocal source integrity does not establish provider, runtime, lifecycle,\nactivation or performance qualification. Earlier Source-unit evidence reached\n118 PASS before incomplete genuine reserve_v7 role/provider rosters refused\nwith EINVAL. Those original assertions and unresolved failure remain. Complete\nworker funding, allocator/TLS/TSD cleanup, real native census/disposition and\nmatched module construction, readiness overlap, handoff, close, join and\nphysical identity return remain unjoined. No accepting provider, capacity\ndonation, legacy adapter, success substitute or test waiver is added.\n\nThe mandatory genuine launched capture lifecycle still fails explicitly after\ncomponent evidence. Actual Source/Root ownership, cursor/read/refusal,\nOriginal-post, rearm, ACK, sticky failure and physical cleanup remain required.\nAuthored component detectors and source review cannot satisfy those gates.\nPreserve actual physical-end reentry, returned effect/post/unlock journals and\nnegative-history terminalization obligations for genuine lifecycle execution.";
  commit = "31cf681571259f53f363ce7550d4db0a00d89841";
  tree = "7f450458d2c53d9b73b24479ae75c842706c54d6";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/standalone-disposition-header-integration";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "22339824a97d9f67c6ec5380581f9c7223ab849e26ef51bb70d2dd1775af2011";
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
