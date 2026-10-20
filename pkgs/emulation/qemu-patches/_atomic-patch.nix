# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "3eb7d00d55544d87191f041c4356d83c55ead4b60c9956eda2bc564ca82dd983";
  subject = "crucible: retain native metadata admission custody";
  body = "Retain the complete reviewed Crucible source, including the native\nfingerprint pipeline, required worker lifetimes, bounded registry enrollment,\nfactual CPU custody, typed physical return and existing selector, Source\nextraction and OpenRISC changes. Preserve upstream attributes and per-file\nlicenses. Keep the pinned upstream base as this checkpoint's sole parent.\n\nPublish each actual native metadata receipt before its independent post.\nRetain raw operation and post results separately, including an owned pre or\ndebit refusal. Prepay canonical Source allocation cells in the actual fixed\nfloor, then move custody only after real allocation and complete conserving\ntransfer. Keep worker residual and stack debits on their actual inline owners,\nand retain dirty bitmap process lifetime independently of header retirement.\n\nCorroborate the published native creator before module publication; require\nmodule publication and actual BQL for runtime state. Preserve the genuine\nentered construction Original before Setup fallback, including pre-module\nBoot construction. Authenticate retained custody before return identity and\nactual creator TID before any phase mutation, then retain real QemuThread and\ncomplete-transfer checks. Do not add task credit, caps, clocks or providers.\n\nPreserve the typed bounded-thread pause-end assertions and the genuine CPU\nallocation receipt geometry wrappers in the storage extraction tuple. Refresh\nall six known extractor hash maps and actual Source Meson dependencies. Keep\npublic SDK80 and physical ABI unchanged. Added negative and overlap component\ncontrols use actual pthread and allocation effects under disclosed fixtures;\nnone issues launched Source or provider authority.\n\nThis checkpoint has not been generated, built, linked or tested here. It is\nlocal source integrity only, with no runtime, provider, accounting, activation,\nfork or lifecycle qualification. Genuine role/module/provider enrollment,\nallocator/TLS/TSD/census and real construction/RR/Receiving overlap remain\nrequired. Retirement local-copy receipt loss is a required next cohort.\n\nPreserve the incomplete required-role fixture refusal and the mandatory\nlaunched capture lifecycle failure. Actual Original/post, rearm, cursor/refusal,\nlogical ACK, sticky failure and retained physical cleanup obligations remain.\nNo assertion, failure, support or preinit gate is waived by this checkpoint.";
  commit = "d55cfbd8f71af6eee1666335640030e4f8de7a16";
  tree = "c32e0cbfd89939b43e391302ad4effeca4ed4f52";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-charge-custody-union";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "d34a1f6a2d3cd1e3bd381f80e91ea033d844ffc0dea62bea1c14971826c183d8";
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
