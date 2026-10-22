# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "efa9bdd9dbf413dee2135e5d7d42f243148bcc5d6734da63e67a37053abdc11e";
  subject = "plugins: compose retained Source custody and checked physical RR returns";
  body = "Supply the cumulative Crucible Source and Native integration against the\npinned upstream QEMU base. Retain public process protocols separately from\nprivate in-process SDK interfaces and preserve every existing per-file license.\n\nRetain actual task, allocator, libc, TLS, placement, thread and backing charges;\nbounded journals and registries; control reader and publisher ownership;\nregistered callback, Ready and Main custody; native descriptors and groups;\nRAM resize, discard, mapping, retirement, getter and read-child lifetimes;\nclock, interrupt, register, translation and fault callback observations; and\ncanonical publisher codecs, preexec storage and byte validation.\n\nKeep exact installed Runtime, module, member, constructor and lender identity.\nRetain independent first, callback, post, attempted, consumed and uncertain\nfacts. Preserve Source group terminal receipts and actual descriptor/frame\nretirement before component return, followed by registration-owner retirement.\nDo not infer physical closure from a negative status or semantic expiry.\n\nPreserve the reader r2 completed-receipt handoff and enrolled Module storage,\nthe returning-only parent identity debt guards, all complete-journal and\ncanonical output-span exclusions, exact registered observation exceptions,\ncompleted registration posts, wrapper history and the process-wide Original\nborrower attempted restriction. Sequential borrower rearm remains unavailable.\n\nRetain metadata-only RR execution and terminal registration separately from\nactual owner birth. Preserve the permanent physical Core keeper, canonical\nholder move, uncertain reference custody and independent physical return posts.\nCompose corrected preexec RR observation and process-wide sticky refusal with\nthe genuine Source recipient reciprocal and retained Source/Native actor state.\nNo replacement provider or accepting issuer fixture is introduced.\n\nRecord real callback and executor paths, partial return, allocation-link\nconsumption, checked QOM reference return, separate terminal-tail enrollment\nand Native reciprocal facts. Keep normal, longjmp and atomic unwinding\nindependent of factual recording. Do not consult returned payloads after their\nphysical last use or erase consumption after a fallible independent post.\n\nActual complete Source storage is 253240 bytes; 31 genuine fixed-floor getters\nadd 44750 bytes, for a 297990-byte floor. Actor4680 and tail registration120\nare embedded in Source; the separate Native RR journal is408. CPU allocation\nheader888, CPUState16992, Core160 and permanent keeper72 are measured physical\nextents. Corrected preexec owner212752/storage26640 preserve their own debit.\n\nRetain original component cases, causal classifiers, assertions, commands and\nresource limits. Preserve bounded independent helper scheduling, the aggregate\ntwo-compiler ceiling, exact metadata authentication and the unchanged normal\ndelivery deadline. Keep each failed first attempt and distinguish owning,\nstandalone, physical and whole-provider evidence under executed source hashes.\nDo not relabel historic normal/full-cohort samples as new measurements.\n\nThe actual actor birth remains unwired and selected CPU admission returns\nENOTSUP. No genuine external Module/Core typed operation, selected activation,\npaid reader execution, semantic RR positive or sequential borrower reuse is\nqualified. Blocking Source/Native locks leave nonwaiting terminal cleanup open;\nclass-six quiescence and persistent semantic Outcome cleanup remain separate.\nPreserve the mandatory genuine dirty-lifecycle refusal.";
  commit = "5b7be4763f681e1e0237b61b24708654a510225f";
  tree = "a152cc6c0a224af19762436e7432ea86636f9225";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/crucible-preexec-rr-actor-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "623c38f84b6c1f4378ce5ad840e7e20e88e0b34fac4a504b9b16f1a25803a6c9";
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
