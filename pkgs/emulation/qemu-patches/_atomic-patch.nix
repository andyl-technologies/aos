# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "a401b492ccec230325c4e7a66ce694422e872e92a16a1cfbc9afaeaa325af90d";
  subject = "plugins: compose bounded physical custody, fork quiescence and service metadata";
  body = "Supply the cumulative Crucible Source and Native changes against the pinned\nupstream QEMU base. Keep public process protocols separate from private\nin-process interfaces and preserve the applicable per-file licenses.\n\nRetain allocator, task, libc, TLS, placement, thread, backing and static charges;\nbounded journals and registries; control reader and publisher ownership;\nregistered callback, Ready and Main custody; native descriptors and groups;\nRAM resize, discard, mapping, retirement, getter and read-child lifetimes;\nclock, interrupt, register, translation and fault observations; and canonical\npublisher codecs, preexec storage and byte validation.\n\nKeep exact Runtime, module, member, constructor and lender identity. Preserve\nindependent first, callback, post, attempted, consumed and uncertain facts.\nRequire actual descriptor/frame retirement and Source group terminal receipts\nbefore component return, then registration-owner retirement. Negative status\nand semantic expiry do not establish physical closure.\n\nPreserve the reader r2 completed-receipt handoff, enrolled Module storage,\nreturning-only parent identity debt guards, complete-journal exclusions,\ncanonical output spans, exact observation exceptions and wrapper history.\nKeep the process-wide Original borrower attempted restriction; sequential\nborrower rearm remains unavailable.\n\nRetain metadata-only RR execution and terminal registrations separately from\nowner birth. Keep the permanent physical Core keeper, canonical holder move,\nuncertain reference custody and independent physical return posts. Compose\ncorrected preexec RR sticky refusal with the genuine Source recipient leaf,\nretained Source/Native actor journals, partial returns and terminal-tail facts.\nKeep executor unwinding separate from factual recording and never erase\nconsumption after an independently failing post.\n\nRecord bounded Source/Native terminal metadata sections without waiting for\ncontended target or registry locks. Retain separate attempted/returned posts\nand uncertain debt. Order ordinary atfork registry quiescence after the RCU\nlocks and release it before child RCU thread recreation; preserve the explicit\nretained hot-fork transaction and ordinary mutex behavior.\n\nJoin the inline physical resource bank and exact constructor loan. Preserve\nschema-two Setup7/plan10 transport parsing and refusal before Source\npublication. Add the physical installing-service v5 view for that exact\nprofile while retaining old v4 and member-profile restrictions. Require all\nindependent Original registration post-attempt and return facts before\nacquisition; default zero statuses are insufficient.\n\nThe complete linked Source measures 254024 bytes. Thirty-one genuine static\ngetters add 44774 bytes, giving a 298798-byte fixed floor. Source actor5256,\nservice296, Original registration72 and bank168 are embedded terms. Native\nRR432, external Main-finish96, Core160 including keeper72, CPUState16992 and\nallocation header888 are independently measured extents. Preexec owner212752\nand storage26640 retain their complete debit. Reader journals remain\n128/112/240/160 bytes; the physical v5 view is72 bytes.\n\nPreserve original cases, assertions, causal classifiers and resource limits,\nbounded independent helper scheduling, the two-compiler ceiling, authenticated\nmetadata loading and the normal delivery deadline. Retain first failures and\nidentify executed sources, changed dependency closures and standalone controls\nseparately from historical full-cohort or normal-entry samples.\n\nCPU admission remains ENOTSUP. No genuine Module/Core semantic issuer, selected\nactivation, populated reader or RR operation, sequential borrower rearm or\nend-to-end nonwaiting terminal cleanup is qualified. Preserve the mandatory\ngenuine dirty-lifecycle refusal and all remaining semantic cleanup boundaries.";
  commit = "ec33e02897fe424523e1dc755ae0f3f651fdb22c";
  tree = "12361245265446cff084677143e44d3394f6b8c5";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/crucible-nonwaiting-bank-service-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "453cafe08bbe1fe12940e1035250d6ccd73c3aa93331170b305e2b8898e539ab";
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
