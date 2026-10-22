# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "0e6b106a46b7698f2c30a3cf30e51832dcecd6b6020ebf19ca8d936ad53815f5";
  subject = "plugins: compose physical stack, member and cleanup provider custody";
  body = "Supply the cumulative Crucible Source and Native changes against the pinned\nupstream QEMU base. Preserve public process protocols, private in-process\ninterfaces, complete corresponding source and applicable per-file licenses.\n\nRetain allocator, task, libc, TLS, placement, thread, backing and static charges;\nbounded journals and registries; control reader and publisher ownership;\nregistered callback, Ready and Main custody; native descriptors and groups;\nRAM resize, discard, mapping, retirement, getter and read-child lifetimes;\nclock, interrupt, register, translation and fault observations; and canonical\npublisher codecs, preexec storage and byte validation.\n\nKeep exact Runtime, module, member, constructor and lender identity. Preserve\nindependent first, callback, post, attempted, consumed and uncertain facts.\nRequire descriptor/frame retirement and Source group terminal receipts before\ncomponent return, followed by registration-owner retirement. Neither negative\nstatus nor semantic expiry establishes physical closure.\n\nPreserve the reader r2 completed-receipt handoff and enrolled Module storage,\nreturning-only parent identity debt guards, complete-journal exclusions,\ncanonical output spans, exact observation exceptions and wrapper history.\nRetain the process-wide Original borrower attempted restriction; sequential\nborrower rearm remains unavailable.\n\nKeep metadata-only RR execution and terminal registration distinct from owner\nbirth. Retain the permanent physical Core keeper, canonical holder movement,\nuncertain reference custody and independent physical return posts. Join the\ncorrected preexec RR sticky refusal with the genuine Source recipient leaf,\nretained Source/Native actor journals, partial returns and terminal-tail facts.\nKeep physical executor recording separate from unwind and semantic cleanup.\n\nPreserve bounded Source/Native metadata sections and their independent posts\nwithout waiting for contended registry or target locks. Order ordinary atfork\nregistry quiescence after RCU locks and release it before child RCU thread\nrecreation, preserving the retained hot-fork transaction and ordinary mutexes.\n\nRetain the inline physical resource bank and constructor loan, all independent\nOriginal registration post-attempt and return facts, and the physical v5\ninstalling-service view. Add strict schema-two role codecs and matched v7\nmembership for Setup7/plan10, preserving all earlier edition restrictions.\nRetain physical pre-CAS reservation and known-no-acquire return debt. Return\nthe exact first suspension refusal before later callbacks or posts when\nadmission never entered.\n\nAdd Setup8/plan11 stack-purpose decoding and factual Main limit observations.\nThis edition remains header-only and refuses other observations. Parsing,\nwire fields and physical receipts provide no stack, thread, mapping or typed\nSource-role issuer. Preserve the signed stack proposal separately from any\nfuture implementation.\n\nRebuild genuine configured Source providers inside the cleanup component\nchecks, retaining ordinary child-null behavior and foreign-child refusal.\nKeep exact production bodies, all original cases and assertions, independent\ncausal omissions and intended assertion diagnostics. Authenticate every\nselected input and include actual preexec dependency fragments in Meson.\nDeclare the same 27-TU component provider closure as an explicit configured\nbuild output before the normal delivery deadline. Authenticate its compiler,\ncommands, environment, actual source/generated dependencies, utility members\nand object bytes before each compile/link. Authenticate the exact linked case\nbinary on execution without rereading provider inputs it does not consume;\npreserve the fresh standalone rebuild. Bind the compiler driver/specs and\nwrapper interpreter, capture compiler-injected environment inputs and refuse\nunsupported process-loader overrides. Retain the actual Native RR overlap\nrecord and member/service identity dependency bodies in delivery fixtures.\nStart longer independent helper suites first within the same two-worker pool,\njoining before the architecture phase. Correct legacy decoder omission selectors inside schema dispatch and preserve both\nbranches. Preserve helper scheduling, the aggregate two-compiler ceiling,\nmetadata validation and original time and memory limits.\n\nThe complete linked Source measures 254040 bytes. Thirty-one actual getters\nadd 44774 bytes, giving a 298814-byte fixed floor. Embedded Source actor 5256,\nOriginal registration 72 and bank 168 remain fully priced. Native RR 432,\nexternal Main-finish 96, Core 160 including keeper 72, CPUState 16992 and\nallocation header 888 retain their measured extents. Both architecture\ncompilers measure preexec owner 215160, storage 27992, session 17288,\nrecipient 3432 and role 80. Reader journals remain 128/112/240/160 and the\nphysical v5 view is 72 bytes.\n\nRetain all failed attempts and distinguish changed configured dependency\nclosure, genuine links, component controls and exact fixture equivalence from\nhistorical normal-delivery and whole 1918-object timings. CPU admission remains\nENOTSUP. No genuine Module/Core semantic issuer, populated reader or RR\noperation, selected activation, sequential borrower rearm or end-to-end\nnonwaiting cleanup is qualified. Preserve the mandatory genuine dirty\nlifecycle refusal and every remaining semantic cleanup boundary.";
  commit = "d1c072e9848e2c06f8d25272e1ae063b65deca61";
  tree = "79cdafeec4443b7315848ca393601a2f8d6b4250";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/crucible-stack-member-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "dec7c052017c2c2c5edf34efcf2946d2d6859aed897916ad3801d91cf880f6a0";
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
