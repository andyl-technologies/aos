# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "be83fc1b580c3756eca103827e500d35145f52873a2207d3c11e399b2bfa4510";
  subject = "Integrate deterministic execution and private fork I/O custody";
  body = "Retain versioned process control, deterministic virtual coordinates,\nprivate child resources, and canonical guest-state projection. Drain\nthe original registered reader and native callback before admitting\ntemplate barriers. Preserve stopped-owner generation, exact time,\nconnection lifetime, and descriptor failure refusal.\n\nEnd an admitted current-CPU stop at the TCG chain while retaining the\nasynchronous runstate transition. Reconstruct each child's private\nLinux epoll backend under the original authenticated fork barrier,\npreserving active and standby modes and the parent's kernel object.\nValidate retained handler membership and inherited descriptor identity\nbefore starting child workers.\n\nObserve stop admission, publication, rearm refusal, and original wake\nreader outcomes only under the existing delivery trace opt-in. Keep\nunowned architecture and unlocked runstate fields unavailable, retain\nlate generations, and preserve native operation and error semantics.\nCarry production-body regressions and explicit causal negatives.\nDeclare extracted public entry points with their original types so\nconfigured prototype diagnostics remain enforced in the fork fixture.\n\nTransfer an outstanding running-owner control request at genuine stopped\npublication to the existing paused owner. Preserve the original request\ncounters, stop-clearing rearm, flush and callback ownership checks.\nExercise reader-before-publication and reader-after-publication ordering,\nno-request behavior, and nested next-generation exactly-once completion.\n\nAvoid empty fault-queue mutex and clock work with an atomically published\npending count, retaining lifecycle and custom deadlines. Observe instruction\ncompletion icount only after finding an active execution context. Exercise\nproduction queue transitions, restored counts, cross-thread publication,\nactive completion/exception semantics, and causal negative controls.\n\nCache tracked Linux mutex owner thread IDs after their first observation.\nSuspend the cache across fork callback ordering, retain uncached fallback,\nand refresh native child ownership before registry reconstruction. Verify\nreal worker/fork IDs, earlier RCU child callbacks, parent stability,\nregistration failure, syscall-free steady tracking, and causal negatives.\n\nCheck snapshot continuation before consulting the accelerator quantum.\nAvoid accelerator identity lookups on cold TB paths while retaining the\npredicate result, active continuation, RR cursor and TB semantics.\nExercise production genesis, resume, selection and VMState post-load\nbodies, exhaustive predicate cases, and the reversed-order negative.\n\nClassify the current accelerator instance once before publication and its\ninitialization callback. Preserve exact sim display name matching, independent\nfailed-init retries, nameless and early startup false results, reset and restore\nidentity, fork inheritance, diagnostic names, and predicate operand order.\nUse the instance classification on icount, RR and fault mode predicates without\nchanging timer effects, execution counts, scheduling or BQL fences. Exercise\nproduction init, getter and predicate bodies, all modes, inherited and custom\nclass names, call-count and order assertions, and compiled causal negatives.\n\nQuery register-rule presence directly while retaining initialization and the\ncomplete ordered rule scan. Preserve instruction-context and phase-deadline\nconditions and their evaluation order. Exercise production bodies, arbitrary\nkinds, complete comparison reads, modeled vector replacement, native fork\ninheritance and compiled causal negatives. Retain uninstrumented O2 object\nevidence with explicit reduced-translation-unit and runtime limits.\n\nRestrict pre-stop FIFO invalidation barriers to the initialized Sim\naccelerator, retaining every common-event pass and FIFO owner restoration.\nRestore ordinary common stop-before-work ordering and avoid redundant empty\nqueue locks on healthy single-threaded TCG turns. Preserve Sim global flush\nfixed points and callback/stop ordering. Exercise production wrapper, drain,\ncommon, FIFO, wait, kick and pause/resume bodies with causal negatives and a\nGit-free source-archive fixture. Keep bounded-provider and full-process\nqualification limits explicit.\n\nUse the cached accelerator instance classification when observing Sim ticks.\nRetain mode-before-icount admission, precise-only observation, the -1 error\nand signed tick result. Exercise the production API body with early and\nnameless safe-getter contracts, named mode matrices, lifecycle identity\ncontinuity, exact query order and counts, signed edge values and compiled\ncausal negatives. Carry the exact rule-presence lazy-memory test adapter.\nKeep ordinary RR barriers unchanged and qualification limits explicit.\n\nUse the existing registry guard for tracked mutex waiter counter updates\nwithout redundant atomic read-modify-write operations. Preserve unsigned\nwrap, underflow refusal, condition waiter identity, ownership transitions,\nall inventory windows and retained fork transaction ordering. Exercise real\npthread mutex and condition operations, contended acquisition, timeout and\nerror paths, differential inventory traces and five causal negatives.\n\nCollect the opposite TB page directly from its tagged page-list membership.\nSkip a missing or already held page while preserving transitive discovery,\nsorted lock acquisition, retry and release semantics. Exercise production\ncollection bodies, both page tags, reversed physical order, same-page\nmembership, lock contention and the omitted-page causal negative.\n\nCarry a system-mode x86 self-modifying-code regression for single-page and\ncross-page instruction writes, including reversed physical mappings. Keep\nproduction-body fixture coverage and full-system qualification distinct.\n\nUse the real compiler annotation and branch-prediction macros in the\nnative waiter and page-collection fixtures. Preserve strict prototype and\nwarning diagnostics, active test assertions and all production bodies.\n\nDeclare extracted public mutex inventory and condition functions with\ntheir original header signatures. Retain strict prototype and declaration\nwarnings, active assertions and production counter ordering in candidate\nand differential-reference translation units.";
  commit = "f67d9cd50d8902b88d6ae8f0b7c81671478e9e90";
  tree = "62ea367152fa9d8b32cc7599b5a9695737c9a61f";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-costs-fixture-prototypes";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "b0998a4eaa2014a2f8e5d394c40c7483ba4f1806093d20f6894e315b6c220017";
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
