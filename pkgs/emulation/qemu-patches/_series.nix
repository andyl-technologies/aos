# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "dbdfc5fa516581d6de1a3d1fd7279e4b97789edb5b20bd76cbf7d7aaf8b2c237";
  patchBranchBaseCommit = "0400e2d08acb30307af7cb214b21552807c1dd46";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "d1609ddc65a8e5917b006267f8c3e090757b8bcb";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";
  patches = [
    {
      file = "0001-crucible-sim-accel.patch";
      branchCommit = "8cc7bf140053c951961d5bf3fea131402a8222ec";
      branchTree = "978943ce1f6fb680f624b358c65972c0e4df261c";
      catalogName = "crucible-sim-accel";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "-accel sim deterministic TCG accelerator";
    }
    {
      file = "0002-crucible-rr-fingerprint-helpers.patch";
      branchCommit = "a919cacb1df54cc3d6a2f0d63e75a0bb806d70d7";
      branchTree = "3065414d8124fc9e69c6b200538927203fa1f79d";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "2b44c52075cdbc5ae1f51c98155c4b59dba11a2b";
      branchTree = "17f5360caabeef8f63ebe60cdc9b7e75d99b38d5";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "165243a56a16978357f613148f83818d3e22e43e";
      branchTree = "40f1be334e1a0b23d7ad2d65441c7cd76abc3cd1";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "8117db174fb23b6a55e7faa5442eaf98504157e3";
      branchTree = "d190dd020a834eb83777f1d416123f321d484eab";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "8efbd9e85b51dfab51eb725c3c659795666fd4e9";
      branchTree = "e7f942870b00e7d252dd80b45381bbcb0876d71a";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "48901acc9cfeebcf1136a25669cf782e224a3d6e";
      branchTree = "6d7fc76b6214782a42700c1bbf227b9d2dfd685d";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "26331bda97311c24b2405e1e001200d44ccc1b5e";
      branchTree = "68805651fb610b41dbaf26bd4aa26e02d9fb8900";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "3840d6f521c5fad94d1006dcbeb2bf4c2e70c383";
      branchTree = "35da42fa79b4a523807521be27ab928c165d4698";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "32047e112525f9c52b1f0558caf3a54ce1077151";
      branchTree = "0dde00c5feef8efabbf753ba5d870254df6cfca2";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "363343ff950d631eb22116ffa51908be5939d900";
      branchTree = "5162959c322c410c9a04f3996cc7ac244a486d91";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "f07adb81dfa39073e17bfdd4e0d24aa026de290b";
      branchTree = "f2c7f619e18ac6eeb224dad260ffdc81be6e956f";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "51efe4b70acc7d36587d24b8f9f5b6cdf25465d2";
      branchTree = "d4a639f9053fbd4ab19acbf59fca0337517c6768";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "f33a8b2d1d26c3c100954c6c85c2305471e74a90";
      branchTree = "d56f4b84a1b05de79c1dcaa426ad0084aecec786";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "212e7de5180289446034399f07c1a7d49da13d58";
      branchTree = "06e49676de1f0e22dcd12b454ca5a3f77606f3e5";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "feb76d6c9a527f6d6a274d0b0eacf36f2006a370";
      branchTree = "4725145bbc4565874a4f37884084f8a732887548";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "69f839b8cd4cba8673fa786420379afe24ba3b27";
      branchTree = "242b3d67b42e0451852cc901bc84e509a7b03642";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "cf2be501f3a677a50432be511d71059e5b09b6c5";
      branchTree = "2b3b23e67d6b4bd95dafda69a07b99ca5b9cadec";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "35cf51781a3c02c770194f4590e741df2ccb519a";
      branchTree = "d139df8f5ba27aa233a552b1f77b2656f14169f0";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "ef098cffc793df724e89e391e75073f70e435cd9";
      branchTree = "0271fbb10e8932875648c8341154b5fb56669d2d";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "0b73d36b13a22013efd94b917fe24148f494c38b";
      branchTree = "ad87a310b38ec97d2adca464d9d585ea7e5d6d95";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "f5643011905911e24b3b2e55ee9930a0547c7604";
      branchTree = "fc7f0be6e9f5adce9d6b8173c9a7da8bb83bf237";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "8e3e8c0aac717b255dc9ce8e505224739cd7348e";
      branchTree = "427e8468eb4e8bc806b6377788a0758a4a5da925";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "473282a8c3fc9a80ce26144cf7b325317f258da1";
      branchTree = "58f2ce5b57c731f8a00163aac77c588ffbe29d14";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "8041cf46aecaa2a98df3f6352d9e5e39fc8377e8";
      branchTree = "cc205e4e4ca64f3ce64d50bba51c724d4545316b";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "81bd7f5e9d13b7231b3f8c54caf3205a8c6f66f8";
      branchTree = "c42e6374bcd7a6fce5e71c797292371041efc865";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "bdfaf7861b4bc081c2d3adb0d84bcac634825263";
      branchTree = "061407a54420279e60ff188318ff1e7789941b3f";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "3520918ee83bdd5216eddc2eaa80d2259c3d87d2";
      branchTree = "456de962a15c1e10ccee0df2b64278f067a6a793";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "a1d2233791f56287160684268b5260be5869b6b5";
      branchTree = "254b48e470a078965a79ec1085b4b4d595dec4b2";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "097246025d1e5bc1f3c15af92aefb16fdf76d028";
      branchTree = "395137cd4cf3fcdd7a582c807b937ad51d38786b";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "cb32d3134cd250d53311f092565760bd5037e493";
      branchTree = "bbfcd0c9dd52b9899a773a07c1d37e43b19793f6";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "dda4f0188da45cfca7a4442a4625f568f8054f99";
      branchTree = "d45dc24d5de507f31be6b2abdfa06860ace1a2d1";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "bde2544238669998254a9d6aa10715aae84c2be8";
      branchTree = "66be497f5f7b2d927f629dda23c5e9449e17ec13";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "3ee8ab34ee58053cab4cba9ddb2d502341a52a77";
      branchTree = "d5cec33883ab6bfa986b4636f37c144d19de952a";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "e9c13a351bae6e6c9bc8ac56ca8e791f45a67fa2";
      branchTree = "15000afeb742ca6d2f1f58bcd4e9723f62c5269f";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "3a2b9a397d0413ac14589fabd23d623f95289b9d";
      branchTree = "b2da5a6b56885201eb936f94bec0e79dd0904a3b";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "925de4ed5246d3801a1d78e752b1d4e659e72f4e";
      branchTree = "459261c9767a3119244c55bd30a23287f5b1e040";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "f815e4024a366d1a2b48c98668efff4ef42417c4";
      branchTree = "65670ef9953575370edcee88fb4d67686a3c947a";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "03d3b9265fb28062e4d4a3f223a0a2d04921f78b";
      branchTree = "4876994ce1997fa8d8e71d2abb2f041e66304421";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      branchCommit = "1da1021cb36dc8242035d6a1419fcc880862941c";
      branchTree = "481dafec5a8a12247d29400407e066aeb8b9b5d6";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      branchCommit = "9e9fb3663ab87cb3d792798d773fdcba3c5f08ed";
      branchTree = "75c4a854a5f613477094b13e259ac3357f099e8d";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped guest virtual-memory writes for synchronous white-box doorbell replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "4fbd150bb454f573ebc50b7157d69e3200942157";
      branchTree = "bba76c6d0fef7d7b1276ba82e45e3929c341ede0";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "9f6a1c88aaa90219f620cd149b9e4e7f5a1d4221";
      branchTree = "379bc92910170d260ef88c5f8c9f3497f80037d4";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "27d7c89a2a139006ee4af27d8ff2762cab3dc2e9";
      branchTree = "199274a8dc65abd9bef2b0b15fa97901b5cde890";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "c9a2566acffa9e0520d0ff8c99d121e50402aaa8";
      branchTree = "f4c226a9dc8dcd76c604e6e6c89249b7726f016e";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      branchCommit = "7fd669b93b22729892fb73f980be2f5d0ca42884";
      branchTree = "e8237caa96f342f36bc11391c7731aa3b86e7883";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      branchCommit = "50e6f644974987c0b926df6dfcac148d0a0794df";
      branchTree = "c446512cd34c28e171f01ba6fffa49f8c10186d2";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,FAULT-ORDER";
      capability = "versioned fault command registry, bounded result queue, and plugin ABI";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      branchCommit = "111e8a4886393305a4a0af56ceac16d9fadf812c";
      branchTree = "354df0348900b961d194255993bffb508f0a7d9a";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement and same-boundary prepare/commit completion";
    }
    {
      file = "0049-crucible-memory-boundary-mutate.patch";
      branchSubject = "crucible: atomically mutate guest memory batches";
      branchCommit = "9ba24a083be276e6e57e05ea4607919c25d22d96";
      branchTree = "9c6a1a62248c140c0258a006078e0a4417d4111a";
      catalogName = "crucible-memory-boundary-mutate";
      class = "F";
      enforces = "QFP-MEM-1,QFP-MEM-2,FAULT-ORDER";
      capability = "atomic ordered GPA/GVA mutation batches with translation, RAM-map, dirty-page, and TB evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      branchCommit = "791d642095d321c05e7f4fbe0930d54a4fbf7acc";
      branchTree = "6a09907ebef5f0e8b96df7f006a6e4671b33cf5f";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      branchCommit = "d1609ddc65a8e5917b006267f8c3e090757b8bcb";
      branchTree = "947e95bcd597e1011b32bd98f2fba306aec99d89";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
  ];
  catalogOnlyCapabilities = [
    {
      catalogName = "crucible-rr-quantum-icount";
      carriedBy = "0002-crucible-rr-fingerprint-helpers.patch";
      class = "D";
      enforces = "PATCH-44,DET-1,QEMU-43";
      capability = "round-robin vCPU switch boundary pinned to node-icount";
    }
    {
      catalogName = "crucible-plugin-advance-barrier";
      carriedBy = "0010-crucible-plugin-time-advance.patch";
      class = "D";
      enforces = "PATCH-19,DET-1,INV-10";
      capability = "normal-mainloop barrier orders timer bottom halves before queued advance completion";
    }
    {
      catalogName = "crucible-plugin-device-wake";
      carriedBy = "0013-crucible-plugin-wake-fd.patch";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "event-driven device completion through the registered wake fd and normal main loop";
    }
    {
      catalogName = "crucible-net-flush-api";
      carriedBy = "0009-crucible-net-deterministic.patch";
      class = "F";
      enforces = "PATCH-32,DET-18,E18";
      capability = "lossless RX queue flush API over deterministic network delivery";
    }
  ];
in {
  inherit
    qemuVersion
    qemuSourceHash
    qemuSourceUrl
    patchBranchRef
    patchBranchModel
    patchBranchBundle
    patchBranchBundleSha256
    patchBranchBaseCommit
    patchBranchBaseTree
    patchBranchHeadCommit
    deterministicAuthorName
    deterministicAuthorEmail
    deterministicBaseDate
    deterministicPatchDate
    patches
    catalogOnlyCapabilities
    ;
  patchFiles = builtins.map (patch: patch.file) patches;
}
