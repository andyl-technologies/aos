# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "6661ad51927d0e61744e180a2989072da83e9342e6d2f37908bc2dfd20c0dfb1";
  patchBranchBaseCommit = "36ac68e25469b93cc91f6350b998b486ac41669d";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "1ca198288b0ca503b8dd86b459dfe03cd1959e46";
  deterministicAuthorName = "Crucible Patch Regenerator";
  deterministicAuthorEmail = "crucible@aos.invalid";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";
  patches = [
    {
      file = "0001-crucible-sim-accel.patch";
      branchCommit = "da1c51da2955cc9b3a5ed9f544629b9bfe3ad235";
      branchTree = "4f338ad519a5934bc4a842f1ca3a34e7409130fc";
      catalogName = "crucible-sim-accel";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "-accel sim deterministic TCG accelerator";
    }
    {
      file = "0002-crucible-rr-fingerprint-helpers.patch";
      branchCommit = "76c0b7570ac490bf2c9c04486a91d29c85d1ca70";
      branchTree = "b1860586bbf654816efbd1acae1a90686d08713e";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "4ed574e8e29866292177b440818c783fe80e8069";
      branchTree = "b48bcffe9612f2094074c578b4444856444145b2";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "9de46872aff72e9ae8b2b09620df98c274de4a86";
      branchTree = "d1a7008c79fe7cc9ce353ad4dc0985d0741f3c8b";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "1e24714152107df39a4d0ca6a20cf41fb7eace26";
      branchTree = "c7b6d0b947047c7838a6cdcbdca9814b380e7cfa";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "02c9cea264366707c0b89c3a66f2b83c34886288";
      branchTree = "8a4bc7ad349d4cf94aa6f2a1d4be67c58985e4ea";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "377c27eb94a324e09bad8fb5fcac084fcf2173fe";
      branchTree = "7921ad69202db99fec07bfb579dac2752176423a";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "9413f18946fa779b118915cb9a2d1d75726aa9aa";
      branchTree = "a7933643ebce09434bbed53430a47630d266e1c6";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "3dcb361105da71bac8b72e4eb297eacf8b1a839a";
      branchTree = "7ad8bad62ab4c91af244bc47b305607187c9b8b6";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "092e1393eade280762f04cacbecbc7cad33f2fd9";
      branchTree = "3f9367dac24ee8fcaf4c3022c6e33e4c4590310f";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "plugin-owned synchronous virtual-time advance and BH/main-loop drains";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "9a6c59e6652d5c28c7e0b0cea61f84e9f13ae7d1";
      branchTree = "3e5bc0e5aa9aaacdc537e38f44d58d5ebb0ea4d4";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "65877f468ca2bb267c493d3b056347232ddb27a4";
      branchTree = "2857bf5ad0299daaa93c42c5393f0d513e0f6b72";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "cd1a511c3dec4df5fbb706a552a7b3d41189b47f";
      branchTree = "9b72b95a189a48f1672866fcab5348997d49183b";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "plugin wake fd registration and blocking main-loop wait";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "3ff61ba174c4376836cdf4fb4a7e5b068390ae76";
      branchTree = "698afb97133480bc39e340cd91a885f8e126e3f0";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "c90805f8a4e02dc56f956c627edbeb26df60634e";
      branchTree = "281d699ffbf06eb0f57339a882ee39c4cfe0f112";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,E19";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "a4c08d4a45eea4377077ccbae43372e2a64899fb";
      branchTree = "93c2594f0366d3b2f6abe1b7d007739d216837fe";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "181308927bc761164cba23cd9f967a847b82705a";
      branchTree = "b96110dd96bae6be4ff480108c171eb78c95fb6e";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "2fc76a0ab1e356e71034c604318a53c25737d097";
      branchTree = "299a179183eb0d3c8df17322d3482e3718936a01";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "e85bc1fa5ec6988f12a8664ba2764b89d52ba6fc";
      branchTree = "75bf281022e87855ae65419f468aef941fe1f1f3";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "2f9102a69e180eac9c52bbd687bb80575c17fb04";
      branchTree = "718e5730fff5128e9871f83691d560dcfa722f22";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "ddd22234dd1057c3b4d320e98afcb9843bf620d6";
      branchTree = "0c787e86d27956f247f7f8f481a5dc14cc757c8e";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "5c76eb8a77b2c249d8bffaeccaaed33673c80559";
      branchTree = "b3598025fa78689a5f9058dcfca01665c9dc1679";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "e8fe3069a3079afb1ca0a6c76e659594a766052c";
      branchTree = "c2168dd65ca70894fc08916ef9410d13bc483134";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "4eead712a4f6308450324866ca3f35671269ffa9";
      branchTree = "27e9c8ba44c8204a3462c54eb45a2bc42888f047";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "sim-mode time-control-guarded shmem drain and one-shot re-poll before coroutine yield";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "7624e43f9cb930db75bddd65ed4741420b32a786";
      branchTree = "b96e0d7a305c6cb2c0399fc79218f15782fcc615";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "9c0b663cb77c821dd4b5c8cdcc9bb9673275552a";
      branchTree = "7eda2c8c19a69a485fe16f783772bbf7b4a01ef9";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "1ca198288b0ca503b8dd86b459dfe03cd1959e46";
      branchTree = "f3e35df1ba9725adf32ec491e34cc729091c1d37";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
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
    ;
  patchFiles = builtins.map (patch: patch.file) patches;
}
