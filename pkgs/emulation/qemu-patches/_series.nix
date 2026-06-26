# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "1d969b51af280458fe3fc5405d1a49eb302afdeac2d3cb88382d3aa2f734efd2";
  patchBranchBaseCommit = "36ac68e25469b93cc91f6350b998b486ac41669d";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "1b2b6240a2e0887244f7c4c5aef0653754503365";
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
      branchCommit = "58a0a8e9a4f101927ee8bc3f81dd64d41c9cc8ec";
      branchTree = "ae3d00c00c41ab7cbbf61087ec4ef045418f0b19";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "baa5eee9455b5186cf2fa43de283503342d25c8d";
      branchTree = "cd0d14719748f54f2786d5fe1691c5f6ba4ee144";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "20a0faf14d5e93f87a253ce38b3906ab707b2686";
      branchTree = "3f46286402d955707c076d47472df9efd40686b6";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "76a361f8bf7d00e0fb316770d072af0b783c1947";
      branchTree = "4d55b7aa73e13cfbec9784f224480bbbb729bbc5";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "a2e56c0378889d8af05d56d1d946fd89533581dc";
      branchTree = "ae1403d7bd32e27d4ee219763e7845459eb6b62c";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "10c6623a1098551e4eacd7bb94cc571d9753a456";
      branchTree = "cc805679b8b59d84244fd3cebfa6f29088bda4ed";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "029d3f2ddab279c7837ac9aadf81c26402df3ca0";
      branchTree = "212724828ce9c456fda9691ec48c0e26947f4506";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "plugin-owned synchronous virtual-time advance and BH/main-loop drains";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "3109c7b18348261f2e2de5a92342cd146046801b";
      branchTree = "a720cb34d50d0b2f3b6145d9a597bbea63346647";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "581add1ecb2dcf0026b1c21789f1f9632628ce46";
      branchTree = "a92711541f019b15c2bd0b4e33dcd058081b195b";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "7b4f3f894483cffe097939bd18e74b968f8245eb";
      branchTree = "1749a7cf9feea3959cefa7096fc9c985d6015360";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "plugin wake fd registration and blocking main-loop wait";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "043b6962cb15c45b52e075a074db346998144c93";
      branchTree = "e6e2a11c1a8b0bf4ca46f12a8c95a69c5ea82a95";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "8a680d39d48608c85eb05c0df524e96225411da1";
      branchTree = "c21c7e7bb190addaceea3946d9f61e204e4c4e06";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,E19";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "4f20c7070d49f635a27904921420e5e808be1275";
      branchTree = "4cd9b4cf24fb1966825febaf1d9b28f2bf56ca74";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "18e0d1059564976629692f1b4c2058ea897b6856";
      branchTree = "8c5050617273df37348f569e8376dea03c0ab868";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "fba58f6026fcf048dc2b7c6935bb433dc31218f2";
      branchTree = "74decd9e3132dd0cb7985881578e79dbeeeec873";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "6c3486925fd4fd49ea5885b6c406c52025a4ffac";
      branchTree = "7256394ee6b381f49b3dc022f97690a056d4e3d9";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "a50778615a1bc71026b7a959619a72cef2be5cc6";
      branchTree = "6150408f039907d334397626f3930d866c17230b";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "f1aa0c6b1d66c8be165ca3b9d6e7e03a53cabd86";
      branchTree = "0ea1663080f36d6214d904e508454c089382402b";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "d2fe02f8bea8e1e640fdfaeb12241d3a6b56f270";
      branchTree = "3fadeceadc4408766a63eeefba9637175934c515";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "f701cd4ce06c2d2bcd47297fdf098133dc944d9d";
      branchTree = "50e8c31240265a133b0ea3a5a7ddd9237e233115";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "0fc5cbe5962c5f08f3c5a0191dec94933802aae6";
      branchTree = "8ad0025d60d3587b6054239fef919ed7e9d62d13";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "sim-mode time-control-guarded shmem drain and one-shot re-poll before coroutine yield";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "e9fe1076c7708c6cc8cbe3a11b60a8d23dce98ee";
      branchTree = "3974ff3ece382ab662bcca433f5a50fcf5ba7787";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "f16bfef262aa750ddf9a55ff8591780157af6e47";
      branchTree = "a78d86425a5209e16d8c4efe1f4091e5ce1cfae8";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "1b2b6240a2e0887244f7c4c5aef0653754503365";
      branchTree = "4d6bdb5b0e1f2baf15695b94091d10711f0179fd";
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
