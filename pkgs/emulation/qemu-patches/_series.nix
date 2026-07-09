# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "f499b5f452b85468f77dc0c961d52bc7441165b893c70d4c9f673f49b69c0695";
  patchBranchBaseCommit = "36ac68e25469b93cc91f6350b998b486ac41669d";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "9fafcbb9a425c995e43fd05de6c9ecd3badab7d4";
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
      branchCommit = "d6197252563ec680469e0cc4bc9f545d61e68c96";
      branchTree = "03b93dfacab46dbcafba656b6cb35ce641af67b6";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "bf8d4e9c358501150e32512e466c0f0504782cca";
      branchTree = "702df567655ceadc2d51dd3d7afd0f42239a1799";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "71c1e2a0e64fd487b3cc041338cc0d107a538768";
      branchTree = "d014220b2c575ff30ddd45dbf5a56b97f741c336";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "3f56e984a10862369e6c7340d7a3adb700ee235a";
      branchTree = "b4825263b7a0be580aef334d5238085437b3d069";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "530c95eee3cbfa47254042003b5bd5f277d4e932";
      branchTree = "f9522ccdfa13cc540a586c676dc0c980950f9d15";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "6d48d90efdf133264c9df8d8603809e3de930bcc";
      branchTree = "92d24c863a57b0a4468c29c8c4d0bb5fcd122677";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "11bdf5dc27716aa3d9baafa26b5b74f8f6238c8e";
      branchTree = "87adcbba02fc8d89c20e89cbd18ada33a3fea1e4";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "19d20669430bbfe4e771c9586e1ebd6758185ba4";
      branchTree = "a0e40cb1f1a6974092cf713021d3ec4aab4f52e9";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "ff5df5ce47c58ccf2fd59241d9a2d81242dc4647";
      branchTree = "9c089931781e217cc3fb8ed6cbd4243ca506fa24";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "plugin-owned synchronous virtual-time advance and BH/main-loop drains";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "05a69c88785c0b6449e046293cbef3940a004479";
      branchTree = "12af4e61b3a00632d44f15c54512a254e6336285";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "1ab22b0d25cb75aede32786e3e0a6f34b156ba77";
      branchTree = "16d6e548b886ed8c7c0dc9b67096809ec6c59816";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "d5b30bfe0cedfc8c2d4394b50dac3296690ca825";
      branchTree = "4b1219712fe1eb244248036c2d4e3575cd4da6e3";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "plugin wake fd registration and blocking main-loop wait";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "ebcf3f82cef21daf032789f50c4d6cd8f78efbc7";
      branchTree = "4e2f56b7aa94120fc83a79b3e588084e0384273a";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "c872c15b4df8f5a2a2dd8b36bbf35149b12b8e5a";
      branchTree = "b39e2284dbe57da68a644000e2783322dafc464e";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "f5f3b58f8eed3257148ce3ceb4c2c05e2d775563";
      branchTree = "a9e14ad25c5db8f95e5326604c2915644314d0ba";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "1e1a457e062256e4cbc3d76be7522f6cbf87a3bc";
      branchTree = "5b172dbc9cd3e93733203525a1bb7fec7d09db9e";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "1b64019e14d870fb471a3a846477a4132ad2aaac";
      branchTree = "993618a4b569e380ef5c7d13b8bc5b153f4f88ee";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "a06fe48453c6a3e05f2608372ebf078c3009d414";
      branchTree = "dec7a08c03bb817068cfb686e63665f279ffdc95";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "ef9402d887aba1cb53d461bf1bc7aba71c2e2874";
      branchTree = "53170e377879d0147d0d0bcf46630b996b246cf9";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "4ee62bccdf9e97e7c294c69e9dd9631469378227";
      branchTree = "b93028eba3b7bc27b589e07ffccf5d2f386fed5f";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "93103b8e080b81b71c4bc9dd63912887a1ebeba5";
      branchTree = "4015b7d62f4c6de2631471056511f4da6a59c67b";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "7c88b92f8a44c0481d20411732d89640e33ca235";
      branchTree = "ec63f8b54be9cc9b0c5555ee5c106767afb666db";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "e46f9b5559702c11a6f3df5fd1b9a20fc375a4cc";
      branchTree = "5b13b56a32fdca45d9638a39baab17284f41bbae";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "sim-mode time-control-guarded shmem drain and one-shot re-poll before coroutine yield";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "4a008c847a5f4bfe4cb3f1f21ff951dda0c3993a";
      branchTree = "d1d43311669a15ff5ee30ebaa656a7de9a614605";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "088e1fc4b40c425eff86d40983b9db733524d414";
      branchTree = "288d4fc5995d14c0e1a06a373531fe8347568bee";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "929ee9e45c01e9fff1777813527374efc830def0";
      branchTree = "46fb4f00ae1ac9cb669ffa1420566e4c27115c13";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "3d8f44835fb17d4a4f803c83cb54931924a2b85f";
      branchTree = "d29d329716498c21a9113f24cbdeb28ab9ece183";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "df64e80ad585550268897776a35d3d01fd775650";
      branchTree = "0eee29317c81cd01151b01e640cb9985544e174e";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "2471117258865a255ed191b6d3bcda85d6e24da0";
      branchTree = "9a39423fbd0b8d4d6017a0ce6c2cea2939a68845";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "8530a69aecfd8b07b91e0342068cff754d6bd631";
      branchTree = "fc4798b65e937e875f4cecd3b8f9702aa92b065d";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "9fafcbb9a425c995e43fd05de6c9ecd3badab7d4";
      branchTree = "9a87ee2024794848ebbb3c8c96b3a5ca6270c85e";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
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
      catalogName = "crucible-plugin-advance-drain";
      carriedBy = "0010-crucible-plugin-time-advance.patch";
      class = "D";
      enforces = "PATCH-19,DET-1,INV-10";
      capability = "bottom-half drain after synchronous virtual-time advance";
    }
    {
      catalogName = "crucible-plugin-drain-mainloop";
      carriedBy = "0010-crucible-plugin-time-advance.patch";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "nonblocking main-loop drain callable from plugin callbacks";
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
