# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "26848a2a4d472f232b9f96320d1ef1b98602eeaec693f4585b4481730db0eb10";
  patchBranchBaseCommit = "36ac68e25469b93cc91f6350b998b486ac41669d";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "75fca1c777807e913c0a512eab87745e286d4c25";
  deterministicAuthorName = "Crucible Patch Regenerator";
  deterministicAuthorEmail = "crucible@aos.invalid";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";
  patches = [
    {
      file = "0001-crucible-sim-accel.patch";
      branchCommit = "e67d0f596d644216dfaffe0d1f6d8f7723859a01";
      branchTree = "978943ce1f6fb680f624b358c65972c0e4df261c";
      catalogName = "crucible-sim-accel";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "-accel sim deterministic TCG accelerator";
    }
    {
      file = "0002-crucible-rr-fingerprint-helpers.patch";
      branchCommit = "20b41aada4f0dfdc1dcf55eaf87901c69928637b";
      branchTree = "613b699b793315b4c8a8f549e9ea78dabe2d2850";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "35cead49b3bd93927025817fe02e8815e286f9f2";
      branchTree = "9403f4546b7efd378d398ddc9353569f1230f76d";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "38e0b108df7a81d3f316a8fb91c99238403afb2e";
      branchTree = "e0a3edab1a3c4deec7fb708c058a855501da8f20";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "4faa12038794cd710d3ab7ccca61a0ad3d3ea9f8";
      branchTree = "ff95d66d73aee18ee8aac2ffea1710aba1f127a5";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "2dda14c5fee223d8701a9601d286399e9f8b77fb";
      branchTree = "e061213f6f6451ed565f0c52fba67b316c255c6d";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "a538deffcf2ea6251c829e8dfb93c8b6abd09e4f";
      branchTree = "566849fab6a3022ec9a65f621053956e62ed5a61";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "0bd9ea60d63ab03f620b840e4deb89cd33538e36";
      branchTree = "fed45877e3f0d113dc6dad243b161bd03b50d734";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "a2230acdaff7afa1dcce6f1dcbe9ad579e260867";
      branchTree = "fff67f43607a5ff851e3ae84c6011caee3720469";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "973af93fa2eede34a197d97f628d61e56214e1c4";
      branchTree = "12efe1a33e0908e0d28d54e553b70f95d1c8b9fd";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "5fc627fc7be30e126467669d666cff9f2c28c3c9";
      branchTree = "96dd833da8abca080ed154e77a958604db83cdb5";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "06175703908f5037be242298fab21d0671410e99";
      branchTree = "5317fc717d2f260747288028dcac81fc43af0df4";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "5d9930e3f858ee0b8c96fa090f226a39cc879d27";
      branchTree = "e16d9a38ac63c0d86704154bf15d177392ece1a6";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "7afdfc2d5dbec459836b9c4522f32d5a4b0179d8";
      branchTree = "08554634b03f92be4672d0292475708e49a9acea";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "8df7f8543cb6506ff2350f6e2c4ee09d4434426d";
      branchTree = "7358aa4cc79223df30ebdd5418b74cd3c9b173d5";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "3a923e9738fe231286f9563a6e71df0d71cfef30";
      branchTree = "68b232259002719265d6519423fb12207253fa3b";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "bc7014367ec6a410a9a61a452bdd551f941dfb0f";
      branchTree = "15a77b53ca35812da9689e314d5396bf81848c3b";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "b5bb0f31c9d3444f67d300824b450800382c5e41";
      branchTree = "ce4abc78e0075d02a2ea44c0b22cfbde2c5dd5e1";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "385edd77048c697a504c23e3e2d7db91003d6afd";
      branchTree = "699b23792bd25b096f3b8bdde78622608c07662e";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "06dc8e89f8fe6386919550589ef0b48684abaffe";
      branchTree = "5bee1282030c8402d29aa9a1d52faff03aa7d530";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "790242b2b0ec6c435ba10a5ed80a1ba0fab0d02f";
      branchTree = "3d2ecd383ac0a36e62bb4c56b1f07887491e3c9d";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "4b72e9429d838fccb9f096941549dd820420a573";
      branchTree = "1ea0464017577eca25dd061d5a8c48cb5f25d9dc";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "2ccb13de9c4fb232d0d8a55242406c00d43be29a";
      branchTree = "bf4d9b83f52429504077e00902f9c694e0164c68";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "fa06bda0566112d47feca4275609a91ecd88ebe3";
      branchTree = "121438d35db4a0995d0d579105762e6cc0614f47";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "81774cb097950bf93620861205c3d43a15153472";
      branchTree = "be60994a278a650e177199b7eba37f54d9d5bb8c";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "4313368e1c4c5a0703a671389f720adef71cc870";
      branchTree = "c64e0dad7e5ed1a72626b20f6d0cb2f3d5a9f034";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "04054e15679863dcc3176f6a73a25c95f6f2a812";
      branchTree = "1c3d3886337cb9700ec303b07d50f34a45609ed4";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "fe4edade8c026e63a40a7e14bab3e2eee7212c02";
      branchTree = "34ec88fcf23cb7d22da4c6143da12795604cbe06";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "70771a58c0b395b403498d59e63fb9ffc65518ab";
      branchTree = "8e6ac752aeb82eb188c3d501c24ce74c12fd61cd";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "4b944e3c3662440470d6e7693ce8d0aa915cf061";
      branchTree = "c6d8ddfc7379f3f731a3235177b0f48d3e85dd02";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "ed93ec85b0bdeeb5b6e6502959c2a976f6c36c91";
      branchTree = "cac80eef6922c4854f5d00e37c9ef1f66bcf5cd2";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "988e565ec8f87ad5afe48151c014699a99ce332b";
      branchTree = "35467c12cb09bf813a056d96c15678ffc13bf5f3";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "75fca1c777807e913c0a512eab87745e286d4c25";
      branchTree = "bc7bd8f52fc20e9f1a1d18f630491894f4244eda";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
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
