# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "48f340ea792b149d7fddfd81487ca8b84dfa8a13ce19d0035910fd8c16c01545";
  patchBranchBaseCommit = "36ac68e25469b93cc91f6350b998b486ac41669d";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "29e5dfd63181ddb5001a1bbfa9a9af572eb737df";
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
      branchCommit = "9cf7d1a24b3df475322d274f942b37d10d54494a";
      branchTree = "3065414d8124fc9e69c6b200538927203fa1f79d";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "8520c261f5c8111cd4e75f4e01d9a4c677d2ef62";
      branchTree = "17f5360caabeef8f63ebe60cdc9b7e75d99b38d5";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "23b07dd00947d91193734b11491fe945211017bc";
      branchTree = "40f1be334e1a0b23d7ad2d65441c7cd76abc3cd1";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "71f276375f46baf6513e4b7a434db13c28987e80";
      branchTree = "d190dd020a834eb83777f1d416123f321d484eab";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "747228e14bafac7ea1f98852c5b5f8434b110071";
      branchTree = "e7f942870b00e7d252dd80b45381bbcb0876d71a";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "02bf1f33bd39f88a131348a28561f3dc9c2de4de";
      branchTree = "6d7fc76b6214782a42700c1bbf227b9d2dfd685d";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "29549a206bf1c384df719e615b0b52ee0987efa5";
      branchTree = "68805651fb610b41dbaf26bd4aa26e02d9fb8900";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "f6d3452a9bc6e56e7ade9e2b6b864cfd92a03be7";
      branchTree = "35da42fa79b4a523807521be27ab928c165d4698";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "48f4f5406af39f35405183119f885b27b102c1ca";
      branchTree = "6891998cf7a4ca8ab09dab23e9f99c2a553fe150";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "0f3e5e62687408d1277993c1a51fdd0fa01afd5f";
      branchTree = "767c8c68639e18db6cfe1a9d381cfa0b7bada1e2";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "801c19219053ea68de469490a701b5f474e4c574";
      branchTree = "489e027085a6c34e60cabca11738a4af34bac2d3";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "0e1eaae1b9615a33e42df604e4dd436b2ff27474";
      branchTree = "96c564c98ee78b0ced481ec9b9091ea81c9ad60d";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "8ea3bf5d3ec82b5f5c479fe789336d977893d1ea";
      branchTree = "5f34c76ffd05daf1ff44ed837630fd47127f5704";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "0f872bf8fab4a733d5c178b806b3e412ffef2d68";
      branchTree = "de8c339c6f9c3fc1186d8613fe62c58787456cbf";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "bb57baeed5fe5ae95b77aede0fc16599be11d2f4";
      branchTree = "69b589d7aca32fa59b6447d7f1da3d8d9f22a7d9";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "265d387d26066fad5ffe8ac5a589f8d577505c94";
      branchTree = "55d43ed9e551d903bbf9abeed7cf9fc4bfb944ad";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "cf7021ec48cdc1f18c9408f312a53a7e488e7f38";
      branchTree = "cd5284028ef5783084b3b7210df3c0d69d0db232";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "596f2f47e76d25f79933d9d8eaecf8752088bfa4";
      branchTree = "fedd02548f7a297e3d08fabc5a68fc42a315b1e3";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "33423acd5de7eeb77978b839e8b7c5da209d9289";
      branchTree = "c2fc2544cf20ca3741a084cf22cefdde305432da";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "f0fe2dbbfcec8bed393df5a72dadece9af401844";
      branchTree = "444f6f0953cc91e3b368f468e116bffcb0da765a";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "38c846e3e4c96d53a21da0f371f5282a357c8bad";
      branchTree = "4447454f1dce7e6f69209c657c3f3823a7924e35";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "9389f151615c7247f08cfe0c9ed1079af8e613fa";
      branchTree = "74565de60f377a44c5f0ed1a821d114758682944";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "0693e25150e2b1a1464d16d914bb384da60772e8";
      branchTree = "852062205443d822cbbc3747b330c911061c5883";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "5ad5bad236067711c1dcadea485867d79e20e9ea";
      branchTree = "475b74dba45f8283f5f72821e1442433edeb83b8";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "a1ae663a5d924cb09a429ac8cf74451401f4517d";
      branchTree = "c960fd5cf4c4c7fe2ca844009d144f8e94754226";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "077de8bc21e2e1bc286d53f1289a9e113cc13265";
      branchTree = "49ed1447fe20c3af94266b2f12aac515e4e8a326";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "ed9187b011e4cf8d430e51958032babc33648a10";
      branchTree = "e6d53f4c1cfe93d941b3155312b99efb91ec7c26";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "0854801b510cdbe24c96c69450a2205b99fe1a38";
      branchTree = "8fc4ac95baf2674b246b2bfb131c565b80c99a02";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "985078096fce013471de4d9167a2f90df8b70a3e";
      branchTree = "3780037fd088d710425d76e15b1211352d0485c6";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "ddf55e3163c8c95151a5c9dbd81ac1a74087dffe";
      branchTree = "760f4b2872f7b3679c897bbc485d8a306640a8b0";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "1a2fcc3cb8d8f33df38e8ba65900a30204c39329";
      branchTree = "aaae59bc43721682dd43dce8ab4d5a73dde71cee";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "9eeb1251ea8e050011e67339067f2c2213007407";
      branchTree = "29dd985fe4804a3f3bceb3ac064f2594a7dc1839";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "d37d11e09c8784ac21112c80bfda5cce7ef02cdd";
      branchTree = "81b986d6118bfe79ee60945f28f802168afcd73a";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "c13883440d44c6eaaada319b2e4880546811cea4";
      branchTree = "5e7652de28fc2ac7dbb50f453f5c80a5b5c96da2";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "36e65456fcaf8630b88ccd0ef0f9207b80273b77";
      branchTree = "da1b4b220b0f0698a684352d8a86082b426bb508";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "d1004727c4c3bbfad9c116f11a6e037f6edc4d78";
      branchTree = "d8b739e0435fa07d91d524433b8e050419b00e68";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "9efd110af4099ef79d4b5f27b0f3f2d499602eef";
      branchTree = "69e491226b9943ca15e48b2d64e2e0748a3ecf00";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "2c0c3ed038c9ad1f6240aea98a81d9216708c0d7";
      branchTree = "de87e45e6147cf97f823719159002c85f6a7228b";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      branchCommit = "15f4469cf3240a25957df79a9ff965e776ed90e6";
      branchTree = "9983fa0a392460fc18e6da53f7f63d828e839717";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      branchCommit = "6edf5705041809153339567c35522d01d7910209";
      branchTree = "3078d2ed8374e899576826cc2608778348c34c64";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped guest virtual-memory writes for synchronous white-box doorbell replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "cfb76410a7cd9261c27a549348ee25f9842c3c5a";
      branchTree = "8cc2f0ffa260389c6452876d6c05a2b48898ef99";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "7b79f2f4adffdfe6f39f93b8190005c5eb4c9b70";
      branchTree = "28796968fb32d6abf2dadcaf658eff97b36086ed";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "932bb2be120e63d892e213c643aa25fc2e0c86e7";
      branchTree = "5a76b55e24ea291812a8306b0167847f7da733d0";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "29e5dfd63181ddb5001a1bbfa9a9af572eb737df";
      branchTree = "9068a0363942e4a66426f09525c0b972ad8e7a35";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
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
