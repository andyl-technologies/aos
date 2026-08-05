# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "93ea8c9d357758fac50d796efed290b0717fcdd30fa162a93d41906a6a912d83";
  patchBranchBaseCommit = "36ac68e25469b93cc91f6350b998b486ac41669d";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "1a05b3386612b0cad3b4db93d44c69632d602ea0";
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
      branchCommit = "b85057f7f220880028d2a38f42257003ecd15082";
      branchTree = "0dde00c5feef8efabbf753ba5d870254df6cfca2";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "56581a70d494f1cdbe30ead454e5eb9b5da003fe";
      branchTree = "5162959c322c410c9a04f3996cc7ac244a486d91";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "8ace4d0af48a6fe9efdb591d3a37be80a3506233";
      branchTree = "f2c7f619e18ac6eeb224dad260ffdc81be6e956f";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "9911457d3e77149b566c7840ace4ca41bd044a61";
      branchTree = "d4a639f9053fbd4ab19acbf59fca0337517c6768";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "786525e204a03e2fada8c5144c3722f7281a14ec";
      branchTree = "d56f4b84a1b05de79c1dcaa426ad0084aecec786";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "62b5a6559765984809685651b0cf4ccd3d9a72cd";
      branchTree = "06e49676de1f0e22dcd12b454ca5a3f77606f3e5";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "abeb43d7f72585c6af4ed0b91f1cfacd16b55171";
      branchTree = "4725145bbc4565874a4f37884084f8a732887548";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "4f08fb61deef63dbf7de683fbc10a10482936b72";
      branchTree = "242b3d67b42e0451852cc901bc84e509a7b03642";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "cc963ceb0ea416db6c92cc9763b8361e3668198a";
      branchTree = "2b3b23e67d6b4bd95dafda69a07b99ca5b9cadec";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "16d453b9a0a12edcdeed852780d27364a712652e";
      branchTree = "d139df8f5ba27aa233a552b1f77b2656f14169f0";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "2065fb34ed4cc0a37463943f5851f16ee9a73f14";
      branchTree = "0271fbb10e8932875648c8341154b5fb56669d2d";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "bb2eb27ad75c5722b8d0cc8920e31a2456a8342a";
      branchTree = "ad87a310b38ec97d2adca464d9d585ea7e5d6d95";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "7a22dedb0d406a0ee4ccc49e5c66e5b57a2cd720";
      branchTree = "fc7f0be6e9f5adce9d6b8173c9a7da8bb83bf237";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "95a02dc43b3e155cb3ae4daabe6cbf1c303bcdd5";
      branchTree = "427e8468eb4e8bc806b6377788a0758a4a5da925";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "d1fa357d8c44837e49b36afbc250c3b88e0f39bd";
      branchTree = "58f2ce5b57c731f8a00163aac77c588ffbe29d14";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "0903ac79e4ce36334a43ce4e4119a06989c6f54f";
      branchTree = "cc205e4e4ca64f3ce64d50bba51c724d4545316b";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "7ac63aae659cd322485dcf54a6d1cde37ec766b5";
      branchTree = "c42e6374bcd7a6fce5e71c797292371041efc865";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "0f9bbfff22fdc0e51779994839b0c2ba9605f563";
      branchTree = "061407a54420279e60ff188318ff1e7789941b3f";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "447eaab53488df5e0c0102ce8d5a63da3bc70552";
      branchTree = "456de962a15c1e10ccee0df2b64278f067a6a793";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "6cee0f70c5ca53c099c298c058a7ec36695e938a";
      branchTree = "254b48e470a078965a79ec1085b4b4d595dec4b2";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "4a3c58ca1c7488d5811fe58f7664faa1817d369d";
      branchTree = "395137cd4cf3fcdd7a582c807b937ad51d38786b";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "2cb777b640a05268c344faab658d9e641eed7c59";
      branchTree = "bbfcd0c9dd52b9899a773a07c1d37e43b19793f6";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "490bbfabf014b972514d7ac251d6488c57d42032";
      branchTree = "d45dc24d5de507f31be6b2abdfa06860ace1a2d1";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "c3ea7daa0d2c5a290f489c5f862dd99c680bcad7";
      branchTree = "66be497f5f7b2d927f629dda23c5e9449e17ec13";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "07063c733fd99ed945c61e50732ad3702cbd561f";
      branchTree = "d5cec33883ab6bfa986b4636f37c144d19de952a";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "4c1c218fa1480d523ec91390219a75af49167473";
      branchTree = "15000afeb742ca6d2f1f58bcd4e9723f62c5269f";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "93b08689b4c0a4862f2fa36455cf7bc4184fa0a6";
      branchTree = "b2da5a6b56885201eb936f94bec0e79dd0904a3b";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "bc3792339ec879f3375e241cb9079a1ec4523d16";
      branchTree = "459261c9767a3119244c55bd30a23287f5b1e040";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "e1f2ee6dd7f485bd1ae16aa3c77a2ab063d4c9e1";
      branchTree = "65670ef9953575370edcee88fb4d67686a3c947a";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "3392d53edd0d1b385df469d94c74c74403db4fcc";
      branchTree = "4876994ce1997fa8d8e71d2abb2f041e66304421";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      branchCommit = "8a65603e452a1250a27a256b91b6608d4156dd7f";
      branchTree = "481dafec5a8a12247d29400407e066aeb8b9b5d6";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      branchCommit = "b3deeb1b8576a57d528c0cace2ba6254a18f900e";
      branchTree = "75c4a854a5f613477094b13e259ac3357f099e8d";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped guest virtual-memory writes for synchronous white-box doorbell replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "52c20f02d3609db51042c07e849e191aaaf0750c";
      branchTree = "bba76c6d0fef7d7b1276ba82e45e3929c341ede0";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "e7c083fb6e441316a6083f006cef5621d27c5521";
      branchTree = "379bc92910170d260ef88c5f8c9f3497f80037d4";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "0cca0f65984e6c9ea7fc20e34b2f399eb474aa1e";
      branchTree = "199274a8dc65abd9bef2b0b15fa97901b5cde890";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "505e66b0b34ad6a8c41e50bba48bb7bcdd50cb5d";
      branchTree = "f4c226a9dc8dcd76c604e6e6c89249b7726f016e";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      branchCommit = "d7f86cc58818d8d97eea0a1221e9195297bf351a";
      branchTree = "e8237caa96f342f36bc11391c7731aa3b86e7883";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      branchCommit = "6a6189322506fd462093a1ce5ad9b0394d90b5ee";
      branchTree = "df04f6464a152789d4811989245a32b4f71739ff";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,FAULT-ORDER";
      capability = "versioned fault command registry, bounded result queue, and plugin ABI";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      branchCommit = "1a05b3386612b0cad3b4db93d44c69632d602ea0";
      branchTree = "fedacbdaf836839b37d534599d40ba9ce137b714";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement";
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
