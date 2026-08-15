# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "7cd84438ba12f0939fd3f2a8d6672626c9bfb3a4626fefecbf8dcab2ae48c78f";
  patchBranchBaseCommit = "0400e2d08acb30307af7cb214b21552807c1dd46";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "9e59d692567bfa96c67c779b9870baf592e7053c";
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
      branchCommit = "17d8e6cc2744b136f565d0eb51ccba9ed88223ad";
      branchTree = "23dc6ae894b945c82a9e79e15c82665b5e69c604";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "eb8047357b6c7973119e931c783647245c34fd08";
      branchTree = "1ca7e7b338e53f5b1f44b4e4ab4d40a837e930e7";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "0e08d666453938cbca281e60eeb7978afd25274d";
      branchTree = "90a039bb166611318048212dafb58259e1e36319";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "06fae2cb8bceae9f277a342b5ec7863af8a260e3";
      branchTree = "e82978a12d1c6884e7e60be3baddbd4682831a53";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "964c399a292f2c01b787e6d0ed158a0dc1ef34a4";
      branchTree = "c1b67918dd04ec8cc73284829a4d69d347bd08a5";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "070600f25ba2e195bf9371a5f01d42a494bec535";
      branchTree = "1b1b3816d337e9949439e3a02d9e3eab203d38c1";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "06d65b959fb94b7a11ed04d1b9720a5a4ad886ab";
      branchTree = "73a60003b165c620f23799201a05f009acd541a1";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "678670f9e02ea8b43dfc7752dcf097d9caa51e21";
      branchTree = "8f5b9a33cbb804ff40bf77c031a03c2ed68a5254";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "37c1d955e3ce1a6775773e95cc9fd1436c54e9a0";
      branchTree = "9d0616e43c6df4119bf8adf732e8ebd05b71ac86";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "eb8c959dff26316911b5b5596e030e22f3f988bf";
      branchTree = "ba10dcf73731d7361a68c9d4b218886ad0405e86";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "bfc2c88d8bcaa1f178a91c1cb7a00ac869f93150";
      branchTree = "e4bff7772965ad362136a767d70b670bc3dca16b";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "e4e6530c237aa8e1ecaceeed80ea15eaf8caa7ea";
      branchTree = "fa4d9f8fdeebc96943680f61159af30d8921c878";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "7adcdabe835de6dbd99e1971f661a6e934d8a515";
      branchTree = "3b4d1b13ed358e71a6b7ffb8159b749029533a27";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "c5eccb1e1d92720d6a5f84138c854d68fd5eb888";
      branchTree = "c2aaec854b60d05d56ee008a3700f236c4421340";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "3eef97b91d6ebb123ce05300db5f67809faa4215";
      branchTree = "f3b717d92780ffd9bca96b2af7f9f025e3fe07c6";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "14a9adfda6d30fcf9174c4ef998d67caf57f318a";
      branchTree = "dc13061595a87d7dbeabef810d4662afc25b1694";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "f4906b4063cebe3f355a99ea9256698139e7a675";
      branchTree = "8b59daa98492f3e562b99c02cfcb350363f5318e";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "d4954ab75c3b980a3d30ad92c265d38531d7ec03";
      branchTree = "19b44c0583b2b78797716ba046f2f54dc35cfb87";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "4be705bc0b22f5e75682e4be56034eceb604cc52";
      branchTree = "e7ab21a2a296eee489051349e11a9bbc12e7d26f";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "bda4a5aff285f596701ffd9a97bbd29061e56a06";
      branchTree = "f5f0dbcd0e4d31e4211ad534bf98da2cbc4d17bf";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "055c82276f253b230b0d3253f9410e274789fcd3";
      branchTree = "b0195b20be019b1be4af94214747249ff89c5f91";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "e3188ef1bf43dd1e3226fc8cd794b853ce569edc";
      branchTree = "d015671c7a8ad73fd1182733429fa55036d08edd";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "02dd170afbf2aeff1dc5f27e12abe4f1a0cb2304";
      branchTree = "82d8198e5a761ab6a74ca80e1bae2173462dc822";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "cbcc37036e1aa38c07517b59597439d419e9c618";
      branchTree = "f5f23eb69e604cb76524378d6ae5cdd560c8a4b8";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "734dd4691db579d64284add2684452f386533d2a";
      branchTree = "9482fc46edf0a1060d156094c860a7c227467281";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "f034e34dc70ba8d5abbb90c6611464539df1a563";
      branchTree = "c62f0b0a2b6b500312e89d2abb874df63b8098ef";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "309da07ea70558b25c9775d239522a4f5088a3cb";
      branchTree = "64064e9c66b24fb065c6966ce4aee2c3bd071f69";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "5b3978f9bfca19635996f437a7a3385d22b03b3f";
      branchTree = "5c4359f5224d552b47efdefd3897481802835f5c";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "0ec4824a91fb1aad8dd519ba97707a70fcd447a3";
      branchTree = "e430cd8696caa5b51922204497d45c995577a3ab";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "2e79ac320fbaa33f307f471352f813160d352389";
      branchTree = "e07e6bb5cb2b779b4fa7ded76dc955b0ea3910a7";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "83b04a8ce6c37ca1b12b503a0c0c17cd140837b4";
      branchTree = "a2bb4515bd741315a8b7e0fd984b3e9da6974579";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "ba05c46a5d9153853c3d526cdeebe44197a60173";
      branchTree = "bc32b25bbbe6a9d4cff64e44526b5878bc8bd1df";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "a8d0faa1295d8d87a4bc3836adeac49ae848698f";
      branchTree = "5f21f4ce0cf500eb87cda3f8975cf9b164d5f084";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "5c0e2da2e9461e74ca83d62fb8a9dbc32353ece6";
      branchTree = "217f70818650b940724d4d3d8dfb97fa63b1860c";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "fa266dc333da413dc88beb3569efa72070078aec";
      branchTree = "177163764446a3e4ac04846ad87b533cc0378552";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "10606f46fb6710a8df860287bef90b77c2250df6";
      branchTree = "f72d328f82bc63ee36a401282492f460482f6f49";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "942741079d64918abff5b8e700a5ada16228abcf";
      branchTree = "33b3753a19b74177ca7f323198427a7c0277f0ed";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "9929da3fc8507258b57c2aa07a237d7237cf08a3";
      branchTree = "8f99375fccdf9adae3014eec6d47a5c566a121f8";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      branchCommit = "a95e0154648505941c1eb26e882c94ea8c73dbba";
      branchTree = "9c7e3efdc9d844a3d7cc5c55aaa82ff07444e981";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      branchCommit = "b32f83874e5d75b5581adfbcf0ecb63ab7d84cb2";
      branchTree = "73f9fcab6049c3143d3e707d1381fbd2ad0f9415";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped guest virtual-memory writes for synchronous white-box doorbell replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "244a6bb4979d85cd00572fc32772c1756c2b3d0e";
      branchTree = "7705c290ae8ec9e5e3b2add9044f44dca85243b7";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "89a15bdcd38e0ca12ded9af10bfdad6d3db05763";
      branchTree = "ed42f964b301ddfbef08462bdc859c2c4c04edd5";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "b8b141eaaa0bdca2f93173d988f09f6e17950710";
      branchTree = "5a07309dde2302935fc7e06ad209e3982bfac271";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "b93ba97a947dee9d3fee20720e121a3376f9015d";
      branchTree = "900a56e50d2526984ec4b65d9101d9b97748d3ab";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      branchCommit = "f43002dbd40efb28d865ac897e960565c398493f";
      branchTree = "619e224e4914e0ffee8fe3df7498ea0495875214";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      branchCommit = "40bb20a6072faa08ec9ff58b88f029e1902effef";
      branchTree = "c155b194e8433dc8058c550d007892af3566752f";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,FAULT-ORDER";
      capability = "versioned fault command registry, bounded result queue, and plugin ABI";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      branchCommit = "a8e1c1efb98109cde27e837463cc611bfa9bbf8d";
      branchTree = "09353d2cac767bcb5eac0057bcc5993c07283c60";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement and same-boundary prepare/commit completion";
    }
    {
      file = "0049-crucible-memory-boundary-mutate.patch";
      branchSubject = "crucible: atomically mutate guest memory batches";
      branchCommit = "ff7384edb4b0ff91a0b34ab9f82d0295ca81410a";
      branchTree = "7e7ebaf2d127343331fe43da20212dfa969d8708";
      catalogName = "crucible-memory-boundary-mutate";
      class = "F";
      enforces = "QFP-MEM-1,QFP-MEM-2,FAULT-ORDER";
      capability = "atomic ordered GPA/GVA mutation batches with translation, RAM-map, dirty-page, and TB evidence";
    }
    {
      file = "0050-crucible-memory-access-faults.patch";
      branchSubject = "crucible: add memory access fault rules";
      branchCommit = "b7f6580ee13fde0a58ecf12ccc114c933d5570fd";
      branchTree = "5e658e827fd1c65b637335f91516b91828075411";
      catalogName = "crucible-memory-access-faults";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "typed fetch, load, store, page-table walk, atomic, and identified virtio DMA memory fault rules with shared service and persistent region state";
    }
    {
      file = "0051-crucible-add-architecture-register-fault-mutations.patch";
      branchSubject = "crucible: add architecture register fault mutations";
      branchCommit = "b2c138d222e135d888752cc33696d604bda01492";
      branchTree = "9d37c5c5e0e61bc8f9b355c38abab909212f29e0";
      catalogName = "crucible-architecture-register-faults";
      class = "D";
      enforces = "QFP-REG-1,QFP-REG-2,FAULT-ORDER";
      capability = "manifest-bound x86-64 and AArch64 register mutations at exact instruction boundaries";
    }
    {
      file = "0052-crucible-instruction-and-exception-faults.patch";
      branchSubject = "crucible: add instruction and exception faults";
      branchCommit = "d993f6200e88ba89065191ffba55741693921b43";
      branchTree = "af20d87e821c31a2d658b06b31a87d136fdeb10c";
      catalogName = "crucible-instruction-and-exception-faults";
      class = "D";
      enforces = "QFP-INSN-1,QFP-EXC-1,FAULT-ORDER";
      capability = "exact x86-64 and AArch64 instruction result, skip, replay, and architectural exception faults";
    }
    {
      file = "0053-crucible-interrupt-faults.patch";
      branchSubject = "crucible: add interrupt controller faults";
      branchCommit = "01dfecad49d62b6c72c15a64974767fc4feed4a0";
      branchTree = "8d38f6f763a74d8330677a5e8a40544700c7ebde";
      catalogName = "crucible-interrupt-faults";
      class = "D";
      enforces = "QFP-IRQ-1,QFP-IRQ-2,FAULT-ORDER";
      capability = "manifest-bound interrupt drop, delay, duplication, replacement, and bounded storms through realized x86-64 and AArch64 controllers";
    }
    {
      file = "0054-crucible-inject-architecture-hardware-errors.patch";
      branchSubject = "crucible: inject architecture hardware errors";
      branchCommit = "e6d2acc4202f876913543ebb58e79392b76310ad";
      branchTree = "f2b69d235ce33d2d93cc10643c754f3548eae6a8";
      catalogName = "crucible-hardware-error-inject";
      class = "D";
      enforces = "QFP-HWERR-1,QFP-HWERR-2,FAULT-ORDER";
      capability = "manifest-bound x86 machine-check, AArch64 RAS, and realized memory ECC delivery with transactional evidence";
    }
    {
      file = "0055-crucible-vcpu-service-control.patch";
      branchSubject = "crucible: control deterministic vCPU service";
      branchCommit = "2b4a22914753ddde663f3e4919c4d2d2097353c9";
      branchTree = "be424cb052d30294291f280f4362294f365431cd";
      catalogName = "crucible-vcpu-service-control";
      class = "D";
      enforces = "QFP-VCPU-1,QFP-VCPU-2,FAULT-ORDER";
      capability = "exact rational vCPU service, fixed-topology stall and offline state, bounded work conservation, and replay evidence";
    }
    {
      file = "0056-crucible-node-lifecycle-faults.patch";
      branchSubject = "crucible: add deterministic node lifecycle control";
      branchCommit = "5947f1d6574f5c50a24123762f9da78f36af2346";
      branchTree = "57dad04a22e89fe28cb432fb0f25732609e6c1cc";
      catalogName = "crucible-node-lifecycle-faults";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "deterministic node lifecycle transitions and schedulable node or vCPU hangs with closed state treatment and replay evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      branchCommit = "a9501e9a952253ec0748161145880e3a12b7ffc5";
      branchTree = "1ebca39b3083b46c403c339b4dca720e20a4dc93";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      branchCommit = "12fbe517105a464689f40ce5a6ea47cc80b5a719";
      branchTree = "f23f68dde53d523757ba5f3650e50e5d460d25f1";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
    {
      file = "0062-crucible-block-transport-reset.patch";
      branchSubject = "crucible: add transactional block transport reset";
      branchCommit = "d57293e344dcb0dd7d6e17de758d3d5a97291f0c";
      branchTree = "c95d90d7144cc1adb62f8db17572e77f115c5093";
      catalogName = "crucible-block-transport-reset";
      class = "F";
      enforces = "STOR-RESET,STOR-RESULT,DET-16,PATCH-26";
      capability = "transactional epoch-scoped block reset, recovery admission, retry dispositions, and declared topology re-enumeration";
    }
    {
      file = "0063-crucible-plugin-vmstop.patch";
      branchSubject = "crucible: hand exact checkpoint boundaries to VM stop";
      branchCommit = "e086518cc99239fce5e91f734eba035eb7f2d237";
      branchTree = "36a5824a1e27de437c08e5b7c203a7129b5b50d5";
      catalogName = "crucible-plugin-vmstop";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43";
      capability = "RR-global exact plugin checkpoint handoff with native pause and QMP flush-error propagation";
    }
    {
      file = "0064-crucible-terminal-lifecycle-completion.patch";
      branchSubject = "crucible: stage terminal lifecycle completion";
      branchCommit = "1e3983453b3db2b25f96896e0f45f7153a52b07a";
      branchTree = "651ac33f444c22228cfde8081b8b4f1c087e7e75";
      catalogName = "crucible-terminal-lifecycle-completion";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "two-phase typed terminal lifecycle evidence, QMP authorization, and exact process-exit staging";
    }
    {
      file = "0065-crucible-authenticated-terminal-lifecycle.patch";
      branchSubject = "crucible: authenticate terminal lifecycle completion";
      branchCommit = "615308302039848dafd1bb824990bf9e9392a0c7";
      branchTree = "587127981869487f2de3d6d3f6783ac06fc8ab61";
      catalogName = "crucible-authenticated-terminal-lifecycle";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "dedicated idempotent QAPI terminal authorization bound to action, evidence, and process generation without guest resume";
    }
    {
      file = "0066-crucible-immutable-process-generation.patch";
      branchSubject = "crucible: provision immutable process generations";
      branchCommit = "4c514d1fca48d867fd499b98b09632b86e6275a9";
      branchTree = "07e26b2824954d9f063f8bbbd7ecdbece357e36c";
      catalogName = "crucible-immutable-process-generation";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "launch-time immutable process generation provisioning before fault-command admission";
    }
    {
      file = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      branchSubject = "crucible: serialize and harden core fault state";
      branchCommit = "63caa7139cde6600af97bc4af4e67bb2a9a20c39";
      branchTree = "b548465e6773cdbf862a8b493d007209108c1176";
      catalogName = "crucible-core-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,FAULT-ORDER";
      capability = "transactional bounded VMState for core command, memory, CPU, interrupt, hardware-error, service, and lifecycle fault state";
    }
    {
      file = "0068-crucible-guest-clock-faults.patch";
      branchSubject = "crucible: guest clock faults";
      branchCommit = "92b71f621ef9689a56072d917352370a8bcc4d31";
      branchTree = "7889224b6d7991441177b9ea9c60fe2c568a0859";
      catalogName = "crucible-guest-clock-faults";
      class = "D";
      enforces = "QFP-CLOCK-1,QFP-CLOCK-2,FAULT-ORDER";
      capability = "transactional guest-clock transforms, source-state transitions, timer rearming, and typed causal evidence";
    }
    {
      file = "0069-crucible-accelerator-fault-device.patch";
      branchSubject = "crucible: add deterministic accelerator device";
      branchCommit = "98d982ae06eacd02aed4e4f129915836320b3796";
      branchTree = "973accb1e079d13b6a61a8b4493815691436b74a";
      catalogName = "crucible-accelerator-fault-device";
      class = "D";
      enforces = "QFP-ACCEL-1,QFP-ACCEL-2,FAULT-ORDER";
      capability = "migration-safe virtio accelerator co-simulation transport with lifecycle, result, memory/ECC, and service mutations for closed GPU, TPU, and FPGA job schemas";
    }
    {
      file = "0070-crucible-fault-vmstate.patch";
      branchSubject = "crucible: finalize fault VMState identity";
      branchCommit = "496565b866ef9fcddda6cf1bcc712fee0e9dbb74";
      branchTree = "1a06d2ded9805e2acc435aed59c672ccbe17c433";
      catalogName = "crucible-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,QFP-STATE-3";
      capability = "live fail-closed build, patch-series, shared-memory ABI, and exact aggregate fault VMState identity";
    }
    {
      file = "0071-crucible-lifecycle-precondition.patch";
      branchSubject = "crucible: bind lifecycle preconditions to VM state";
      branchCommit = "8733958170a191a9d00661c693a9573804a2bcb5";
      branchTree = "3d0e9d404d983d26fb15c3489863fa4207d32754";
      catalogName = "crucible-lifecycle-precondition";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "atomic lifecycle prepare and commit over the same authenticated VM-state precondition";
    }
    {
      file = "0072-crucible-typed-node-result-schema.patch";
      branchSubject = "crucible: preserve typed node result schema";
      branchCommit = "9d92a81c52257e14f6d9fa621ff0af248dec0adb";
      branchTree = "a0df3f30ed480bd4d6cfc3523f9b64ea33f2784b";
      catalogName = "crucible-typed-node-result-schema";
      class = "D";
      enforces = "QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "fixed typed-command results with command-specific evidence retained on authenticated occurrence events";
    }
    {
      file = "0073-crucible-device-wait-vmstop.patch";
      branchSubject = "crucible: admit checkpoint stop from exact callbacks";
      branchCommit = "e0580798f2669227edf5f68540496a3bc228087d";
      branchTree = "f2f41a2fed99fbcb512f6cb984f1bc6f58ec2c8d";
      catalogName = "crucible-device-wait-vmstop";
      class = "F";
      enforces = "QFP-STATE-2,DET-1,INV-10";
      capability = "synchronous exact stop at drained control wakes with nonblocking admission from device-completion callbacks";
    }
    {
      file = "0074-crucible-arm-accelerator-result-opportunities.patch";
      branchSubject = "crucible: arm accelerator result opportunities";
      branchCommit = "27ba14c1667da56b9ec7b385ee033226142bd0ce";
      branchTree = "a74340222ced61c5b015cb3ffe00a7ec85659aa9";
      catalogName = "crucible-accelerator-result-opportunity";
      class = "F";
      enforces = "QFP-ACCEL-3,QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "atomic one-shot accelerator result arming with durable reservations and typed deferred completion results";
    }
    {
      file = "0075-crucible-restore-authenticated-fault-event-requests.patch";
      branchSubject = "crucible: restore authenticated fault event requests";
      branchCommit = "9e59d692567bfa96c67c779b9870baf592e7053c";
      branchTree = "524522633c502d086256ea8d149c581d6415bf4a";
      catalogName = "crucible-authenticated-event-request-envelope";
      class = "F";
      enforces = "QFP-STATE-2,QFP-ACCEL-3,QFP-EVENT-1,FAULT-ORDER";
      capability = "mandatory authenticated request/evidence envelopes for fresh-process restore and exact accelerator-opportunity binding";
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
