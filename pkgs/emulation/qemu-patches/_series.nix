# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "dd5e97b5f96d1602fb03d2c0a9df64881f9af847c0f0114f91fa0e06db0ee21d";
  patchBranchBaseCommit = "0400e2d08acb30307af7cb214b21552807c1dd46";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "e4b752dd8373c62d92c70c5385886730ea2bd7dd";
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
      branchCommit = "e32846899f3904f6ec39873df178bec29cd1d45b";
      branchTree = "215c6fdfde2b91ac5da5c09edecadab2c4e024ca";
      catalogName = "crucible-architecture-register-faults";
      class = "D";
      enforces = "QFP-REG-1,QFP-REG-2,FAULT-ORDER";
      capability = "manifest-bound x86-64 and AArch64 register mutations at exact instruction boundaries";
    }
    {
      file = "0052-crucible-instruction-and-exception-faults.patch";
      branchSubject = "crucible: add instruction and exception faults";
      branchCommit = "f12078f4222c42e48dae0383913b77514d3588d0";
      branchTree = "15c69bdf79e102bd192d41a6b715228d9504fd9e";
      catalogName = "crucible-instruction-and-exception-faults";
      class = "D";
      enforces = "QFP-INSN-1,QFP-EXC-1,FAULT-ORDER";
      capability = "exact x86-64 and AArch64 instruction result, skip, replay, and architectural exception faults";
    }
    {
      file = "0053-crucible-interrupt-faults.patch";
      branchSubject = "crucible: add interrupt controller faults";
      branchCommit = "9f34c9f4225583dd484051ec781e1d62610a741e";
      branchTree = "11a78d1ec05aba79db9e53f13f5ee41e6a3ceb35";
      catalogName = "crucible-interrupt-faults";
      class = "D";
      enforces = "QFP-IRQ-1,QFP-IRQ-2,FAULT-ORDER";
      capability = "manifest-bound interrupt drop, delay, duplication, replacement, and bounded storms through realized x86-64 and AArch64 controllers";
    }
    {
      file = "0054-crucible-inject-architecture-hardware-errors.patch";
      branchSubject = "crucible: inject architecture hardware errors";
      branchCommit = "b49fcf5ca88aa628abe43ed034c88f2396f53b11";
      branchTree = "0403b1f4020669b19161521659e6e9eca592e013";
      catalogName = "crucible-hardware-error-inject";
      class = "D";
      enforces = "QFP-HWERR-1,QFP-HWERR-2,FAULT-ORDER";
      capability = "manifest-bound x86 machine-check, AArch64 RAS, and realized memory ECC delivery with transactional evidence";
    }
    {
      file = "0055-crucible-vcpu-service-control.patch";
      branchSubject = "crucible: control deterministic vCPU service";
      branchCommit = "a54ddd26ec88996c83788b530eda3c3102d266a4";
      branchTree = "8508bfa8d98824ad2672e063b18930ea746e54c1";
      catalogName = "crucible-vcpu-service-control";
      class = "D";
      enforces = "QFP-VCPU-1,QFP-VCPU-2,FAULT-ORDER";
      capability = "exact rational vCPU service, fixed-topology stall and offline state, bounded work conservation, and replay evidence";
    }
    {
      file = "0056-crucible-node-lifecycle-faults.patch";
      branchSubject = "crucible: add deterministic node lifecycle control";
      branchCommit = "e943d874b073688ab30d46a9a52e731b7223de66";
      branchTree = "c26ecd13c78e2d0b254615e8ebbe3559ab7c2cba";
      catalogName = "crucible-node-lifecycle-faults";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "deterministic node lifecycle transitions and schedulable node or vCPU hangs with closed state treatment and replay evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      branchCommit = "912cf023ce3d3c7bdc3189755106b460b45f24f1";
      branchTree = "d1abde7603af352ce6943bcced20abeeeb245014";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      branchCommit = "748eab8b282e6a8136d9a6598b1ba2de3c1a6e12";
      branchTree = "33e6bbad656c3eab63f01adb6030602311719cbe";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
    {
      file = "0062-crucible-block-transport-reset.patch";
      branchSubject = "crucible: add transactional block transport reset";
      branchCommit = "cc4c50d9158635acaf8fecc407979db889692249";
      branchTree = "3dada9278a9ea74968eaa1de0517a8fc19e89fd5";
      catalogName = "crucible-block-transport-reset";
      class = "F";
      enforces = "STOR-RESET,STOR-RESULT,DET-16,PATCH-26";
      capability = "transactional epoch-scoped block reset, recovery admission, retry dispositions, and declared topology re-enumeration";
    }
    {
      file = "0063-crucible-plugin-vmstop.patch";
      branchSubject = "crucible: hand exact checkpoint boundaries to VM stop";
      branchCommit = "28f27d9b1c450bdb24f8034eab52f58f4ee4ea95";
      branchTree = "19421484765155f90704552ebe37b60e8f825274";
      catalogName = "crucible-plugin-vmstop";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43";
      capability = "RR-global exact plugin checkpoint handoff with native pause and QMP flush-error propagation";
    }
    {
      file = "0064-crucible-terminal-lifecycle-completion.patch";
      branchSubject = "crucible: stage terminal lifecycle completion";
      branchCommit = "3d2a1ce540e0a4c9b4733b891bf8d706f46695bf";
      branchTree = "2204e5e8a4417b7dcba9f6821b38f55be230c2b7";
      catalogName = "crucible-terminal-lifecycle-completion";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "two-phase typed terminal lifecycle evidence, QMP authorization, and exact process-exit staging";
    }
    {
      file = "0065-crucible-authenticated-terminal-lifecycle.patch";
      branchSubject = "crucible: authenticate terminal lifecycle completion";
      branchCommit = "f6a7f1a6dccdd74f523eeab7c94ca26614e92789";
      branchTree = "6aa23229c39faa9762253891b45ef603cec25075";
      catalogName = "crucible-authenticated-terminal-lifecycle";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "dedicated idempotent QAPI terminal authorization bound to action, evidence, and process generation without guest resume";
    }
    {
      file = "0066-crucible-immutable-process-generation.patch";
      branchSubject = "crucible: provision immutable process generations";
      branchCommit = "4b77f109e55e1ac41ee5a313004948d61155f013";
      branchTree = "4e76dc8de0d8c5a2e79adb5e241afd7da530727c";
      catalogName = "crucible-immutable-process-generation";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "launch-time immutable process generation provisioning before fault-command admission";
    }
    {
      file = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      branchSubject = "crucible: serialize and harden core fault state";
      branchCommit = "d6b87a64f4ed96767b7e864b32a335137607a281";
      branchTree = "1b00797058e92964449950d071a6fb42f89d1752";
      catalogName = "crucible-core-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,FAULT-ORDER";
      capability = "transactional bounded VMState for core command, memory, CPU, interrupt, hardware-error, service, and lifecycle fault state";
    }
    {
      file = "0068-crucible-guest-clock-faults.patch";
      branchSubject = "crucible: guest clock faults";
      branchCommit = "75c48b0d71aee95f9ce0780d2793e3f099c1b5f7";
      branchTree = "abc8510490235e674d09a1e2b2539777b8732070";
      catalogName = "crucible-guest-clock-faults";
      class = "D";
      enforces = "QFP-CLOCK-1,QFP-CLOCK-2,FAULT-ORDER";
      capability = "transactional guest-clock transforms, source-state transitions, timer rearming, and typed causal evidence";
    }
    {
      file = "0069-crucible-accelerator-fault-device.patch";
      branchSubject = "crucible: add deterministic accelerator device";
      branchCommit = "733fa29e254e9860350e8df1d8dd556824eb1687";
      branchTree = "0d9a2211f7d2a4fbfa494843e2f90592576f007a";
      catalogName = "crucible-accelerator-fault-device";
      class = "D";
      enforces = "QFP-ACCEL-1,QFP-ACCEL-2,FAULT-ORDER";
      capability = "migration-safe virtio accelerator co-simulation transport with lifecycle, result, memory/ECC, and service mutations for closed GPU, TPU, and FPGA job schemas";
    }
    {
      file = "0070-crucible-fault-vmstate.patch";
      branchSubject = "crucible: finalize fault VMState identity";
      branchCommit = "1824b7b9e6d3f51adb52bfa77d217470ab7f4a88";
      branchTree = "6d62973f5fd1949e6e2ac7bcba48d436ca087295";
      catalogName = "crucible-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,QFP-STATE-3";
      capability = "live fail-closed build, patch-series, shared-memory ABI, and exact aggregate fault VMState identity";
    }
    {
      file = "0071-crucible-lifecycle-precondition.patch";
      branchSubject = "crucible: bind lifecycle preconditions to VM state";
      branchCommit = "8a02bda3caff97575e8fe3c6259df919aad0249e";
      branchTree = "d4674d64ef3f88ce8e264bf53af6d476f019d25f";
      catalogName = "crucible-lifecycle-precondition";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "atomic lifecycle prepare and commit over the same authenticated VM-state precondition";
    }
    {
      file = "0072-crucible-typed-node-result-schema.patch";
      branchSubject = "crucible: preserve typed node result schema";
      branchCommit = "2fc4903ebd03c7bab168f31d05b794e8638e2570";
      branchTree = "a37dec96939bcad4e2157a21351a5b7bea9a39a0";
      catalogName = "crucible-typed-node-result-schema";
      class = "D";
      enforces = "QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "fixed typed-command results with command-specific evidence retained on authenticated occurrence events";
    }
    {
      file = "0073-crucible-device-wait-vmstop.patch";
      branchSubject = "crucible: admit checkpoint stop from exact callbacks";
      branchCommit = "edd428b7b59d4e44b6a189300294380a48dca210";
      branchTree = "2923394e84f46db527fdc3663adf18cd4a255712";
      catalogName = "crucible-device-wait-vmstop";
      class = "F";
      enforces = "QFP-STATE-2,DET-1,INV-10";
      capability = "synchronous exact stop at drained control wakes with nonblocking admission from device-completion callbacks";
    }
    {
      file = "0074-crucible-arm-accelerator-result-opportunities.patch";
      branchSubject = "crucible: arm accelerator result opportunities";
      branchCommit = "d1bcc85285a77f92b361cd765d7fbf7ac575dda2";
      branchTree = "b57f3c4d9daaeaeca6e1423cdebb2532537e19ed";
      catalogName = "crucible-accelerator-result-opportunity";
      class = "F";
      enforces = "QFP-ACCEL-3,QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "atomic one-shot accelerator result arming with durable reservations and typed deferred completion results";
    }
    {
      file = "0075-crucible-restore-authenticated-fault-event-requests.patch";
      branchSubject = "crucible: restore authenticated fault event requests";
      branchCommit = "d32d7f0c4268471414aa286ca1a601d4f76aa403";
      branchTree = "0398e503aa99e14a5d30e09ca23e8bce8ef5b2df";
      catalogName = "crucible-authenticated-event-request-envelope";
      class = "F";
      enforces = "QFP-STATE-2,QFP-ACCEL-3,QFP-EVENT-1,FAULT-ORDER";
      capability = "mandatory authenticated request/evidence envelopes for fresh-process restore and exact accelerator-opportunity binding";
    }
    {
      file = "0076-crucible-9p-completion-wake-registration.patch";
      branchSubject = "crucible: register 9p completion wakes before plugin install";
      branchCommit = "659c8c043f85297a828b9dcd69ac0da06ec9069c";
      branchTree = "29d432c12ce261d0bff6a8d4d6406dc7275e2c81";
      catalogName = "crucible-9p-completion-wake-registration";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "realize-time 9p completion notifier registration independent of plugin installation order";
    }
    {
      file = "0077-crucible-serialize-rr-cursor.patch";
      branchSubject = "crucible: serialize authoritative RR cursor";
      branchCommit = "2d793409295884241bdf8f3ce00b9e263e08787d";
      branchTree = "0f005f0afc1bd6f8cb7f9ff371fde07df382d9a1";
      catalogName = "crucible-serialized-rr-cursor";
      class = "D";
      enforces = "DET-29,QEMU-34,QEMU-43,QFP-STATE-2";
      capability = "authoritative multi-vCPU round-robin cursor accounting and VMState restoration across host scheduling ceilings";
    }
    {
      file = "0078-crucible-fingerprint-guest-state-domains.patch";
      branchSubject = "crucible: fingerprint guest-visible state domains";
      branchCommit = "0a7d60e59a2f24ceb6b22bec3d00aba93a6157f4";
      branchTree = "762d9a7158da36e7b7fa350b40fa3d4910fe825e";
      catalogName = "crucible-fingerprint-guest-state-domains";
      class = "D";
      enforces = "DET-29,QEMU-34,QFP-STATE-2";
      capability = "guest black-box fingerprints exclude separately authenticated process-local control state and target-declared transient CPU notifications";
    }
    {
      file = "0079-crucible-stopped-state-control-progress.patch";
      branchSubject = "crucible: bound stopped-state control progress";
      branchCommit = "0edac7fb95507ab603a2841fbed9deb6fc2e5199";
      branchTree = "5d0a8f256f53167fb677456b0f3f6c2af5d6c357";
      catalogName = "crucible-stopped-state-control-progress";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43,QFP-STATE-2";
      capability = "level-triggered stopped-state control progress with queued-work admission and a bounded BQL wait";
    }
    {
      file = "0080-crucible-inactive-retention-clock-guard.patch";
      branchSubject = "crucible: guard inactive retention clock reads";
      branchCommit = "af3169e18940cd436c3b5535ead446f09c356575";
      branchTree = "4fd1e1b5e7b25118ab21d7b2a24bcaeaa2de697c";
      catalogName = "crucible-inactive-retention-clock-guard";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "memory-retention clock sampling only after an active-rule admission check so fresh-process restore cannot observe an irrelevant transient clock sentinel";
    }
    {
      file = "0081-crucible-deferred-result-evidence-test.patch";
      branchSubject = "crucible: validate deferred result evidence";
      branchCommit = "c962f4173601595a6d42556d5c1cea89e6532a1c";
      branchTree = "8b48e869db558c9f9b7345e79dc3e38b384584e9";
      catalogName = "crucible-deferred-result-evidence-test";
      class = "F";
      enforces = "QEMU-44,FAULT-EVIDENCE";
      capability = "live instruction-fault coverage validates the canonical typed evidence added to deferred completions";
    }
    {
      file = "0082-crucible-deterministic-instruction-input-state.patch";
      branchSubject = "crucible: stabilize instruction input selectors";
      branchCommit = "d463f12b8fd47f3e4f6c6f5ae15d96c9e058c761";
      branchTree = "7ce2631153030c6faea9b54672d170257c834ab8";
      catalogName = "crucible-deterministic-instruction-input-state";
      class = "D";
      enforces = "DET-1,QEMU-44,FAULT-EVIDENCE";
      capability = "instruction input-state selectors use a cross-process-stable architectural-register digest while full CPU, RAM, and device state hashes remain in canonical evidence";
    }
    {
      file = "0083-crucible-inert-clock-restore.patch";
      branchSubject = "crucible: preserve clocks across VMState restore";
      branchCommit = "d53823a3d9bc0991d37ef24b7020ae0aa5d13acb";
      branchTree = "fd608e5894fea3dea0976871ba5a911d5c41c29a";
      catalogName = "crucible-inert-clock-restore";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,QFP-STATE-2";
      capability = "the complete VMState load transaction suppresses transient guest-clock transforms, then a successful outermost restore retains native timers, including HPET timers without a fault-managed generation, and rearms effective Crucible transforms";
    }
    {
      file = "0084-crucible-exact-restore-network-announcement.patch";
      branchSubject = "crucible: suppress migration announcements on exact restore";
      branchCommit = "5ab8c82a9ee626e022e40e79d54c495b0b6acb74";
      branchTree = "8ceef8ec8f94f13657266301e5274e98fe0833ee";
      catalogName = "crucible-exact-restore-network-announcement";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "exact Crucible VMState restore suppresses migration-only virtio-net guest announcements while ordinary QEMU migration retains its upstream announcement behavior";
    }
    {
      file = "0085-crucible-register-rejection-atomicity.patch";
      branchSubject = "crucible: prove register rejection atomicity";
      branchCommit = "b5bf0a99dd6152728e93f339cf9689769471ad73";
      branchTree = "e51377bb1adf6be8ddb6e63b536869594504b165";
      catalogName = "crucible-register-rejection-atomicity";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-REG-2,FAULT-EVIDENCE";
      capability = "exact RR ownership gates canonical register observation; every realized CPU manifest is validated; rejected register commands preserve every canonical GDB register byte and all six mutation side-effect counters";
    }
    {
      file = "0086-crucible-genesis-observation-boundary.patch";
      branchSubject = "crucible: admit genesis observation boundary";
      branchCommit = "593687ed5ff9c4a2f07acc0d987295b8c0542c71";
      branchTree = "669eb1ea3cc4852951fb5ae82147dec3ccda5507";
      catalogName = "crucible-genesis-observation-boundary";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "the BQL-held prelaunch genesis boundary admits complete all-vCPU architectural observation only at exact raw icount zero";
    }
    {
      file = "0087-crucible-deterministic-rcu-quiescence.patch";
      branchSubject = "crucible: defer host RCU kicks in sim";
      branchCommit = "eae515e268ec284f1773e72d926860d1178962c1";
      branchTree = "dc13f6fb07ecd2d6ad748b50097c8e21fad3caa6";
      catalogName = "crucible-deterministic-rcu-quiescence";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "sim mode reaches RCU quiescence at its bounded deterministic RR execution boundaries without host-timed translation-block exits";
    }
    {
      file = "0088-crucible-deterministic-host-kick-boundary.patch";
      branchSubject = "crucible: defer generic host kicks in active sim slices";
      branchCommit = "79780f4de0d08c3ef2ad43019d787ade68f0294a";
      branchTree = "e6dd34d7a989df6352ed4a6f6aad38098832a3f9";
      catalogName = "crucible-deterministic-host-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "during an active bounded sim slice, state-free host latency hints cannot choose a guest boundary, while between-slice, zero-icount startup, admitted terminal pause, stop, unplug, halted, stopped, and interrupt-request kicks retain immediate exits";
    }
    {
      file = "0089-crucible-exact-boundary-vcpu-introspection.patch";
      branchSubject = "crucible: admit vCPU introspection at exact boundaries";
      branchCommit = "0e16a87a0e79c39d6c07d5b02169c5e118228780";
      branchTree = "1bdcbb1934ac36da79f25d7e78bec7b911a3dc65";
      catalogName = "crucible-exact-boundary-vcpu-introspection";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact BQL-held main-loop boundaries read every quiescent vCPU register file and the committed RR cursor without a current vCPU, while arbitrary unowned contexts remain rejected";
    }
    {
      file = "0090-crucible-active-tcg-kick-boundary.patch";
      branchSubject = "crucible: defer generic kicks to TCG boundaries";
      branchCommit = "260c90b9564b99764ec70442d26d4ee5ee588143";
      branchTree = "6bbc6b736a157cbbc62092c925ac4a4ef3e16bd9";
      catalogName = "crucible-active-tcg-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "state-free sim kicks request exit at the next deterministic translation-block boundary while committed transitions preserve immediate liveness";
    }
    {
      file = "0091-crucible-canonical-rr-genesis-cursor.patch";
      branchSubject = "crucible: expose the canonical RR genesis cursor";
      branchCommit = "53d1c54de86a867fafa21936aa090b6de8e8fd5b";
      branchTree = "4762a69a59020bf84d761d6f2a1e18d3df4856e9";
      catalogName = "crucible-canonical-rr-genesis-cursor";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact raw-zero observers read the unique next RR coordinate without mutating scheduler state while every later invalid cursor remains rejected";
    }
    {
      file = "0092-crucible-canonical-terminal-rr-cursor.patch";
      branchSubject = "crucible: canonicalize terminal RR observations";
      branchCommit = "e4b752dd8373c62d92c70c5385886730ea2bd7dd";
      branchTree = "c9084d25cd61d01f8ab29b98d2700f509551be04";
      catalogName = "crucible-canonical-terminal-rr-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "live observers at a quantum terminal project onto the next scheduler-owned vCPU at position zero without mutating serialized RR state";
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
