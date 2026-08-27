# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "66e2e4573cf4a61fff2ba1ce19510812b5eb046fae758fa8399e08070c2b6335";
  patchBranchBaseCommit = "0400e2d08acb30307af7cb214b21552807c1dd46";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "e130dd1f8c3891df306ac7a26d2b8943c5349e1d";
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
      branchCommit = "3c9a33bfbc5fec7ba028674439ce69c287d0ba6d";
      branchTree = "6c0adf16b26c6f35f4aa34191cb506f4392a8b38";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX direct injection with canonical shared-memory backpressure and fresh guest-device probing on every retained retry";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "d66240f95eb39b2c5cdc036a8ff81b8d4ab609da";
      branchTree = "9b01bb09da95d48e25dd15bd291738235acea9f5";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "7d022389d862fb50a0137bba36302cb19e3533be";
      branchTree = "3c5468bd07c556648004f564d502d70098a509a7";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "deb2a424c4f1fc8edb0e263aa3ed58c87bc7b42d";
      branchTree = "e29ec8eb366456502ac7a15fb34c710d44761312";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "cc872785732f4f8ecd199e89be5f283ea3923a36";
      branchTree = "58e4e091332753e69c4e7c029e119bcdd9fa344a";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "a053b92e1357d86065d58994ea4923b57085955c";
      branchTree = "797129222d137cee55328918e66ab00330b1ecec";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "24c4b770019d8c13f3ee3edd3a8316d24541c7a9";
      branchTree = "7b3aeb9943ca83ca58a6428c9911819363cbcbc0";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "75e6193f809a2ffce1b3ab13dad3ee3ef19b7136";
      branchTree = "609f1bcd9487d66442cc981230d15f25f2d119a6";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "d2905ec952373629860a5ce56eca5e098d28d4c1";
      branchTree = "641de63aaaf5d7bd59d556219bad5bc11d54a0af";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "efa82758e1946d81ad151ffb97c3c7cb29ae5f4a";
      branchTree = "c3657dc838ae59d823a797be49bacc8cb83c723c";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "a95a9f520b00e9d211cc2e7d40833c2126b1a8c5";
      branchTree = "885ecca6908def294be8d49066bd0ae9bccc0fb7";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "bcf33730ee0b40928205aeeed51ebcbea3500147";
      branchTree = "0c22f1c74760373ef5c36473cdc4eacac1d8290d";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "c1ddd36cfa54b7e76090f85ffed7bb177ad07106";
      branchTree = "0cbff1c45c7bab8d9876d24206e818c71e59aa06";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "0406bafdcd7ad2cd6ceed2434a2b7fb9ce396b9c";
      branchTree = "092c809790703b39a802d62d1c06b1aa6091982e";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "02d6374c4fa7945bcc1a130559db6923901dc098";
      branchTree = "fc6b398f04c3f18d977505fd1c55b90f2495946e";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "b90d354c4a76acd7654cfdca0e5018b92b1a5bd1";
      branchTree = "e676c2f114d7067aabfd587644e6d2f66dcde875";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "2dcd7bcad83c22e0d2ccc332578bbbc2659d48ee";
      branchTree = "1ca62bb8f23ad5673b83b3c7da5e06f5a0c88880";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "90db706dfafb934b4415a7d67ed9622713e0a8d3";
      branchTree = "3e2e7529fef086dd792c0d5d99bd8b8f19556503";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "85a146c613f38443e71e823c8216abfe72fb2273";
      branchTree = "115862651208e711c5e37ebe0b5b09f2ba478bc8";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "cef1eda7fd9c1e19dc08b8166cf2ba1f6d7e10eb";
      branchTree = "00308c8ec732bd37c7cd393d356f46fcfe9b207f";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "30ae923444e4e5dbe3985bd441c0937f93f6bdfb";
      branchTree = "5bb3cbc831af69d1f93580888660bdddaeabaa66";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "77b088046ac7bd4bb81574fd1e21f1bb3526f8dc";
      branchTree = "85800985191ece332223bd8d1277bdc689d4d644";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "88d4c573c2f86bbc3831251e4ba1b60c001e1cd2";
      branchTree = "cdbf2d0851524af9c164240ffaf0263e2ee46e6a";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "f7a3e612df5107ca901e664fd91ac1ffdd3bb210";
      branchTree = "bd1c0ea3f189627dc7706351d9155e0c4a3cc8e7";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "485a3ed2fe4dc5be2a324f8a0358648673d63c39";
      branchTree = "d3a00fcef83373d570db551ad20b42d24858fd96";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "f17ee39e81d27945e2025d7aadf22ac5e7beddc4";
      branchTree = "89aa710a9f6ce2b093cfa24583f6089aa397a6e3";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "58a343eb95bc873bcac662275e051d9aafda04e6";
      branchTree = "9f4e5c0797edb151281c537f5928c37e661b009b";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "47ef524fdc1cd70d45ec70ee0146e847f332ddd3";
      branchTree = "ab7012bcdaa5fffe65062286f65ddf53dbe5b91b";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "7eac6b977ec28828c8d8efdb44b17cd8361acf3a";
      branchTree = "094618061d9eaa3a8540497b7ca01381ccc2f558";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "7165faf28dc96dc643508cf293d1e9fd78b658b1";
      branchTree = "4043e6bb518dac8a4b7c79f1f636debedac0b9d7";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "a9ecddee62951030ea1b41677a5272194ca140c9";
      branchTree = "f5231896155e82e102ad300cee869cd4e651bd8d";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      branchCommit = "9ffac05b10260d81d362dbd9a09de83275ef39c6";
      branchTree = "b35cf01852bbacf3a96f80252c2855e1a7144f8f";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      branchCommit = "ee26741fe0e2c7024667ebb7aa74b8940e4bc374";
      branchTree = "006a3d647927ec46bef8746f19fd032188689e68";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped current-vCPU and exact resume-vCPU guest-memory writes for deterministic white-box replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "cf95397cf3b21e280c269e829e07555ef202a94b";
      branchTree = "8f02aad8f5c19a567700c9472c816693679a3a34";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "cfceaed988117cd273ceeb8329a533922122657d";
      branchTree = "325a5c42f942b2ca91fd255bace190140e1c3551";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "edf0ea85db1173974542e0947d568c6aa9ace73b";
      branchTree = "419afc3f8a51d12330f666f83275b75d3cb187bc";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "0bb30a26d1cbd2d32201de2c568145ddc8965937";
      branchTree = "73a975ea3091525bceb0eb0bc0fee87a337aebc5";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      branchCommit = "fdb4f9d35af1524ff432188033cb9f800a869034";
      branchTree = "d3bb7b139baa1462ddafe10afb6fce8db68f4277";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      branchCommit = "b05a00f34a4cc74cfc5a4d6b5e1cdc7d84609bed";
      branchTree = "8ec10b4fbbba1d3b8f84b35cc7878db2fa4202c3";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,FAULT-ORDER";
      capability = "versioned fault command registry, bounded result queue, and plugin ABI";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      branchCommit = "84765daa78b1fa424ceb5730475a60a1f4bd5e8c";
      branchTree = "4f4bd2579e5d3f0dc57781c2cd711dc5ebd0d40c";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement and same-boundary prepare/commit completion";
    }
    {
      file = "0049-crucible-memory-boundary-mutate.patch";
      branchSubject = "crucible: atomically mutate guest memory batches";
      branchCommit = "eb477c9b4492bf5ca9ceb426120a2fad45ba1642";
      branchTree = "65e45222418470e2624c88c7af6d98e3ebd1fd67";
      catalogName = "crucible-memory-boundary-mutate";
      class = "F";
      enforces = "QFP-MEM-1,QFP-MEM-2,FAULT-ORDER";
      capability = "atomic ordered GPA/GVA mutation batches with translation, RAM-map, dirty-page, and TB evidence";
    }
    {
      file = "0050-crucible-memory-access-faults.patch";
      branchSubject = "crucible: add memory access fault rules";
      branchCommit = "399f997206c9464d82189dd2eb5e9288c5cca426";
      branchTree = "6f964f0ebd1dddb2aba0489f91078660f20501e4";
      catalogName = "crucible-memory-access-faults";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "typed fetch, load, store, page-table walk, atomic, and identified virtio DMA memory fault rules with shared service and persistent region state";
    }
    {
      file = "0051-crucible-add-architecture-register-fault-mutations.patch";
      branchSubject = "crucible: add architecture register fault mutations";
      branchCommit = "ec4d0b1102900c98807027765339f0a3a5912d1c";
      branchTree = "4d482dfbce8d034d658add396fc4af654dd31681";
      catalogName = "crucible-architecture-register-faults";
      class = "D";
      enforces = "QFP-REG-1,QFP-REG-2,FAULT-ORDER";
      capability = "manifest-bound x86-64 and AArch64 register mutations at exact instruction boundaries";
    }
    {
      file = "0052-crucible-instruction-and-exception-faults.patch";
      branchSubject = "crucible: add instruction and exception faults";
      branchCommit = "369931bf67a6317afd0c5d788837cbe038354dad";
      branchTree = "23813d6ad31f3a513f898a52d55b5b5a1e094794";
      catalogName = "crucible-instruction-and-exception-faults";
      class = "D";
      enforces = "QFP-INSN-1,QFP-EXC-1,FAULT-ORDER";
      capability = "exact x86-64 and AArch64 instruction result, skip, replay, and architectural exception faults";
    }
    {
      file = "0053-crucible-interrupt-faults.patch";
      branchSubject = "crucible: add interrupt controller faults";
      branchCommit = "b7a7c38ac1278702e534d9d332d586e3b0026a7b";
      branchTree = "b19b80774a1022eab11fc0e0934fb78c8ebe5f48";
      catalogName = "crucible-interrupt-faults";
      class = "D";
      enforces = "QFP-IRQ-1,QFP-IRQ-2,FAULT-ORDER";
      capability = "manifest-bound interrupt drop, delay, duplication, replacement, and bounded storms through realized x86-64 and AArch64 controllers";
    }
    {
      file = "0054-crucible-inject-architecture-hardware-errors.patch";
      branchSubject = "crucible: inject architecture hardware errors";
      branchCommit = "3e6d0d1ed895a30cd135bfcfc657950ab481bdea";
      branchTree = "b169d89def5a1ef84582efe23fcfd00774cff66a";
      catalogName = "crucible-hardware-error-inject";
      class = "D";
      enforces = "QFP-HWERR-1,QFP-HWERR-2,FAULT-ORDER";
      capability = "manifest-bound x86 machine-check, AArch64 RAS, and realized memory ECC delivery with transactional evidence";
    }
    {
      file = "0055-crucible-vcpu-service-control.patch";
      branchSubject = "crucible: control deterministic vCPU service";
      branchCommit = "f985a15944acae24a55d50426093a0bff8ed9f1b";
      branchTree = "6448512d113e03b3ced04bdaa4ac5c8edf8ee84f";
      catalogName = "crucible-vcpu-service-control";
      class = "D";
      enforces = "QFP-VCPU-1,QFP-VCPU-2,FAULT-ORDER";
      capability = "exact rational vCPU service, fixed-topology stall and offline state, bounded work conservation, and replay evidence";
    }
    {
      file = "0056-crucible-node-lifecycle-faults.patch";
      branchSubject = "crucible: add deterministic node lifecycle control";
      branchCommit = "32f386f5b7c75351c7540392638b71032f34dee7";
      branchTree = "04aaa0d49a21107d8c32d29c2f6fae82e172257b";
      catalogName = "crucible-node-lifecycle-faults";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "deterministic node lifecycle transitions and schedulable node or vCPU hangs with closed state treatment and replay evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      branchCommit = "3699f59e4bb840be90d35e436f483998695a0bbd";
      branchTree = "2d7eea9b0a52972faf826c9ef886c09ae424a83f";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      branchCommit = "d2833055a730a327b8cee1260f265eb7cda4fabd";
      branchTree = "644850c49eb5ab8dc6d0a9e55d69574e05ea470f";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
    {
      file = "0062-crucible-block-transport-reset.patch";
      branchSubject = "crucible: add transactional block transport reset";
      branchCommit = "9bc1a011a1fcf745fb23fe05ec1033a1d9da9fe8";
      branchTree = "84fbdd7e10a4762863ffd13e17184e83a3afbedb";
      catalogName = "crucible-block-transport-reset";
      class = "F";
      enforces = "STOR-RESET,STOR-RESULT,DET-16,PATCH-26";
      capability = "transactional epoch-scoped block reset, recovery admission, retry dispositions, and declared topology re-enumeration";
    }
    {
      file = "0063-crucible-plugin-vmstop.patch";
      branchSubject = "crucible: hand exact checkpoint boundaries to VM stop";
      branchCommit = "c7e03320184d70cc284a1eda3b6fe8899f4643c7";
      branchTree = "858f33d79624408ff619c6fb595186b9ca967486";
      catalogName = "crucible-plugin-vmstop";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43";
      capability = "RR-global exact plugin checkpoint handoff with native pause and QMP flush-error propagation";
    }
    {
      file = "0064-crucible-terminal-lifecycle-completion.patch";
      branchSubject = "crucible: stage terminal lifecycle completion";
      branchCommit = "062cde9af3f3ec2c0da4267edd99fe7051e0fb25";
      branchTree = "a312f7feea78b5851f3ae1d00bf1b10a81bba2c4";
      catalogName = "crucible-terminal-lifecycle-completion";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "two-phase typed terminal lifecycle evidence, QMP authorization, and exact process-exit staging";
    }
    {
      file = "0065-crucible-authenticated-terminal-lifecycle.patch";
      branchSubject = "crucible: authenticate terminal lifecycle completion";
      branchCommit = "1db80913ba96c66ba78bd5d687060b58e786f9de";
      branchTree = "8025a4922c8ef644de0d42c1f698a99921b49851";
      catalogName = "crucible-authenticated-terminal-lifecycle";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "dedicated idempotent QAPI terminal authorization bound to action, evidence, and process generation without guest resume";
    }
    {
      file = "0066-crucible-immutable-process-generation.patch";
      branchSubject = "crucible: provision immutable process generations";
      branchCommit = "9d36dc878c8b792e782705c5f7c055b36bca045c";
      branchTree = "e19733292f6061f95617a03925020b88a34bfda7";
      catalogName = "crucible-immutable-process-generation";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "launch-time immutable process generation provisioning before fault-command admission";
    }
    {
      file = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      branchSubject = "crucible: serialize and harden core fault state";
      branchCommit = "9abae65de1a08b284800ef4a03b77f1f4e766c68";
      branchTree = "c54f80128b088dc316ba883191d6ca0719c2f5b5";
      catalogName = "crucible-core-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,FAULT-ORDER";
      capability = "transactional bounded VMState for core command, memory, CPU, interrupt, hardware-error, service, and lifecycle fault state";
    }
    {
      file = "0068-crucible-guest-clock-faults.patch";
      branchSubject = "crucible: guest clock faults";
      branchCommit = "e946c4086f04b49ceeaef26834188252bc09984c";
      branchTree = "2f3e4f73fd27e0450eecdf48bee52f43b64a5126";
      catalogName = "crucible-guest-clock-faults";
      class = "D";
      enforces = "QFP-CLOCK-1,QFP-CLOCK-2,FAULT-ORDER";
      capability = "transactional guest-clock transforms, source-state transitions, timer rearming, and typed causal evidence";
    }
    {
      file = "0069-crucible-accelerator-fault-device.patch";
      branchSubject = "crucible: add deterministic accelerator device";
      branchCommit = "e3891b63b48f2c8aaba27724192f36bf8b925031";
      branchTree = "9c35232ed8bf7e260b02780dea71c74574e2b69e";
      catalogName = "crucible-accelerator-fault-device";
      class = "D";
      enforces = "QFP-ACCEL-1,QFP-ACCEL-2,FAULT-ORDER";
      capability = "migration-safe virtio accelerator co-simulation transport with lifecycle, result, memory/ECC, and service mutations for closed GPU, TPU, and FPGA job schemas";
    }
    {
      file = "0070-crucible-fault-vmstate.patch";
      branchSubject = "crucible: finalize fault VMState identity";
      branchCommit = "3544f1c9d75b6f49686f86591c0ba5550b6efad3";
      branchTree = "df6fd6c7ecdd7bfdcf689401b12bc40ee8802da1";
      catalogName = "crucible-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,QFP-STATE-3";
      capability = "live fail-closed build, patch-series, shared-memory ABI, and exact aggregate fault VMState identity";
    }
    {
      file = "0071-crucible-lifecycle-precondition.patch";
      branchSubject = "crucible: bind lifecycle preconditions to VM state";
      branchCommit = "eab59fbbf436fc0748674f0367b714f93b9c0cf7";
      branchTree = "e8887d5fa6dbdf870a1772823c4ed6c12109a6e0";
      catalogName = "crucible-lifecycle-precondition";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "atomic lifecycle prepare and commit over the same authenticated VM-state precondition";
    }
    {
      file = "0072-crucible-typed-node-result-schema.patch";
      branchSubject = "crucible: preserve typed node result schema";
      branchCommit = "065f738cb00d16256acc09f7fd53c8b6cf37e697";
      branchTree = "2fa2814cb6558ccf4c627e27b6909577911efe87";
      catalogName = "crucible-typed-node-result-schema";
      class = "D";
      enforces = "QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "fixed typed-command results with command-specific evidence retained on authenticated occurrence events";
    }
    {
      file = "0073-crucible-device-wait-vmstop.patch";
      branchSubject = "crucible: admit checkpoint stop from exact callbacks";
      branchCommit = "c185d11a6048d0502fa7d7c7d44f9ab5ebba8cc7";
      branchTree = "1f6c3dd066f630b0e5293b95d4f424c11a02f3c9";
      catalogName = "crucible-device-wait-vmstop";
      class = "F";
      enforces = "QFP-STATE-2,DET-1,INV-10";
      capability = "synchronous exact stop at drained control wakes with nonblocking admission from device-completion callbacks";
    }
    {
      file = "0074-crucible-arm-accelerator-result-opportunities.patch";
      branchSubject = "crucible: arm accelerator result opportunities";
      branchCommit = "ae50442c55c9aabb22a85f37fb42470409844fc6";
      branchTree = "a1f92fab4e637b5aa8e0409784a28dcfed336b3c";
      catalogName = "crucible-accelerator-result-opportunity";
      class = "F";
      enforces = "QFP-ACCEL-3,QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "atomic one-shot accelerator result arming with durable reservations and typed deferred completion results";
    }
    {
      file = "0075-crucible-restore-authenticated-fault-event-requests.patch";
      branchSubject = "crucible: restore authenticated fault event requests";
      branchCommit = "480f01a74593e6527a19843b9c35f6b99b68853d";
      branchTree = "37a9bfc74ac6bc8280c57a52bfe1d39c64993268";
      catalogName = "crucible-authenticated-event-request-envelope";
      class = "F";
      enforces = "QFP-STATE-2,QFP-ACCEL-3,QFP-EVENT-1,FAULT-ORDER";
      capability = "mandatory authenticated request/evidence envelopes for fresh-process restore and exact accelerator-opportunity binding";
    }
    {
      file = "0076-crucible-9p-completion-wake-registration.patch";
      branchSubject = "crucible: register 9p completion wakes before plugin install";
      branchCommit = "e2b294b5dd3d1f3f681c6d3be61ea9f81d6860e1";
      branchTree = "ee1aac471b5a0e5cfb68662f0693ee408ada783c";
      catalogName = "crucible-9p-completion-wake-registration";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "realize-time 9p completion notifier registration independent of plugin installation order";
    }
    {
      file = "0077-crucible-serialize-rr-cursor.patch";
      branchSubject = "crucible: serialize authoritative RR cursor";
      branchCommit = "5058f05b391f13566dbf20632775c1c17fa5f329";
      branchTree = "1c9820ae15ec532d78aac04900c833957ab22530";
      catalogName = "crucible-serialized-rr-cursor";
      class = "D";
      enforces = "DET-29,QEMU-34,QEMU-43,QFP-STATE-2";
      capability = "authoritative multi-vCPU round-robin cursor accounting and VMState restoration across host scheduling ceilings";
    }
    {
      file = "0078-crucible-fingerprint-guest-state-domains.patch";
      branchSubject = "crucible: fingerprint guest-visible state domains";
      branchCommit = "54ff3a11907b0f705a26073500cf2fd4b983233e";
      branchTree = "eea17bb40115b35ee529eccfe8d38048f19401c3";
      catalogName = "crucible-fingerprint-guest-state-domains";
      class = "D";
      enforces = "DET-29,QEMU-34,QFP-STATE-2";
      capability = "guest black-box fingerprints exclude separately authenticated process-local control state and target-declared transient CPU notifications";
    }
    {
      file = "0079-crucible-stopped-state-control-progress.patch";
      branchSubject = "crucible: bound stopped-state control progress";
      branchCommit = "f9460f7634437e7f173d1a06608b0bf1a53770ed";
      branchTree = "907a7c4dbd6af9c08ecbd6553c23e860011c8e52";
      catalogName = "crucible-stopped-state-control-progress";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43,QFP-STATE-2";
      capability = "level-triggered stopped-state control progress with queued-work admission and a bounded BQL wait";
    }
    {
      file = "0080-crucible-inactive-retention-clock-guard.patch";
      branchSubject = "crucible: guard inactive retention clock reads";
      branchCommit = "8bea17df8965882c3a5a61ea4474e530aca828d2";
      branchTree = "486734bb8ee50d3858a73a3f564876725a34eda8";
      catalogName = "crucible-inactive-retention-clock-guard";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "memory-retention clock sampling only after an active-rule admission check so fresh-process restore cannot observe an irrelevant transient clock sentinel";
    }
    {
      file = "0081-crucible-deferred-result-evidence-test.patch";
      branchSubject = "crucible: validate deferred result evidence";
      branchCommit = "4f983ce94ee4531194ba08e8dae54fb3f9eee5ca";
      branchTree = "99f6da4d71db8d6f214e038ba7a9c606f325a0e0";
      catalogName = "crucible-deferred-result-evidence-test";
      class = "F";
      enforces = "QEMU-44,FAULT-EVIDENCE";
      capability = "live instruction-fault coverage validates the canonical typed evidence added to deferred completions";
    }
    {
      file = "0082-crucible-deterministic-instruction-input-state.patch";
      branchSubject = "crucible: stabilize instruction input selectors";
      branchCommit = "4f49da6dcdc675c2faaa7339d3fdc734f46c61aa";
      branchTree = "cc6aff69e15a402f1dbab452510ea9018685855b";
      catalogName = "crucible-deterministic-instruction-input-state";
      class = "D";
      enforces = "DET-1,QEMU-44,FAULT-EVIDENCE";
      capability = "instruction input-state selectors use a cross-process-stable architectural-register digest while full CPU, RAM, and device state hashes remain in canonical evidence";
    }
    {
      file = "0083-crucible-inert-clock-restore.patch";
      branchSubject = "crucible: preserve clocks across VMState restore";
      branchCommit = "93f5150814030bc410a59fb71c362bfff8fa180a";
      branchTree = "423fee28a3b63bd58da312bf0215495528ad775d";
      catalogName = "crucible-inert-clock-restore";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,QFP-STATE-2";
      capability = "the complete VMState load transaction suppresses transient guest-clock transforms, then a successful outermost restore retains native timers, including HPET timers without a fault-managed generation, and rearms effective Crucible transforms";
    }
    {
      file = "0084-crucible-exact-restore-network-announcement.patch";
      branchSubject = "crucible: suppress migration announcements on exact restore";
      branchCommit = "42241ad951cbf47bbbc4b5b0d8b5a65fbcfd1aae";
      branchTree = "858d9128bebaa2ad0d458ccb16e05ef5224c939d";
      catalogName = "crucible-exact-restore-network-announcement";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "exact Crucible VMState restore suppresses migration-only virtio-net guest announcements while ordinary QEMU migration retains its upstream announcement behavior";
    }
    {
      file = "0085-crucible-register-rejection-atomicity.patch";
      branchSubject = "crucible: prove register rejection atomicity";
      branchCommit = "e0d849d331a2972b41f0889fc02adf5462485c76";
      branchTree = "c942a8a3fa4880ee0b428b44d144ab8e07dbb4f4";
      catalogName = "crucible-register-rejection-atomicity";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-REG-2,FAULT-EVIDENCE";
      capability = "exact RR ownership gates canonical register observation; every realized CPU manifest is validated; rejected register commands preserve every canonical GDB register byte and all six mutation side-effect counters";
    }
    {
      file = "0086-crucible-genesis-observation-boundary.patch";
      branchSubject = "crucible: admit genesis observation boundary";
      branchCommit = "9af835d18548d3275f2d576c0145348e83759059";
      branchTree = "80fd4ef52ee24cb71d96b2d4af81d62b5669fa22";
      catalogName = "crucible-genesis-observation-boundary";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "the BQL-held prelaunch genesis boundary admits complete all-vCPU architectural observation only at exact raw icount zero";
    }
    {
      file = "0087-crucible-deterministic-rcu-quiescence.patch";
      branchSubject = "crucible: defer host RCU kicks in sim";
      branchCommit = "4b590dd00360ef1cf6ec6e1c5492b0e7b27981d7";
      branchTree = "84dde55eb81845baafa426fb15295a6320009a3a";
      catalogName = "crucible-deterministic-rcu-quiescence";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "sim mode reaches RCU quiescence at its bounded deterministic RR execution boundaries without host-timed translation-block exits";
    }
    {
      file = "0088-crucible-deterministic-host-kick-boundary.patch";
      branchSubject = "crucible: defer generic host kicks in active sim slices";
      branchCommit = "eca67f44c34561d1da2e348c979bca8a1cb737e5";
      branchTree = "076834ad3adf71c264f8d8ccdb6ee1ed55c64d93";
      catalogName = "crucible-deterministic-host-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "during an active bounded sim slice, state-free host latency hints cannot choose a guest boundary, while between-slice, zero-icount startup, admitted terminal pause, stop, unplug, halted, stopped, and interrupt-request kicks retain immediate exits";
    }
    {
      file = "0089-crucible-exact-boundary-vcpu-introspection.patch";
      branchSubject = "crucible: admit vCPU introspection at exact boundaries";
      branchCommit = "bb44ce49a3a3d7400db757aa0575ea79ebb7f977";
      branchTree = "faba4e1a6fdafc5827dea095fb1b57e37a8e36c1";
      catalogName = "crucible-exact-boundary-vcpu-introspection";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact BQL-held main-loop boundaries read every quiescent vCPU register file and the committed RR cursor without a current vCPU, while arbitrary unowned contexts remain rejected";
    }
    {
      file = "0090-crucible-active-tcg-kick-boundary.patch";
      branchSubject = "crucible: defer generic kicks to TCG boundaries";
      branchCommit = "2e65104d45c23b8985bdaeebe2d81d415068f8d5";
      branchTree = "33d658e56bde6f218786e9008e85d35a032e55f2";
      catalogName = "crucible-active-tcg-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "state-free sim kicks request exit at the next deterministic translation-block boundary while committed transitions preserve immediate liveness";
    }
    {
      file = "0091-crucible-canonical-rr-genesis-cursor.patch";
      branchSubject = "crucible: expose the canonical RR genesis cursor";
      branchCommit = "4d58f514479e58ffda3ca60bc47e1fa3d8af370b";
      branchTree = "e31da07aa13f592396054745ebac806f31784554";
      catalogName = "crucible-canonical-rr-genesis-cursor";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact raw-zero observers read the unique next RR coordinate without mutating scheduler state while every later invalid cursor remains rejected";
    }
    {
      file = "0092-crucible-canonical-terminal-rr-cursor.patch";
      branchSubject = "crucible: canonicalize terminal RR observations";
      branchCommit = "5cc893ee411cb765f22fe78702626c96e54d59f4";
      branchTree = "34dc5c184034bffbff82d9646df056c34f27745f";
      catalogName = "crucible-canonical-terminal-rr-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "live observers at a quantum terminal project onto the next scheduler-owned vCPU at position zero without mutating serialized RR state";
    }
    {
      file = "0093-crucible-canonical-register-cursor.patch";
      branchSubject = "crucible: canonicalize after-instruction register cursors";
      branchCommit = "a9d88aa9eb314ca19f541f82227daea7f38fa2cb";
      branchTree = "f2f1aecb943b6195dbc6fb4a43a581c89b0da773";
      catalogName = "crucible-canonical-register-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "after-instruction register evidence advances its callback-local prefix and projects an exact quantum terminal onto the canonical next RR coordinate";
    }
    {
      file = "0094-crucible-retention-virtual-time-origin.patch";
      branchSubject = "crucible: anchor retention to virtual time";
      branchCommit = "1717e439c8a1eeff093863a3a726d530d775c0c7";
      branchTree = "ab754efb28da63c19e9ec5ae13c5e22d146b1579";
      catalogName = "crucible-retention-virtual-time-origin";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "memory-retention expiry originates in authoritative virtual nanoseconds instead of mixing raw instruction coordinates with clock-biased deadlines";
    }
    {
      file = "0095-crucible-raw-pte-update-identity.patch";
      branchSubject = "crucible: preserve raw PTE update identity";
      branchCommit = "8f1deb9b320c565c54796e83d280df13be7dfaea";
      branchTree = "5222f67bf250551cc1d680b21977357c524d0bb4";
      catalogName = "crucible-raw-pte-update-identity";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "x86 page-table translation consumes corrected transient PTE bytes while accessed/dirty cmpxchg preserves the canonical backing entry and cannot retry forever";
    }
    {
      file = "0096-crucible-physical-page-table-region-fixture.patch";
      branchSubject = "tests/tcg: target page-table regions physically";
      branchCommit = "8a4e0bf0eab0c76e05247f733d96278873e93aa0";
      branchTree = "a748752649092dfc24cac033d623d0af79a0518a";
      catalogName = "crucible-physical-page-table-region-fixture";
      class = "F";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-EVIDENCE";
      capability = "live persistent page-table-region tests address descriptor storage by GPA while ordinary guest-memory region tests retain GVA targeting";
    }
    {
      file = "0097-crucible-canonicalize-memory-retry-identity.patch";
      branchSubject = "crucible: canonicalize memory retry identity";
      branchCommit = "658f9129d160f5c36118d4bf21d717badc957d4b";
      branchTree = "15da987612cccada74d65de1a9f6e6f0931ebbe7";
      catalogName = "crucible-canonical-memory-retry-identity";
      class = "D";
      enforces = "DET-1,QFP-MEMA-1,QFP-STATE-2";
      capability = "memory retry keys exclude TB-local instruction ordinals and serialize that compatibility field at canonical zero across fault-driven retranslation";
    }
    {
      file = "0098-crucible-inactive-nested-tsc-guard.patch";
      branchSubject = "crucible: guard inactive nested TSC reads";
      branchCommit = "57e8d69490042d25c225c6e1dc7f04cd806e132f";
      branchTree = "2d8da8cb47bcfbd1c8e7f1d944cac4d372650886";
      catalogName = "crucible-inactive-nested-tsc-guard";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,PATCH-3";
      capability = "inactive guest-clock faults avoid TSC sampling inside SVM entry and exit so nested execution preserves upstream icount accounting";
    }
    {
      file = "0099-crucible-valid-aarch64-abort-fixture.patch";
      branchSubject = "tests/tcg: use valid AArch64 abort syndrome";
      branchCommit = "e24a3a7e9bb27cc7b274fdecd496a779717bef10";
      branchTree = "e08e6b5e705503902fb7ec62f52d38ec67088c40";
      catalogName = "crucible-valid-aarch64-abort-fixture";
      class = "F";
      enforces = "QFP-MEMA-1,FAULT-EVIDENCE,PATCH-3";
      capability = "the live AArch64 poison-exception and retry fixtures submit the data-abort vector and a same-EL syndrome accepted by the production architecture validator";
    }
    {
      file = "0100-crucible-aarch64-memory-exception-vectors.patch";
      branchSubject = "crucible: validate AArch64 memory exception vectors";
      branchCommit = "77a8f42f89634408d59cf77a966aa22d9ec723ca";
      branchTree = "95eb4c3d7307a8dd12690b2866ea4c9206a47781";
      catalogName = "crucible-aarch64-memory-exception-vectors";
      class = "D";
      enforces = "QFP-MEMA-1,FAULT-EVIDENCE,PATCH-3";
      capability = "AArch64 memory exception admission requires instruction-abort vector 2 for fetches and data-abort vector 3 for non-fetch accesses";
    }
    {
      file = "0101-crucible-canonicalize-snapshot-rr-resume.patch";
      branchSubject = "crucible: canonicalize snapshot RR resume";
      branchCommit = "53cb1eca7ab89893ab65d2c8eddfd8bf8a3ae82c";
      branchTree = "63e2ef329db39cd7aa68ab0214beba3e0f01db49";
      catalogName = "crucible-canonical-snapshot-rr-resume";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "successful sim-mode snapshots arm the same one-shot serialized-owner selection used after load so source continuation preserves the RR owner and intra-turn position";
    }
    {
      file = "0102-crucible-bql-exact-register-capture.patch";
      branchSubject = "crucible: admit BQL exact register capture";
      branchCommit = "6764f209f43687e355e0706a460a57240636971a";
      branchTree = "7c385a93544ea975a0098ad2300f2a0518700f3a";
      catalogName = "crucible-bql-exact-register-capture";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "BQL-held exact callbacks read quiescent vCPU registers while post-snapshot RR owner reselection is pending, and idle-time completion is explicitly scoped as exact";
    }
    {
      file = "0103-crucible-isolate-checkpoint-control-wake.patch";
      branchSubject = "crucible: isolate checkpoint control wake";
      branchCommit = "96d3e72c87e3bbcc111369dea21cf547f7710643";
      branchTree = "0e66b3afb35432b45452b3f7bb68d6bd016c0e82";
      catalogName = "crucible-isolate-checkpoint-control-wake";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,PATCH-20";
      capability = "a pending exact VM-stop handoff wakes QEMU's main loop without resuming parked block coroutines or admitting post-pause completions";
    }
    {
      file = "0104-crucible-preserve-checkpoint-block-durability.patch";
      branchSubject = "crucible: preserve checkpoint block durability";
      branchCommit = "6ea8b0b3328c2c5a65e08e4004681d3d9ee94ac0";
      branchTree = "0850d6342027ae6ca0d67018b17a779084a49fe1";
      catalogName = "crucible-preserve-checkpoint-block-durability";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QFP-BLOCK-3";
      capability = "synthetic QEMU stop-time flushes preserve the checkpointed Apache durability continuation and cannot create post-quiescence Crucible block requests";
    }
    {
      file = "0105-crucible-selector-control-plane-fixtures.patch";
      branchSubject = "crucible: isolate selector control-plane fixtures";
      branchCommit = "03d9e7688f423910049a06b1b1c98a88474152bb";
      branchTree = "863e81a5f642d2c733c8e4234586dd1d2d7fa188";
      catalogName = "crucible-selector-control-plane-fixtures";
      class = "F";
      enforces = "FAULT-ORDER,PATCH-3,QFP-INST-3";
      capability = "live instruction selector overlap and exclusivity fixtures use unreachable occurrences so admission checks remain isolated from data-plane fault delivery";
    }
    {
      file = "0106-crucible-defer-active-slice-host-wakes.patch";
      branchSubject = "crucible: defer active-slice host wake requests";
      branchCommit = "3ec5fe842bc60a25ad67c641b4f7356e37a70195";
      branchTree = "a96d23007069cf5fe9aee180564025359622269d";
      catalogName = "crucible-defer-active-slice-host-wakes";
      class = "D";
      enforces = "DET-1,QFP-KICK-3,QEMU-43";
      capability = "an atomic idle-active-pending handshake admits multi-vCPU state-free wakes only before TCG starts and never lets them select a translation-block endpoint, while single-vCPU soft exits and explicit terminal and committed lifecycle wakes remain live";
    }
    {
      file = "0107-crucible-anchor-rr-cursor-genesis.patch";
      branchSubject = "crucible: anchor RR cursor at guest genesis";
      branchCommit = "5f27c75fd20eee0fd08f45070981e6744be5d09c";
      branchTree = "c83e5630f693423707c5a54bfd1792ec81c67f2e";
      catalogName = "crucible-anchor-rr-cursor-genesis";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "fresh sim-mode execution establishes vCPU 0 position 0 before the first budget, and the serialized owner remains authoritative across partial turns and VMState restore";
    }
    {
      file = "0108-crucible-deterministic-network-kick.patch";
      branchSubject = "crucible: preserve deterministic network continuation";
      branchCommit = "9b3072172802f0f1ce54d9997471e7c4975a1fa6";
      branchTree = "02c1cbe4dbeba715add6fcc8871f6b44057a669e";
      catalogName = "crucible-deterministic-network-kick";
      class = "D";
      enforces = "DET-1,PLUG-23,PLUG-24,QEMU-43";
      capability = "sim-mode virtio-net queue kicks and serialized tx_waiting resumes drain every deferred TX bottom half synchronously, supply one committed raw transmit icount, preserve the virtqueue notification cursor in an optional sim VMState subsection, symmetrically flush pre-checkpoint translation history, and use bounded cache-independent TB shapes without direct chains on both continuations so VMState restore preserves packet and fault-decision continuation";
    }
    {
      file = "0109-crucible-control-boundary-node-faults.patch";
      branchSubject = "crucible: dispatch exact control-boundary node faults";
      branchCommit = "65c32bfc073690159870f2b9576ac11fe74de03c";
      branchTree = "90fddc82b2c8a61e62f5d1ee2ab415ea1fde2266";
      catalogName = "crucible-control-boundary-node-faults";
      class = "F";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "a node-boundary command submitted while QEMU is halted at an exact drained control wake is dispatched at that same raw icount, so PREPARE and APPLY complete without requiring guest progress; terminal authorization hashes zero the raw evidence coordinate before the plugin maps it into scheduler-logical space";
    }
    {
      file = "0110-crucible-release-halted-rr-turn.patch";
      branchSubject = "crucible: release halted partial RR turns";
      branchCommit = "34dfbf156f5768c9725fb0ae6d5138174fa032f0";
      branchTree = "86dbee3a96c34a534b9091d381bb3aef4603e299";
      catalogName = "crucible-release-halted-rr-turn";
      class = "D";
      enforces = "DET-1,PLUG-24,QEMU-43";
      capability = "a vCPU that executes HLT before exhausting its serialized RR turn leaves the execution loop when no alternative vCPU is runnable; a helper-marked multi-vCPU guest PAUSE fences control-boundary acknowledgement until it commits a cursor-zero early handoff immediately after icount accounting and before callbacks or host-work exits, so a released spin lock cannot be reacquired before a waiting peer runs; and that exact completed-turn handoff admits safe register capture while other owner mismatches fail closed";
    }
    {
      file = "0111-crucible-hot-fork-readiness.patch";
      branchSubject = "crucible: report hot-fork readiness proofs";
      branchCommit = "7ff04305e4fde33c1889e392a16f1090bdac6225";
      branchTree = "b34e3cec1b80e0cf66065de560fdb59052c13d52";
      catalogName = "crucible-hot-fork-readiness";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "bounded versioned QMP queries report QEMU-owned precise-icount, single-threaded sim RR, and exact paused/device-flush proofs plus a sorted generation-tagged registry of every active qemu_thread_create thread and the sole QMP coordinator; every non-coordinator remains unclassified and every unimplemented subsystem, mapping, external thread, and child-reinitialization proof stays clear so the audit cannot advertise hot fork";
    }
    {
      file = "0112-crucible-hot-fork-thread-ownership.patch";
      branchSubject = "crucible: classify unresolved hot-fork threads";
      branchCommit = "4ee02f149151c2cedc56bfbd3254980e09397c58";
      branchTree = "d2ba34f80ea4c35593ed4e4c4e3122cf7dcde8ca";
      catalogName = "crucible-hot-fork-thread-ownership";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "the bounded thread-registry schema explicitly assigns the RCU callback worker and every QEMU IOThread to unresolved subsystem-specific ownership classes while retaining them in the exact unclassified blocker count; no owner class supplies a barrier or child disposition and no readiness proof changes";
    }
    {
      file = "0113-crucible-hot-fork-rcu-inventory.patch";
      branchSubject = "crucible: inventory hot-fork RCU state";
      branchCommit = "79920e9d7583c44e03f0469fcd8d0b70c5dbefd7";
      branchTree = "4937f9253ea7a64425a99ec2f3179e1cb46e2e0c";
      catalogName = "crucible-hot-fork-rcu-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded versioned QMP inventory reports every registered RCU reader, instantaneous read-side activity, submitted-but-incomplete callbacks, and active drain operations; the report remains observational, supplies no held quiescence barrier, and leaves the RCU readiness proof clear";
    }
    {
      file = "0114-crucible-hot-fork-aio-inventory.patch";
      branchSubject = "crucible: inventory hot-fork AIO activity";
      branchCommit = "e130dd1f8c3891df306ac7a26d2b8943c5349e1d";
      branchTree = "fd5d33c997b1000b09646cb0c1627d0a0f317de1";
      catalogName = "crucible-hot-fork-aio-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded versioned QMP inventory reports every registered AioContext, exact home-thread ownership, active poll and dispatch calls, queued and active bottom halves, queued coroutines, and notification state; the report remains observational, does not enumerate timers or handlers, supplies no held drain barrier, and leaves the AIO readiness proof clear";
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
      catalogName = "crucible-net-direct-inject-api";
      carriedBy = "0009-crucible-net-deterministic.patch";
      class = "F";
      enforces = "PATCH-32,DET-18,E18";
      capability = "lossless RX direct-injection status API with no QEMU-private retention or stale private-queue backpressure latch";
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
