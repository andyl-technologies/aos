# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "c9906d4546e6325a5a3e469dc7708f18997a81fc1f171aedb0df3d1781b2a428";
  patchBranchBaseCommit = "0400e2d08acb30307af7cb214b21552807c1dd46";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "7c8d69b83c5a51d5f18f54ab5596272d2c194200";
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
      branchCommit = "90c525c8e66410131977dee10c39c3948d247039";
      branchTree = "44d36a952e0f01f28d2a20ed211b55401623dce8";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped guest virtual-memory writes for synchronous white-box doorbell replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "c4c0cb0e753ac66db78c0cf8c6db5b2530e88e55";
      branchTree = "511e888f51c2c274a4bbe97f1f5036dc3ddd5027";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "8f507355656273a82de5599f2c79cd4b3e421918";
      branchTree = "61b3ff950763175bff86202d3946f7ee8965e0df";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "5c59c5c3ea9417e5079ef09809ed7d655e8e108c";
      branchTree = "ebd988114476f4ea8140283dbed6da38437a1834";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "9931764dbfc27367122f8c36dcc87045c5ebf022";
      branchTree = "3b021a92ebd46f7a6d9b161aa6e7a0be40c4be23";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      branchCommit = "5f91c341b6a40606c293fac391e8ad33b9722f64";
      branchTree = "f5747d58cb89ff044d419dae6f4338984b305c81";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      branchCommit = "1029809b1794d214c64544a68dec79e505de9ba6";
      branchTree = "ff3191752266593756855715645b5d80ba46b7a2";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,FAULT-ORDER";
      capability = "versioned fault command registry, bounded result queue, and plugin ABI";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      branchCommit = "1a332bb0d9f7907b98be8d42935b5b5b6734fe74";
      branchTree = "c63f3b952b9cbb71d5c6f4710004ff32a7ddd4fb";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement and same-boundary prepare/commit completion";
    }
    {
      file = "0049-crucible-memory-boundary-mutate.patch";
      branchSubject = "crucible: atomically mutate guest memory batches";
      branchCommit = "069f6b93c8bed806240c4ad206ecdbbcff2b5b44";
      branchTree = "89244f2e76491953778787ec4d960007f5e22704";
      catalogName = "crucible-memory-boundary-mutate";
      class = "F";
      enforces = "QFP-MEM-1,QFP-MEM-2,FAULT-ORDER";
      capability = "atomic ordered GPA/GVA mutation batches with translation, RAM-map, dirty-page, and TB evidence";
    }
    {
      file = "0050-crucible-memory-access-faults.patch";
      branchSubject = "crucible: add memory access fault rules";
      branchCommit = "bdbe1706bd7383de11ba9a4e1084ca24e38658a4";
      branchTree = "a92244fa73fca89608ed2af2dee87f0e988b21b4";
      catalogName = "crucible-memory-access-faults";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "typed fetch, load, store, page-table walk, atomic, and identified virtio DMA memory fault rules with shared service and persistent region state";
    }
    {
      file = "0051-crucible-add-architecture-register-fault-mutations.patch";
      branchSubject = "crucible: add architecture register fault mutations";
      branchCommit = "f39b42a95153b69bee52b66a5e24a941ec7a794f";
      branchTree = "8ac4fb294cd70d4b5badef783b650c52127fd74e";
      catalogName = "crucible-architecture-register-faults";
      class = "D";
      enforces = "QFP-REG-1,QFP-REG-2,FAULT-ORDER";
      capability = "manifest-bound x86-64 and AArch64 register mutations at exact instruction boundaries";
    }
    {
      file = "0052-crucible-instruction-and-exception-faults.patch";
      branchSubject = "crucible: add instruction and exception faults";
      branchCommit = "c7f92183f44586593380359440df57498a6cb1c2";
      branchTree = "816fdb5410a688dfa0e0e9fb849ff4704700f9b6";
      catalogName = "crucible-instruction-and-exception-faults";
      class = "D";
      enforces = "QFP-INSN-1,QFP-EXC-1,FAULT-ORDER";
      capability = "exact x86-64 and AArch64 instruction result, skip, replay, and architectural exception faults";
    }
    {
      file = "0053-crucible-interrupt-faults.patch";
      branchSubject = "crucible: add interrupt controller faults";
      branchCommit = "d6f0961013d2a2167e3a8ad24c82c1e28784d5e5";
      branchTree = "7f574ec6e85a13c6f9d96bac7b36ba09b86251f4";
      catalogName = "crucible-interrupt-faults";
      class = "D";
      enforces = "QFP-IRQ-1,QFP-IRQ-2,FAULT-ORDER";
      capability = "manifest-bound interrupt drop, delay, duplication, replacement, and bounded storms through realized x86-64 and AArch64 controllers";
    }
    {
      file = "0054-crucible-inject-architecture-hardware-errors.patch";
      branchSubject = "crucible: inject architecture hardware errors";
      branchCommit = "a519e9eb4a1baee6b44108a3a2b0a90bdfd6f787";
      branchTree = "8ebf0d7a2a83418108c184278a59cb2408977f4c";
      catalogName = "crucible-hardware-error-inject";
      class = "D";
      enforces = "QFP-HWERR-1,QFP-HWERR-2,FAULT-ORDER";
      capability = "manifest-bound x86 machine-check, AArch64 RAS, and realized memory ECC delivery with transactional evidence";
    }
    {
      file = "0055-crucible-vcpu-service-control.patch";
      branchSubject = "crucible: control deterministic vCPU service";
      branchCommit = "1b6d7bbfacb045722be3299cb1081a0e66f5348c";
      branchTree = "d647ecb5131883cf361ccc623cd0c676432f99b6";
      catalogName = "crucible-vcpu-service-control";
      class = "D";
      enforces = "QFP-VCPU-1,QFP-VCPU-2,FAULT-ORDER";
      capability = "exact rational vCPU service, fixed-topology stall and offline state, bounded work conservation, and replay evidence";
    }
    {
      file = "0056-crucible-node-lifecycle-faults.patch";
      branchSubject = "crucible: add deterministic node lifecycle control";
      branchCommit = "776285311fd916918937e258db33fdf5c533401d";
      branchTree = "0d269c4486cacabb36942d50c8d06f79521c3cde";
      catalogName = "crucible-node-lifecycle-faults";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "deterministic node lifecycle transitions and schedulable node or vCPU hangs with closed state treatment and replay evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      branchCommit = "d2cfa59a7b3f612e8ea4c574e81afcde08418808";
      branchTree = "9a481cf1b3c35ef1ccf45299de220140f5531a35";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      branchCommit = "0ea930626e1fef5618777597f3093c3520268c15";
      branchTree = "f4eb072225d9f97f954710fb5e7594f9a5c4a06f";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
    {
      file = "0062-crucible-block-transport-reset.patch";
      branchSubject = "crucible: add transactional block transport reset";
      branchCommit = "b4a949d58b4bb208f293496d7c94aeb53e373bc4";
      branchTree = "bf8c6a308a2dc49fa03ff62b49e049eafd8a1e1a";
      catalogName = "crucible-block-transport-reset";
      class = "F";
      enforces = "STOR-RESET,STOR-RESULT,DET-16,PATCH-26";
      capability = "transactional epoch-scoped block reset, recovery admission, retry dispositions, and declared topology re-enumeration";
    }
    {
      file = "0063-crucible-plugin-vmstop.patch";
      branchSubject = "crucible: hand exact checkpoint boundaries to VM stop";
      branchCommit = "73fadf2f3391e784222f7f7a382463d33407a57d";
      branchTree = "2a300e5d078d7e59bcba531cb5fb5e41263127a9";
      catalogName = "crucible-plugin-vmstop";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43";
      capability = "RR-global exact plugin checkpoint handoff with native pause and QMP flush-error propagation";
    }
    {
      file = "0064-crucible-terminal-lifecycle-completion.patch";
      branchSubject = "crucible: stage terminal lifecycle completion";
      branchCommit = "df69d64cbe528424006bbd2a1d8e63344ae668f5";
      branchTree = "9de548d7662a85d68b08f71f71c2be749f51d9ce";
      catalogName = "crucible-terminal-lifecycle-completion";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "two-phase typed terminal lifecycle evidence, QMP authorization, and exact process-exit staging";
    }
    {
      file = "0065-crucible-authenticated-terminal-lifecycle.patch";
      branchSubject = "crucible: authenticate terminal lifecycle completion";
      branchCommit = "795eab1f84b2563a384febef3d2a21e83cdf9ec7";
      branchTree = "370753136cdae6c8d4ee208eb6a875b6c229239a";
      catalogName = "crucible-authenticated-terminal-lifecycle";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "dedicated idempotent QAPI terminal authorization bound to action, evidence, and process generation without guest resume";
    }
    {
      file = "0066-crucible-immutable-process-generation.patch";
      branchSubject = "crucible: provision immutable process generations";
      branchCommit = "2a75195c2d01ccde45fe3a23ac430d39913a9aeb";
      branchTree = "e1609ae5eca1d8a74572ef85278a537beca464d4";
      catalogName = "crucible-immutable-process-generation";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "launch-time immutable process generation provisioning before fault-command admission";
    }
    {
      file = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      branchSubject = "crucible: serialize and harden core fault state";
      branchCommit = "9ff03cab223a25d6ef4f31bfed6c2d86b66a223e";
      branchTree = "a965fa8cb87891cab35e0c15c6419230f7888201";
      catalogName = "crucible-core-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,FAULT-ORDER";
      capability = "transactional bounded VMState for core command, memory, CPU, interrupt, hardware-error, service, and lifecycle fault state";
    }
    {
      file = "0068-crucible-guest-clock-faults.patch";
      branchSubject = "crucible: guest clock faults";
      branchCommit = "409f802eb33f8a9ab671e2d291145e5e2e69fa08";
      branchTree = "2733a3c03aeb2b5291226ad8f9f6532aa720e98b";
      catalogName = "crucible-guest-clock-faults";
      class = "D";
      enforces = "QFP-CLOCK-1,QFP-CLOCK-2,FAULT-ORDER";
      capability = "transactional guest-clock transforms, source-state transitions, timer rearming, and typed causal evidence";
    }
    {
      file = "0069-crucible-accelerator-fault-device.patch";
      branchSubject = "crucible: add deterministic accelerator device";
      branchCommit = "192125f79642cba5314ff22f9d7a6a24ff97127c";
      branchTree = "8650a37fdeb426cfa6d30ad0960d622589c00e07";
      catalogName = "crucible-accelerator-fault-device";
      class = "D";
      enforces = "QFP-ACCEL-1,QFP-ACCEL-2,FAULT-ORDER";
      capability = "migration-safe virtio accelerator co-simulation transport with lifecycle, result, memory/ECC, and service mutations for closed GPU, TPU, and FPGA job schemas";
    }
    {
      file = "0070-crucible-fault-vmstate.patch";
      branchSubject = "crucible: finalize fault VMState identity";
      branchCommit = "795d88ff70bb97e74afc4977f5c91e485ca66818";
      branchTree = "db5bac40a939ef10e6eec70bc298c2d7dc0c8cea";
      catalogName = "crucible-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,QFP-STATE-3";
      capability = "live fail-closed build, patch-series, shared-memory ABI, and exact aggregate fault VMState identity";
    }
    {
      file = "0071-crucible-lifecycle-precondition.patch";
      branchSubject = "crucible: bind lifecycle preconditions to VM state";
      branchCommit = "be4d2d637089c0db2e4d4e8b21a9ad9b0dfae20c";
      branchTree = "20e22fd523dc05e13c48ab9033b49ed67121f33c";
      catalogName = "crucible-lifecycle-precondition";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "atomic lifecycle prepare and commit over the same authenticated VM-state precondition";
    }
    {
      file = "0072-crucible-typed-node-result-schema.patch";
      branchSubject = "crucible: preserve typed node result schema";
      branchCommit = "6440c48b9d998133d95aee901492dc9bd6eb432e";
      branchTree = "aa5c3ee702cc86b89f88cfa126f3b24fc8036ed6";
      catalogName = "crucible-typed-node-result-schema";
      class = "D";
      enforces = "QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "fixed typed-command results with command-specific evidence retained on authenticated occurrence events";
    }
    {
      file = "0073-crucible-device-wait-vmstop.patch";
      branchSubject = "crucible: admit checkpoint stop from exact callbacks";
      branchCommit = "1fad865e4709b2fa685a1043607a844dd6d02e34";
      branchTree = "cd547ab923d683c5e03682cea6ba5354c4d45c4a";
      catalogName = "crucible-device-wait-vmstop";
      class = "F";
      enforces = "QFP-STATE-2,DET-1,INV-10";
      capability = "synchronous exact stop at drained control wakes with nonblocking admission from device-completion callbacks";
    }
    {
      file = "0074-crucible-arm-accelerator-result-opportunities.patch";
      branchSubject = "crucible: arm accelerator result opportunities";
      branchCommit = "e86b1efb2689cf1e0d47fdb48a2b62d3502511d9";
      branchTree = "2517f5d608ba1fdb812d80561488e796f19474bd";
      catalogName = "crucible-accelerator-result-opportunity";
      class = "F";
      enforces = "QFP-ACCEL-3,QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "atomic one-shot accelerator result arming with durable reservations and typed deferred completion results";
    }
    {
      file = "0075-crucible-restore-authenticated-fault-event-requests.patch";
      branchSubject = "crucible: restore authenticated fault event requests";
      branchCommit = "1977dee7a7ea4707d72edd4aabc7a3bc6d2e19b9";
      branchTree = "9654e4f78ac847b7eddffc60a9f231b4c023f9f3";
      catalogName = "crucible-authenticated-event-request-envelope";
      class = "F";
      enforces = "QFP-STATE-2,QFP-ACCEL-3,QFP-EVENT-1,FAULT-ORDER";
      capability = "mandatory authenticated request/evidence envelopes for fresh-process restore and exact accelerator-opportunity binding";
    }
    {
      file = "0076-crucible-9p-completion-wake-registration.patch";
      branchSubject = "crucible: register 9p completion wakes before plugin install";
      branchCommit = "7f6e6976c732ff1dd423ab93af9b18689a2d57fb";
      branchTree = "277d590ae04eef6cce6e6b9c53840902959c66c5";
      catalogName = "crucible-9p-completion-wake-registration";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "realize-time 9p completion notifier registration independent of plugin installation order";
    }
    {
      file = "0077-crucible-serialize-rr-cursor.patch";
      branchSubject = "crucible: serialize authoritative RR cursor";
      branchCommit = "d61f746568283b0c900230b120ef79aab692f0f8";
      branchTree = "b169f87fe1387846c935dbfc3e5c80530116eaca";
      catalogName = "crucible-serialized-rr-cursor";
      class = "D";
      enforces = "DET-29,QEMU-34,QEMU-43,QFP-STATE-2";
      capability = "authoritative multi-vCPU round-robin cursor accounting and VMState restoration across host scheduling ceilings";
    }
    {
      file = "0078-crucible-fingerprint-guest-state-domains.patch";
      branchSubject = "crucible: fingerprint guest-visible state domains";
      branchCommit = "d2bd1d8b9d72748e5afdd5e8b3096b1e26597692";
      branchTree = "78a56bd4aaa393b0af3abe4cd2d4f2dd816c2a3a";
      catalogName = "crucible-fingerprint-guest-state-domains";
      class = "D";
      enforces = "DET-29,QEMU-34,QFP-STATE-2";
      capability = "guest black-box fingerprints exclude separately authenticated process-local control state and target-declared transient CPU notifications";
    }
    {
      file = "0079-crucible-stopped-state-control-progress.patch";
      branchSubject = "crucible: bound stopped-state control progress";
      branchCommit = "575c9bba298b0d53086bce2ba7fd74ecb226216a";
      branchTree = "172e303cdc14b8db2cec85dc52477146a33466b2";
      catalogName = "crucible-stopped-state-control-progress";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43,QFP-STATE-2";
      capability = "level-triggered stopped-state control progress with queued-work admission and a bounded BQL wait";
    }
    {
      file = "0080-crucible-inactive-retention-clock-guard.patch";
      branchSubject = "crucible: guard inactive retention clock reads";
      branchCommit = "cb7ab46714afed573995eb5ae57699a1c1c6cc6a";
      branchTree = "7d8d2ebd16f154813d3d482a75ec38c912e4ccae";
      catalogName = "crucible-inactive-retention-clock-guard";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "memory-retention clock sampling only after an active-rule admission check so fresh-process restore cannot observe an irrelevant transient clock sentinel";
    }
    {
      file = "0081-crucible-deferred-result-evidence-test.patch";
      branchSubject = "crucible: validate deferred result evidence";
      branchCommit = "a9080e2b23107cbf01eccb4239b26600358f9715";
      branchTree = "7193e3f97125b621c658171f84186afc00d4c08d";
      catalogName = "crucible-deferred-result-evidence-test";
      class = "F";
      enforces = "QEMU-44,FAULT-EVIDENCE";
      capability = "live instruction-fault coverage validates the canonical typed evidence added to deferred completions";
    }
    {
      file = "0082-crucible-deterministic-instruction-input-state.patch";
      branchSubject = "crucible: stabilize instruction input selectors";
      branchCommit = "d87ae4155ae787de8c738b7f43425a99934a9c0f";
      branchTree = "94db91de618a6fd56b070937f4e3810f171c5415";
      catalogName = "crucible-deterministic-instruction-input-state";
      class = "D";
      enforces = "DET-1,QEMU-44,FAULT-EVIDENCE";
      capability = "instruction input-state selectors use a cross-process-stable architectural-register digest while full CPU, RAM, and device state hashes remain in canonical evidence";
    }
    {
      file = "0083-crucible-inert-clock-restore.patch";
      branchSubject = "crucible: preserve clocks across VMState restore";
      branchCommit = "057194a6e3c470c66334ad6f0b5658c9c16e64f2";
      branchTree = "929f0d53c097ba7d05c69682027ee2972e9ccd18";
      catalogName = "crucible-inert-clock-restore";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,QFP-STATE-2";
      capability = "the complete VMState load transaction suppresses transient guest-clock transforms, then a successful outermost restore retains native timers, including HPET timers without a fault-managed generation, and rearms effective Crucible transforms";
    }
    {
      file = "0084-crucible-exact-restore-network-announcement.patch";
      branchSubject = "crucible: suppress migration announcements on exact restore";
      branchCommit = "6511de883f4e7cfdbd525695b9a82bbe8edc1e4b";
      branchTree = "8325da9e349b41868f81d69e800637dd7819320b";
      catalogName = "crucible-exact-restore-network-announcement";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "exact Crucible VMState restore suppresses migration-only virtio-net guest announcements while ordinary QEMU migration retains its upstream announcement behavior";
    }
    {
      file = "0085-crucible-register-rejection-atomicity.patch";
      branchSubject = "crucible: prove register rejection atomicity";
      branchCommit = "233b6b35af9e399f92379f3a75c5a616a390df0e";
      branchTree = "17a95182b47e545d61074bff7a013186fcd00740";
      catalogName = "crucible-register-rejection-atomicity";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-REG-2,FAULT-EVIDENCE";
      capability = "exact RR ownership gates canonical register observation; every realized CPU manifest is validated; rejected register commands preserve every canonical GDB register byte and all six mutation side-effect counters";
    }
    {
      file = "0086-crucible-genesis-observation-boundary.patch";
      branchSubject = "crucible: admit genesis observation boundary";
      branchCommit = "1f0996e48799cfdae76c60bb00bd41129d40aa7a";
      branchTree = "b541af0e3f868752770f925c79c6e8667ccca259";
      catalogName = "crucible-genesis-observation-boundary";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "the BQL-held prelaunch genesis boundary admits complete all-vCPU architectural observation only at exact raw icount zero";
    }
    {
      file = "0087-crucible-deterministic-rcu-quiescence.patch";
      branchSubject = "crucible: defer host RCU kicks in sim";
      branchCommit = "4146e9473afcdd619181619975e7fa8eac1347be";
      branchTree = "dbc62fb2c7ed0b2fc2089e6b9980683a621f1236";
      catalogName = "crucible-deterministic-rcu-quiescence";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "sim mode reaches RCU quiescence at its bounded deterministic RR execution boundaries without host-timed translation-block exits";
    }
    {
      file = "0088-crucible-deterministic-host-kick-boundary.patch";
      branchSubject = "crucible: defer generic host kicks in active sim slices";
      branchCommit = "b74a72830566cf82c06caea2b48f2bdfccb33fcf";
      branchTree = "eed61b4fe79859db97b538553ef56800a1eb0cb3";
      catalogName = "crucible-deterministic-host-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "during an active bounded sim slice, state-free host latency hints cannot choose a guest boundary, while between-slice, zero-icount startup, admitted terminal pause, stop, unplug, halted, stopped, and interrupt-request kicks retain immediate exits";
    }
    {
      file = "0089-crucible-exact-boundary-vcpu-introspection.patch";
      branchSubject = "crucible: admit vCPU introspection at exact boundaries";
      branchCommit = "ae94b78bf72aa349383461f1675b396ea568b18a";
      branchTree = "6bfcc3dea7fc1f0d2459507ed9207ed5a9b32a19";
      catalogName = "crucible-exact-boundary-vcpu-introspection";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact BQL-held main-loop boundaries read every quiescent vCPU register file and the committed RR cursor without a current vCPU, while arbitrary unowned contexts remain rejected";
    }
    {
      file = "0090-crucible-active-tcg-kick-boundary.patch";
      branchSubject = "crucible: defer generic kicks to TCG boundaries";
      branchCommit = "7bcead204fb80ef6deb4fb23fea6109c82951640";
      branchTree = "dd1214b29f107e8651b2e3396ee69368461ae320";
      catalogName = "crucible-active-tcg-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "state-free sim kicks request exit at the next deterministic translation-block boundary while committed transitions preserve immediate liveness";
    }
    {
      file = "0091-crucible-canonical-rr-genesis-cursor.patch";
      branchSubject = "crucible: expose the canonical RR genesis cursor";
      branchCommit = "e41b81123902186b0d1a1463e666d68d10045118";
      branchTree = "e73429c3002a00a5054809bdbc23053dcfd73348";
      catalogName = "crucible-canonical-rr-genesis-cursor";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact raw-zero observers read the unique next RR coordinate without mutating scheduler state while every later invalid cursor remains rejected";
    }
    {
      file = "0092-crucible-canonical-terminal-rr-cursor.patch";
      branchSubject = "crucible: canonicalize terminal RR observations";
      branchCommit = "6dc105541792878bd9a11c8cf54ab4b909c3bd0e";
      branchTree = "0466ea7c98e164cd33e7c06ec0cc9e43334d69fe";
      catalogName = "crucible-canonical-terminal-rr-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "live observers at a quantum terminal project onto the next scheduler-owned vCPU at position zero without mutating serialized RR state";
    }
    {
      file = "0093-crucible-canonical-register-cursor.patch";
      branchSubject = "crucible: canonicalize after-instruction register cursors";
      branchCommit = "805087dcc31320ac1d615fbe7a5b7c36bf71bac5";
      branchTree = "d8e41ba4baace3a0403a191efa61284e918cb3c2";
      catalogName = "crucible-canonical-register-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "after-instruction register evidence advances its callback-local prefix and projects an exact quantum terminal onto the canonical next RR coordinate";
    }
    {
      file = "0094-crucible-retention-virtual-time-origin.patch";
      branchSubject = "crucible: anchor retention to virtual time";
      branchCommit = "887b32dcd5fa6ce2c26b68cbc93f8754e0fa47c0";
      branchTree = "ec162b01adba9c3ba986a39f17798c30dc20a55f";
      catalogName = "crucible-retention-virtual-time-origin";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "memory-retention expiry originates in authoritative virtual nanoseconds instead of mixing raw instruction coordinates with clock-biased deadlines";
    }
    {
      file = "0095-crucible-raw-pte-update-identity.patch";
      branchSubject = "crucible: preserve raw PTE update identity";
      branchCommit = "36acf3c4787f59390cecc5e4c15ddb964a01929e";
      branchTree = "c8ad99b53256def5e05ca4bef80734c606d0ab1f";
      catalogName = "crucible-raw-pte-update-identity";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "x86 page-table translation consumes corrected transient PTE bytes while accessed/dirty cmpxchg preserves the canonical backing entry and cannot retry forever";
    }
    {
      file = "0096-crucible-physical-page-table-region-fixture.patch";
      branchSubject = "tests/tcg: target page-table regions physically";
      branchCommit = "ef180c26bbe3d512435b6ce5306c22edd00d1fe5";
      branchTree = "16cd53d277d3156ba9c8b9502647a304e6b82550";
      catalogName = "crucible-physical-page-table-region-fixture";
      class = "F";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-EVIDENCE";
      capability = "live persistent page-table-region tests address descriptor storage by GPA while ordinary guest-memory region tests retain GVA targeting";
    }
    {
      file = "0097-crucible-canonicalize-memory-retry-identity.patch";
      branchSubject = "crucible: canonicalize memory retry identity";
      branchCommit = "50b21eaf98a4b3baefdaec54a73e3dcd3ff8e05c";
      branchTree = "4ec5ebebfbd4a73dad7f6b1fb3828acf43bd2382";
      catalogName = "crucible-canonical-memory-retry-identity";
      class = "D";
      enforces = "DET-1,QFP-MEMA-1,QFP-STATE-2";
      capability = "memory retry keys exclude TB-local instruction ordinals and serialize that compatibility field at canonical zero across fault-driven retranslation";
    }
    {
      file = "0098-crucible-inactive-nested-tsc-guard.patch";
      branchSubject = "crucible: guard inactive nested TSC reads";
      branchCommit = "77c00c7ccbb047202afde3c3db615a49b7f5dcf3";
      branchTree = "3feb4d8e0999ccd0cb78164ba351dd3539628511";
      catalogName = "crucible-inactive-nested-tsc-guard";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,PATCH-3";
      capability = "inactive guest-clock faults avoid TSC sampling inside SVM entry and exit so nested execution preserves upstream icount accounting";
    }
    {
      file = "0099-crucible-valid-aarch64-abort-fixture.patch";
      branchSubject = "tests/tcg: use valid AArch64 abort syndrome";
      branchCommit = "c33b2114183607a18826fcc60ead21bbde1f7dd8";
      branchTree = "5131036327904b1ce23baf2b12ba09268249df37";
      catalogName = "crucible-valid-aarch64-abort-fixture";
      class = "F";
      enforces = "QFP-MEMA-1,FAULT-EVIDENCE,PATCH-3";
      capability = "the live AArch64 poison-exception and retry fixtures submit the data-abort vector and a same-EL syndrome accepted by the production architecture validator";
    }
    {
      file = "0100-crucible-aarch64-memory-exception-vectors.patch";
      branchSubject = "crucible: validate AArch64 memory exception vectors";
      branchCommit = "5302bcac3b446321fef66084a2a3a294f583787a";
      branchTree = "74f144770c797d85aa9125d8e0345f9fb49bae18";
      catalogName = "crucible-aarch64-memory-exception-vectors";
      class = "D";
      enforces = "QFP-MEMA-1,FAULT-EVIDENCE,PATCH-3";
      capability = "AArch64 memory exception admission requires instruction-abort vector 2 for fetches and data-abort vector 3 for non-fetch accesses";
    }
    {
      file = "0101-crucible-canonicalize-snapshot-rr-resume.patch";
      branchSubject = "crucible: canonicalize snapshot RR resume";
      branchCommit = "15253289779ef75f017b3b4de95128bfaeff954c";
      branchTree = "f49224243d2696869bec456065448d0cd09584db";
      catalogName = "crucible-canonical-snapshot-rr-resume";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "successful sim-mode snapshots arm the same one-shot serialized-owner selection used after load so source continuation preserves the RR owner and intra-turn position";
    }
    {
      file = "0102-crucible-bql-exact-register-capture.patch";
      branchSubject = "crucible: admit BQL exact register capture";
      branchCommit = "22e6805be6243db5600f30cc404d7a928c4ee0cd";
      branchTree = "b4c0cba93b63a223c22af94aac1e90fdee2d335f";
      catalogName = "crucible-bql-exact-register-capture";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "BQL-held exact callbacks read quiescent vCPU registers while post-snapshot RR owner reselection is pending, and idle-time completion is explicitly scoped as exact";
    }
    {
      file = "0103-crucible-isolate-checkpoint-control-wake.patch";
      branchSubject = "crucible: isolate checkpoint control wake";
      branchCommit = "4d9da0d22f09991084e685b9fdbb8ff538d04110";
      branchTree = "cb85f3ffaaeacb53649e6c19bdc6ee5cad29b679";
      catalogName = "crucible-isolate-checkpoint-control-wake";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,PATCH-20";
      capability = "a pending exact VM-stop handoff wakes QEMU's main loop without resuming parked block coroutines or admitting post-pause completions";
    }
    {
      file = "0104-crucible-preserve-checkpoint-block-durability.patch";
      branchSubject = "crucible: preserve checkpoint block durability";
      branchCommit = "8a6c3ea6f7cf823b8609875f4327e8b8068e2982";
      branchTree = "7f34c324092310ddec31cdf5f809b49b8f0f0d06";
      catalogName = "crucible-preserve-checkpoint-block-durability";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QFP-BLOCK-3";
      capability = "synthetic QEMU stop-time flushes preserve the checkpointed Apache durability continuation and cannot create post-quiescence Crucible block requests";
    }
    {
      file = "0105-crucible-selector-control-plane-fixtures.patch";
      branchSubject = "crucible: isolate selector control-plane fixtures";
      branchCommit = "2fc19020522fafed796fed523ffa15152b376f46";
      branchTree = "18bba5bcdc489b6904117382dad03b006e5ac6d5";
      catalogName = "crucible-selector-control-plane-fixtures";
      class = "F";
      enforces = "FAULT-ORDER,PATCH-3,QFP-INST-3";
      capability = "live instruction selector overlap and exclusivity fixtures use unreachable occurrences so admission checks remain isolated from data-plane fault delivery";
    }
    {
      file = "0106-crucible-defer-active-slice-host-wakes.patch";
      branchSubject = "crucible: defer active-slice host wake requests";
      branchCommit = "7df0704a40f8dff5d7329569e9ab05aef8bd6245";
      branchTree = "999a43db0b41bebf97f5e82ba66091d8154f6887";
      catalogName = "crucible-defer-active-slice-host-wakes";
      class = "D";
      enforces = "DET-1,QFP-KICK-3,QEMU-43";
      capability = "an atomic idle-active-pending handshake admits multi-vCPU state-free wakes only before TCG starts and never lets them select a translation-block endpoint, while single-vCPU soft exits and explicit terminal and committed lifecycle wakes remain live";
    }
    {
      file = "0107-crucible-anchor-rr-cursor-genesis.patch";
      branchSubject = "crucible: anchor RR cursor at guest genesis";
      branchCommit = "e8a03808f07b1d469e3ea8c949f1b0b04f92dce6";
      branchTree = "8419ad547b9518297dc2ed2d973689c761d0ba23";
      catalogName = "crucible-anchor-rr-cursor-genesis";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "fresh sim-mode execution establishes vCPU 0 position 0 before the first budget, and the serialized owner remains authoritative across partial turns and VMState restore";
    }
    {
      file = "0108-crucible-deterministic-network-kick.patch";
      branchSubject = "crucible: preserve deterministic network continuation";
      branchCommit = "fa9e56fda83b3363a3979233544a257293e29909";
      branchTree = "6ee7f50f65319620b51da496393795042f48cbbd";
      catalogName = "crucible-deterministic-network-kick";
      class = "D";
      enforces = "DET-1,PLUG-23,PLUG-24,QEMU-43";
      capability = "sim-mode virtio-net queue kicks and serialized tx_waiting resumes drain every deferred TX bottom half synchronously, supply one committed raw transmit icount, preserve the virtqueue notification cursor in an optional sim VMState subsection, symmetrically flush pre-checkpoint translation history, and use bounded cache-independent TB shapes without direct chains on both continuations so VMState restore preserves packet and fault-decision continuation";
    }
    {
      file = "0109-crucible-control-boundary-node-faults.patch";
      branchSubject = "crucible: dispatch exact control-boundary node faults";
      branchCommit = "51a1ec02a606d60465bfa32cbbc73bd242faef22";
      branchTree = "5b2c51565862658ed75e83a4ca04e4b0858beb5f";
      catalogName = "crucible-control-boundary-node-faults";
      class = "F";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "a node-boundary command submitted while QEMU is halted at an exact drained control wake is dispatched at that same raw icount, so PREPARE and APPLY complete without requiring guest progress; terminal authorization hashes zero the raw evidence coordinate before the plugin maps it into scheduler-logical space";
    }
    {
      file = "0110-crucible-release-halted-rr-turn.patch";
      branchSubject = "crucible: release halted partial RR turns";
      branchCommit = "4dba51665731496fa872294480cc22c96e570642";
      branchTree = "aa758829bf2b9613ca889d23d925ab913aea81e8";
      catalogName = "crucible-release-halted-rr-turn";
      class = "D";
      enforces = "DET-1,PLUG-24,QEMU-43";
      capability = "a vCPU that executes HLT before exhausting its serialized RR turn leaves the execution loop when no alternative vCPU is runnable; a helper-marked multi-vCPU guest PAUSE fences control-boundary acknowledgement until it commits a cursor-zero early handoff immediately after icount accounting and before callbacks or host-work exits, so a released spin lock cannot be reacquired before a waiting peer runs; and that exact completed-turn handoff admits safe register capture while other owner mismatches fail closed";
    }
    {
      file = "0111-crucible-accelerator-service-schema.patch";
      branchSubject = "crucible: correct accelerator service schema";
      branchCommit = "a390da08d38e9cc63ecd6bf60a2e8d79f30d253f";
      branchTree = "841ab32c637a09efc7d78abeddc7e8a3a83cbcf3";
      catalogName = "crucible-accelerator-service-schema";
      class = "F";
      enforces = "QFP-ACCEL-SERVICE,FAULT-ORDER";
      capability = "typed accelerator service commands admit the ratio-valued capacity field used by the versioned node-fault payload before atomically installing compute, memory-rate, thermal, and power service policy";
    }
    {
      file = "0112-crucible-compile-affected-clock-sources.patch";
      branchSubject = "crucible: compile only affected clock sources";
      branchCommit = "7b9b607ebd3dc190128214757d5e29521b0939eb";
      branchTree = "4a6f1cdc0313797de3211af66066d8410d384d7f";
      catalogName = "crucible-compile-affected-clock-sources";
      class = "F";
      enforces = "QFP-CLOCK-SOURCE,FAULT-ORDER";
      capability = "a committed clock rule recompiles and rearms only sources selected by that exact rule, so an unrelated source that cannot project raw time at the stopped boundary cannot invalidate the authenticated transition";
    }
    {
      file = "0113-crucible-restore-accelerator-rule-indexes.patch";
      branchSubject = "crucible: restore accelerator rule indexes";
      branchCommit = "9b5d22a78d42d034e248d7e8f33e8527c467cd14";
      branchTree = "f16be2ffdfdce2a19343bf32c155a387186dc94b";
      catalogName = "crucible-restore-accelerator-rule-indexes";
      class = "F";
      enforces = "QFP-ACCEL-SERVICE,FAULT-RESTORE";
      capability = "fresh-process VMState restore rebuilds each accelerator lifecycle, result, memory, and service rule index from the authenticated staged node-rule ledger before commit, preserving persistent accelerator behavior without duplicating rule ownership";
    }
    {
      file = "0114-crucible-authenticate-fault-result-payloads.patch";
      branchSubject = "crucible: authenticate every fault result payload";
      branchCommit = "5f22ca7f8515f8b923c97d6c52f2fb89526aafd1";
      branchTree = "60e62f5e96aa6645105e2c6f894adbebfe366a53";
      catalogName = "crucible-authenticate-fault-result-payloads";
      class = "F";
      enforces = "QFP-RESULT,FAULT-ORDER";
      capability = "every queued fault result authenticates the exact payload retained beside it, including prepare-time rejection evidence, so the host can classify a typed rejection without losing transaction ownership";
    }
    {
      file = "0115-crucible-clock-impulse-read-error-policies.patch";
      branchSubject = "crucible: honor clock impulse and read-error policies";
      branchCommit = "7c8d69b83c5a51d5f18f54ab5596272d2c194200";
      branchTree = "8c0e235f449f8a1c32e1574205823e5fe92bd781";
      catalogName = "crucible-clock-impulse-read-error-policies";
      class = "F";
      enforces = "QFP-CLOCK-TRANSFORM,QFP-CLOCK-SOURCE,FAULT-ORDER";
      capability = "impulse clock transforms retain their effective monotonicity and overdue-timer policies in versioned clock VMState, while an x86 TSC read-error transition raises a deterministic guest #GP and internal projections retain the last source value";
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
