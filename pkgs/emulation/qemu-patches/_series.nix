# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "4a664bbdb5b80497a2f3c2129277b0aa718ce786d7d258b72be270bda860dc1b";
  patchBranchBaseCommit = "0400e2d08acb30307af7cb214b21552807c1dd46";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "5c8031ff78718263eb9b8218249f49b9a47ff6d1";
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
      branchCommit = "5a5c3098c96b55ecbe0132d18bcbd9f63087a084";
      branchTree = "1ca7e7b338e53f5b1f44b4e4ab4d40a837e930e7";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "7a46633ed1fbd7299d82d380c7e26c0b5dadbbc8";
      branchTree = "90a039bb166611318048212dafb58259e1e36319";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "489151e30ac0992a5c7a051840d1ea31a0472e5f";
      branchTree = "e82978a12d1c6884e7e60be3baddbd4682831a53";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "e2fc6665eed6aa3dbc4435fb57483e63331b5625";
      branchTree = "c1b67918dd04ec8cc73284829a4d69d347bd08a5";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "831862e25d453783fe52f15a12b9354ec9b53a73";
      branchTree = "1b1b3816d337e9949439e3a02d9e3eab203d38c1";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "9833fe210a3d169788b9e25366cef2f24837bea5";
      branchTree = "73a60003b165c620f23799201a05f009acd541a1";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "d1fc6f6c9074f4a1d9f9e481a7557dbc328f13fd";
      branchTree = "8f5b9a33cbb804ff40bf77c031a03c2ed68a5254";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "9a422b0585807a94bae0b8dbe2e5a693cb09712f";
      branchTree = "9d0616e43c6df4119bf8adf732e8ebd05b71ac86";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "4597dbf78ab830b212ba744d67bb7312fe42ce48";
      branchTree = "ba10dcf73731d7361a68c9d4b218886ad0405e86";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "229f888b3ee107054ca1f21f410a674a52f35382";
      branchTree = "e4bff7772965ad362136a767d70b670bc3dca16b";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "8e7dd9ebdade24d16f8b35b23d8802e511e90db6";
      branchTree = "fa4d9f8fdeebc96943680f61159af30d8921c878";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "075679e14e41d0f19771b9bf06749cad94b206a5";
      branchTree = "3b4d1b13ed358e71a6b7ffb8159b749029533a27";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "4d20ed55a01a69cb9ba9a8254f0a7096e4c5a8fc";
      branchTree = "c2aaec854b60d05d56ee008a3700f236c4421340";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "736b6166fe8db865a01ecca27dad1ee4a79cac15";
      branchTree = "f3b717d92780ffd9bca96b2af7f9f025e3fe07c6";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "f26b8b3985491cb5040ebb8ca16cd1cd6f132eaf";
      branchTree = "dc13061595a87d7dbeabef810d4662afc25b1694";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "4f36eb1c2dcaa9d7398b79ea33fb906ed524ba30";
      branchTree = "8b59daa98492f3e562b99c02cfcb350363f5318e";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "d85633e4abd770b5e99bee2d70d580b8b05c0888";
      branchTree = "19b44c0583b2b78797716ba046f2f54dc35cfb87";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "42b1c7a2f747e419301763aac8f3a44fef7352fe";
      branchTree = "e7ab21a2a296eee489051349e11a9bbc12e7d26f";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "a02745f357b4aa7a601987c886a183ddaad36d31";
      branchTree = "f5f0dbcd0e4d31e4211ad534bf98da2cbc4d17bf";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "1f735662b82e05a7d5aa630df96890a316679762";
      branchTree = "b0195b20be019b1be4af94214747249ff89c5f91";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "e90876609bda069c4cb587b4751961051a2fa397";
      branchTree = "d015671c7a8ad73fd1182733429fa55036d08edd";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "6dbe5256e927970bbefb457f2a94c91b03d2be0f";
      branchTree = "82d8198e5a761ab6a74ca80e1bae2173462dc822";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "f37c5aa265d293bc4ec01716c63da01f4d49b69c";
      branchTree = "f5f23eb69e604cb76524378d6ae5cdd560c8a4b8";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "77cf9b346b52f730a3facef47f1c35b3a462d081";
      branchTree = "9482fc46edf0a1060d156094c860a7c227467281";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "01fa78b07da0fc725dfe3b436d5780ef1a6ff304";
      branchTree = "c62f0b0a2b6b500312e89d2abb874df63b8098ef";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "b3aa610f609505c996857e64fea8cbbf7a0d6f76";
      branchTree = "64064e9c66b24fb065c6966ce4aee2c3bd071f69";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "331c54e62287e5b8eca59cbdf30de5f24b726501";
      branchTree = "5c4359f5224d552b47efdefd3897481802835f5c";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "a8d0d26a6fef8fd30ae483ed6a8c3b99aab40f89";
      branchTree = "e430cd8696caa5b51922204497d45c995577a3ab";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "3773c2949dde24efc2996cd55b6aec7ef9a477d6";
      branchTree = "e07e6bb5cb2b779b4fa7ded76dc955b0ea3910a7";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "d4fa63a68a27494198bd984fe8d31321530e0bf1";
      branchTree = "a2bb4515bd741315a8b7e0fd984b3e9da6974579";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "53f07f6fda8af26a553ccc89b081fd9ed16b3c3d";
      branchTree = "bc32b25bbbe6a9d4cff64e44526b5878bc8bd1df";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "6ea73696a369193bb4f61cf9807dcc916492638f";
      branchTree = "5f21f4ce0cf500eb87cda3f8975cf9b164d5f084";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "2cc1e6405da24c6cb1fd3686ba1b7b6df70df973";
      branchTree = "217f70818650b940724d4d3d8dfb97fa63b1860c";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "9ecd7e804f933ad32007a2de33ad7d491ac3b3dc";
      branchTree = "177163764446a3e4ac04846ad87b533cc0378552";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "8b315f19b28b6c04967a25d9f3be61fbda3f8b2a";
      branchTree = "f72d328f82bc63ee36a401282492f460482f6f49";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "3c10f9c1b88fe8b3267fcb8bde3cca490b4b5796";
      branchTree = "33b3753a19b74177ca7f323198427a7c0277f0ed";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "be7c60df871183da02681c3a199cfcec5aba1a35";
      branchTree = "8f99375fccdf9adae3014eec6d47a5c566a121f8";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      branchCommit = "2819c7d5ad6a9906243f05c15149e8555912625c";
      branchTree = "9c7e3efdc9d844a3d7cc5c55aaa82ff07444e981";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      branchCommit = "b3fbaee866c4136c31bb31371d0c63915ed6385f";
      branchTree = "73f9fcab6049c3143d3e707d1381fbd2ad0f9415";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped guest virtual-memory writes for synchronous white-box doorbell replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "727aa5d4dbb76d14c2a40298889b6a27137e09ef";
      branchTree = "7705c290ae8ec9e5e3b2add9044f44dca85243b7";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "b599df8768c07d21c478554c75b2dfc5cca9ffea";
      branchTree = "ed42f964b301ddfbef08462bdc859c2c4c04edd5";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "fb4e5914468d382a48ad7e2929cc7d2e0c7b9651";
      branchTree = "5a07309dde2302935fc7e06ad209e3982bfac271";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "cd8aebbe53eee3f0ab78519c9a571341cd523ef5";
      branchTree = "900a56e50d2526984ec4b65d9101d9b97748d3ab";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      branchCommit = "819e8f0f33754602931b955cb598cbcc9fd0f928";
      branchTree = "619e224e4914e0ffee8fe3df7498ea0495875214";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      branchCommit = "faa5de98141dee32b5220a09c7085718e03a0797";
      branchTree = "c155b194e8433dc8058c550d007892af3566752f";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,FAULT-ORDER";
      capability = "versioned fault command registry, bounded result queue, and plugin ABI";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      branchCommit = "a0441e755cf0f589bab6c79de08b5021a0094742";
      branchTree = "09353d2cac767bcb5eac0057bcc5993c07283c60";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement and same-boundary prepare/commit completion";
    }
    {
      file = "0049-crucible-memory-boundary-mutate.patch";
      branchSubject = "crucible: atomically mutate guest memory batches";
      branchCommit = "9a4c5529f7400d3daf747a11179801f7f47cdb7e";
      branchTree = "7e7ebaf2d127343331fe43da20212dfa969d8708";
      catalogName = "crucible-memory-boundary-mutate";
      class = "F";
      enforces = "QFP-MEM-1,QFP-MEM-2,FAULT-ORDER";
      capability = "atomic ordered GPA/GVA mutation batches with translation, RAM-map, dirty-page, and TB evidence";
    }
    {
      file = "0050-crucible-memory-access-faults.patch";
      branchSubject = "crucible: add memory access fault rules";
      branchCommit = "da02d75674a83a91bc7d7c451665d5793602e04f";
      branchTree = "5e658e827fd1c65b637335f91516b91828075411";
      catalogName = "crucible-memory-access-faults";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "typed fetch, load, store, page-table walk, atomic, and identified virtio DMA memory fault rules with shared service and persistent region state";
    }
    {
      file = "0051-crucible-add-architecture-register-fault-mutations.patch";
      branchSubject = "crucible: add architecture register fault mutations";
      branchCommit = "130a1797c3e7b9ebc27ae2ba8b57109ea5de050a";
      branchTree = "a25bc910c3f9cb015d67fe2476844937524f025c";
      catalogName = "crucible-architecture-register-faults";
      class = "D";
      enforces = "QFP-REG-1,QFP-REG-2,FAULT-ORDER";
      capability = "manifest-bound x86-64 and AArch64 register mutations at exact instruction boundaries";
    }
    {
      file = "0052-crucible-instruction-and-exception-faults.patch";
      branchSubject = "crucible: add instruction and exception faults";
      branchCommit = "44140ee97e8f3ee1b87570dbb2c7a2d57c590200";
      branchTree = "0c5cccdb884aa0013a1f95fd094317818c6a45c8";
      catalogName = "crucible-instruction-and-exception-faults";
      class = "D";
      enforces = "QFP-INSN-1,QFP-EXC-1,FAULT-ORDER";
      capability = "exact x86-64 and AArch64 instruction result, skip, replay, and architectural exception faults";
    }
    {
      file = "0053-crucible-interrupt-faults.patch";
      branchSubject = "crucible: add interrupt controller faults";
      branchCommit = "9ab0736fb69da1835d796e67590a8141d30daa8f";
      branchTree = "2f0cc27179d2f0d10b81bfdd3ea37d0185deb06d";
      catalogName = "crucible-interrupt-faults";
      class = "D";
      enforces = "QFP-IRQ-1,QFP-IRQ-2,FAULT-ORDER";
      capability = "manifest-bound interrupt drop, delay, duplication, replacement, and bounded storms through realized x86-64 and AArch64 controllers";
    }
    {
      file = "0054-crucible-inject-architecture-hardware-errors.patch";
      branchSubject = "crucible: inject architecture hardware errors";
      branchCommit = "762e4338d3711a279c1ef5c73cd19adce977e169";
      branchTree = "4d9e568f3ef998bdc11449bf9cdfd323708ff1d4";
      catalogName = "crucible-hardware-error-inject";
      class = "D";
      enforces = "QFP-HWERR-1,QFP-HWERR-2,FAULT-ORDER";
      capability = "manifest-bound x86 machine-check, AArch64 RAS, and realized memory ECC delivery with transactional evidence";
    }
    {
      file = "0055-crucible-vcpu-service-control.patch";
      branchSubject = "crucible: control deterministic vCPU service";
      branchCommit = "9e047a17365014e3a06c6a51ff5fb83b505bccc8";
      branchTree = "7a63dbb77c79f6ee9ac897f01f8fc47ca46c08e2";
      catalogName = "crucible-vcpu-service-control";
      class = "D";
      enforces = "QFP-VCPU-1,QFP-VCPU-2,FAULT-ORDER";
      capability = "exact rational vCPU service, fixed-topology stall and offline state, bounded work conservation, and replay evidence";
    }
    {
      file = "0056-crucible-node-lifecycle-faults.patch";
      branchSubject = "crucible: add deterministic node lifecycle control";
      branchCommit = "a77c0984bbdfe7a0658df2992bdb26b142975254";
      branchTree = "6287296215648eef26dcf94b2759b9cdf03471ff";
      catalogName = "crucible-node-lifecycle-faults";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "deterministic node lifecycle transitions and schedulable node or vCPU hangs with closed state treatment and replay evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      branchCommit = "0ae694776b3951daab1a099e9d4d02e2c669cd75";
      branchTree = "4ad83f09241e0da6c05f86468b11ad75a073b80e";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      branchCommit = "4b10a4078b1629b0d7e30409b6336ad4a697cee1";
      branchTree = "1c2c197fe72fdb7269807756922c0707f93206cd";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
    {
      file = "0062-crucible-block-transport-reset.patch";
      branchSubject = "crucible: add transactional block transport reset";
      branchCommit = "d9694f2d0d19d9f6ef42506459f7f04bc93febac";
      branchTree = "07a7dffa0553efb0c5df132f1dc920af0d56063c";
      catalogName = "crucible-block-transport-reset";
      class = "F";
      enforces = "STOR-RESET,STOR-RESULT,DET-16,PATCH-26";
      capability = "transactional epoch-scoped block reset, recovery admission, retry dispositions, and declared topology re-enumeration";
    }
    {
      file = "0063-crucible-plugin-vmstop.patch";
      branchSubject = "crucible: hand exact checkpoint boundaries to VM stop";
      branchCommit = "4215711efde764c32f62213f85338ee3ccac256b";
      branchTree = "f96ed5ef5281fc363728ea56005435adfca8af99";
      catalogName = "crucible-plugin-vmstop";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43";
      capability = "RR-global exact plugin checkpoint handoff with native pause and QMP flush-error propagation";
    }
    {
      file = "0064-crucible-terminal-lifecycle-completion.patch";
      branchSubject = "crucible: stage terminal lifecycle completion";
      branchCommit = "0709103565946ae1f1d6997f9bd5c8aea133cf28";
      branchTree = "624e78baeb180f392366f98760326b9ebfef679f";
      catalogName = "crucible-terminal-lifecycle-completion";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "two-phase typed terminal lifecycle evidence, QMP authorization, and exact process-exit staging";
    }
    {
      file = "0065-crucible-authenticated-terminal-lifecycle.patch";
      branchSubject = "crucible: authenticate terminal lifecycle completion";
      branchCommit = "e2ddff3965b6623784f0d4c887f173bbe653cbc8";
      branchTree = "07644d4bc11ea8201f6b2e620712a6ef4d9629eb";
      catalogName = "crucible-authenticated-terminal-lifecycle";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "dedicated idempotent QAPI terminal authorization bound to action, evidence, and process generation without guest resume";
    }
    {
      file = "0066-crucible-immutable-process-generation.patch";
      branchSubject = "crucible: provision immutable process generations";
      branchCommit = "2162a5ea46636206734be52f17e6e594cab69bc7";
      branchTree = "c2a23c0ede4ad50b6affa24f9b2bc7852a576e3f";
      catalogName = "crucible-immutable-process-generation";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "launch-time immutable process generation provisioning before fault-command admission";
    }
    {
      file = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      branchSubject = "crucible: serialize and harden core fault state";
      branchCommit = "6acb2b12718635bf1cfaee34e9438fff22b8e0fa";
      branchTree = "1908feebda4f33583621da2afb9c7d4888e61daa";
      catalogName = "crucible-core-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,FAULT-ORDER";
      capability = "transactional bounded VMState for core command, memory, CPU, interrupt, hardware-error, service, and lifecycle fault state";
    }
    {
      file = "0068-crucible-guest-clock-faults.patch";
      branchSubject = "crucible: guest clock faults";
      branchCommit = "b32459c4bd0dfed4c5823448dba304ab620f6822";
      branchTree = "3494cecd178557ca9fc72b92ed490784ede111b6";
      catalogName = "crucible-guest-clock-faults";
      class = "D";
      enforces = "QFP-CLOCK-1,QFP-CLOCK-2,FAULT-ORDER";
      capability = "transactional guest-clock transforms, source-state transitions, timer rearming, and typed causal evidence";
    }
    {
      file = "0069-crucible-accelerator-fault-device.patch";
      branchSubject = "crucible: add deterministic accelerator device";
      branchCommit = "5c8031ff78718263eb9b8218249f49b9a47ff6d1";
      branchTree = "b7dd420654a010a86226cfe8f2fd5e32b4e6ec49";
      catalogName = "crucible-accelerator-fault-device";
      class = "D";
      enforces = "QFP-ACCEL-1,QFP-ACCEL-2,FAULT-ORDER";
      capability = "migration-safe virtio accelerator co-simulation transport with lifecycle, result, memory/ECC, and service mutations for closed GPU, TPU, and FPGA job schemas";
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
