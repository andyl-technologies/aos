# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-11.1.1.bundle;
  patchBranchBundleSha256 = "ae78641e666d6158f3c70a9d7791a753e8a45e78ea86b8553f642ec0defb5d7b";
  patchBranchBaseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  patchBranchBaseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  patchBranchHeadCommit = "7273c8ae7bfa040cda1d234fba811767e484df53";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";
  patches = [
    {
      file = "0001-crucible-sim-accel.patch";
      branchCommit = "286ccad75d00d4515a0fe11a98f2f21ca7c0f5d7";
      branchTree = "7b805f34d83433317ae5914cd6c2594219e5a9ef";
      catalogName = "crucible-sim-accel";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "-accel sim deterministic TCG accelerator";
    }
    {
      file = "0002-crucible-rr-fingerprint-helpers.patch";
      branchCommit = "6b7f8c18ce5b14ee807080cac2858645976c9c82";
      branchTree = "2e9f492ed84b42c275ea11992ed99788d65853cc";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "51c11cf80b1b1e9bb900b777f848fe0814e4ac8f";
      branchTree = "4d82828541cad014ae092122c087811eab4130dc";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "3c073266d130a050b87c53d53b7f02f1bcccf75c";
      branchTree = "5b2b66470453cca95e26ccf364ee5a0563b3578c";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "afb1dc6d9d12f5b975a4e500c23882a766bb94a3";
      branchTree = "dddec251bb4aa9e92866780b32fe221c78093936";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "87e7a867552db00921e370f291772bdefc9a49df";
      branchTree = "fb39430816d7b292e50c98c4ba688f1393b08804";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "966ca95bc1ae698afa82c1974308af5a3bcf8f8a";
      branchTree = "7ca2f831506a5010a33b6c4f203f5f9b771e4c8c";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "bb28ce790eb182cc335d17db05993195625c7427";
      branchTree = "adddab94218359cd1eb8d031f1874d4701b82d0a";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "4ab3f7150cfa6ad5419e38dc3d2bb9dc47f0df89";
      branchTree = "7d015c836fbb41aede80e0197b115e11bb793286";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX direct injection with canonical shared-memory backpressure and fresh guest-device probing on every retained retry";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "a1e25af609d6627003c514774b1b5f6da5c874c7";
      branchTree = "7decf1b0631225bcf94a0d3a517d7aeb8ed00f79";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "8cc7db57177f4375d932a19a19f17fc2032a3492";
      branchTree = "094fbc948cf78bf59a553496ed74600b3c787288";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "82a8c02673aaf64d91fc0b5ba13d7ecab804f1a7";
      branchTree = "f2f34a21690f39a5105f4ebf9b56bea60c576b9f";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "262fd68d5eeec5f63452681579c74e677114ad41";
      branchTree = "4d6269ab681a1ef03376a5dd115ca78d1bff87b7";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "ceb2b67c7f2e648bb5183771196460d6a9034bfc";
      branchTree = "ec8ddc1bb6a29af19c4c69a0a905e2f0783f4b04";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "d84909758728b798e0489f8ff2a1818aafd87d79";
      branchTree = "2788dfc44f1d5a3cdeca6f956d6d64d491847f2c";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "06471485f260081b2cebed2d2c6eca61b7751a8a";
      branchTree = "fa9efc138da4b7b62e3fc0fccdddb45fb24f258e";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "03ee4fe04ed883b4550cff3d785cd121fff97ff8";
      branchTree = "6cbc99c00af6610c40295548656140843c17b685";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "273e1f0314511b94f364284daf90d58a1087512f";
      branchTree = "07366983be054888bd1cf3b1fdce39aa43c540e9";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "7349d8c97bdd170086b5c0345522cbb1682905b5";
      branchTree = "f4c9767e6f8b80e9a981a296ea6d4185a643c2ff";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "1ed7eb19ce7f4e30ea62ed6b3e6fee45a9ca1225";
      branchTree = "3e96acfebcfad152fb42f9c3ead9ef313dbf89dc";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "7c0a02b070dfa12ddc360294658c66bb87783af3";
      branchTree = "6066036eb0d7b35c613fba7378467987808114a9";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "6930816f81a7343a41b4681486e08c63730bca84";
      branchTree = "7b91fad0ba8922a7fb8932425611599bbd70da1d";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "68baa7badbd56d148a95232650de4d02cf708a88";
      branchTree = "474b53656315947e86e00601b6a5e0f0b67b400d";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "2ac94c38fd6cdec25d7f665f9f1abc620c8961b6";
      branchTree = "752b8b2a8a26f10457035c5aed0aa8de74f53275";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "934187a3cd76dc575cd9225359117160af8603e9";
      branchTree = "c33e980595c811771b65ba56f08b5740a09e000a";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "059781d1a9ddd26bfc43df0bef3e277d28af97e7";
      branchTree = "626ab51da5c6c273db9f56552842a5baa21187d4";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "6341ee7f8c7a448d48bb48783e504a37eed6969c";
      branchTree = "be5154772fa63d172db7f5fda2ded3d3f45739be";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "8fe67c016ff06428867fc406037676bff8b45d27";
      branchTree = "144283db8b5746f77c8dc5227d214ba9a20134da";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "d6ea8e96aa6584e4af8fd887f9ddc0de06bc8be1";
      branchTree = "1b568e9438235a454543da6093edb5d5e89d977d";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "d4eeeff808b51c933ff4cda39a8aba3e4a4e247b";
      branchTree = "76c8d3285dcf7f5bdc4b0093b6e4ed2421b57567";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "0b220e2b42d7fc11b9de40120a75900421d7307e";
      branchTree = "9c065044febe2245a53c6a3bb3f2c88eb0749f12";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "ccb9d8e18e750fcc3cb496e32b6a5d567ee42ad2";
      branchTree = "cbf3be85b0304a56766c9cae6b3752970e27aee0";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "8c43b8f9f88a42d058270d12ae71d577b6d1ca6b";
      branchTree = "5042fd3e91e7fcd8b1c18c985398f493429d8bd7";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "a33d5d846ebb45b83196413594d5902721c03cde";
      branchTree = "5a25c441675d6d24b612d514e4711bb0a2dd86b7";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "adc43e37453b677efe68f7ac5b4eec4f3fc74d96";
      branchTree = "1af19c4182a6b189944e93422a3673f669166913";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "6e1eadc89be6fb7d8bd8120ffadaf9f0516cb8d1";
      branchTree = "2a3c33607e90ea4c8528b5bedb26eeaf973e5d92";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "ecdb64e814e751fb4da4afa37b9004b102591ff8";
      branchTree = "1d8e78e4828f01de1a722f7b12a69349cc2f1c23";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "19e5adee6077838bd313d8d7bc8b8b56da14c141";
      branchTree = "927e6682c45514216669cb6f323ec47bc573bd66";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "7d97c8b15af5afad85582b0c3c503d2368254809";
      branchTree = "d17c481c76228a20a09965968a0119ce0b012934";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      branchCommit = "4e2cbfba2dadc1c469e24186b27ce59528329982";
      branchTree = "9e5bfc6bb1de310e7f78d8492168d414e3146325";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      branchCommit = "166e7e4a0e79d8b9ed3b167838fc3155e2f4a581";
      branchTree = "d3de348688d41cb02560688ec2ca0882f43938a0";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped guest virtual-memory writes for synchronous white-box doorbell replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "543b5ac9916fd577f6bfbe77f6a79f6029df27ed";
      branchTree = "40855016c820329217ca385c8da1223ece3ba278";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "ab34dab7291c9139e41ab7b5e4c056f39a44432e";
      branchTree = "f1ddf68153d799df72d771ec39a8db5449bfbc85";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "ff367c6b069eeb441aef68bc4c013cacfa77a591";
      branchTree = "336ee130bfffe587abb612928ce4c4e344bdfcdb";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "82859d81e9f6aa37d77200253041e491632af0f3";
      branchTree = "bf8e408574783c7c3ea23ec854b40beb549a94e3";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      branchCommit = "600015b0cd998f4af8af02087e0ab36f844690f6";
      branchTree = "9d7c2c1bbef7eb705dbe24a26117956cfa67b5f7";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      branchCommit = "b4b6ce3e93a92c756292ab01c4c76e8aac3c867f";
      branchTree = "ab58d210cd8f4cdec05d3dcf03bf4c0d64ac3301";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,FAULT-ORDER";
      capability = "versioned fault command registry, bounded result queue, and plugin ABI";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      branchCommit = "7adbec579cd2dd401e534f2b39deabb884cbdab1";
      branchTree = "49dd845a69d0848756eb23ba40ee0de2795ced55";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement and same-boundary prepare/commit completion";
    }
    {
      file = "0049-crucible-memory-boundary-mutate.patch";
      branchSubject = "crucible: atomically mutate guest memory batches";
      branchCommit = "e576dfeae565041e4402db1cd0e9f15844cb4648";
      branchTree = "980c338a7be024bf75cc2b4b3fc3aa219c60332f";
      catalogName = "crucible-memory-boundary-mutate";
      class = "F";
      enforces = "QFP-MEM-1,QFP-MEM-2,FAULT-ORDER";
      capability = "atomic ordered GPA/GVA mutation batches with translation, RAM-map, dirty-page, and TB evidence";
    }
    {
      file = "0050-crucible-memory-access-faults.patch";
      branchSubject = "crucible: add memory access fault rules";
      branchCommit = "d1fa01c99a662709a478715a5eae4badd0d223db";
      branchTree = "0437a36a7f37dd09b341298f6c4f8e765b4d8fee";
      catalogName = "crucible-memory-access-faults";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "typed fetch, load, store, page-table walk, atomic, and identified virtio DMA memory fault rules with shared service and persistent region state";
    }
    {
      file = "0051-crucible-add-architecture-register-fault-mutations.patch";
      branchSubject = "crucible: add architecture register fault mutations";
      branchCommit = "d4da75a6336751e5027665c6644e550132b26b36";
      branchTree = "acf3b2d71d2409ba5fed7f3dc2b6127eb03d4f96";
      catalogName = "crucible-architecture-register-faults";
      class = "D";
      enforces = "QFP-REG-1,QFP-REG-2,FAULT-ORDER";
      capability = "manifest-bound x86-64 and AArch64 register mutations at exact instruction boundaries";
    }
    {
      file = "0052-crucible-instruction-and-exception-faults.patch";
      branchSubject = "crucible: add instruction and exception faults";
      branchCommit = "7c08aeab8374975e925b854ff5ac2b7bab5af640";
      branchTree = "e062c8f707991c000ab50de339cbe5f99661934a";
      catalogName = "crucible-instruction-and-exception-faults";
      class = "D";
      enforces = "QFP-INSN-1,QFP-EXC-1,FAULT-ORDER";
      capability = "exact x86-64 and AArch64 instruction result, skip, replay, and architectural exception faults";
    }
    {
      file = "0053-crucible-interrupt-faults.patch";
      branchSubject = "crucible: add interrupt controller faults";
      branchCommit = "f1db3bff9cea22ff06c5f0eaba06582f4b26894b";
      branchTree = "5de4bb3cbb5f28b3825abb415f722915f41fecfe";
      catalogName = "crucible-interrupt-faults";
      class = "D";
      enforces = "QFP-IRQ-1,QFP-IRQ-2,FAULT-ORDER";
      capability = "manifest-bound interrupt drop, delay, duplication, replacement, and bounded storms through realized x86-64 and AArch64 controllers";
    }
    {
      file = "0054-crucible-inject-architecture-hardware-errors.patch";
      branchSubject = "crucible: inject architecture hardware errors";
      branchCommit = "7dd13617414ffd1bcc9a1ad5bf7e7170521c5824";
      branchTree = "63167c8ec6d592f2704854995c78ef6ddc2b4b46";
      catalogName = "crucible-hardware-error-inject";
      class = "D";
      enforces = "QFP-HWERR-1,QFP-HWERR-2,FAULT-ORDER";
      capability = "manifest-bound x86 machine-check, AArch64 RAS, and realized memory ECC delivery with transactional evidence";
    }
    {
      file = "0055-crucible-vcpu-service-control.patch";
      branchSubject = "crucible: control deterministic vCPU service";
      branchCommit = "870935e9daa80d85e5c123544a7314800e87cb3d";
      branchTree = "92c47703e55578e546ad94dea567a33ff1d03985";
      catalogName = "crucible-vcpu-service-control";
      class = "D";
      enforces = "QFP-VCPU-1,QFP-VCPU-2,FAULT-ORDER";
      capability = "exact rational vCPU service, fixed-topology stall and offline state, bounded work conservation, and replay evidence";
    }
    {
      file = "0056-crucible-node-lifecycle-faults.patch";
      branchSubject = "crucible: add deterministic node lifecycle control";
      branchCommit = "d9809a7084a65f488fa47c974c918e248b9cab52";
      branchTree = "653b9d753264734aec0b01427602c501dad50c82";
      catalogName = "crucible-node-lifecycle-faults";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "deterministic node lifecycle transitions and schedulable node or vCPU hangs with closed state treatment and replay evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      branchCommit = "9e7eacbc8f90858cbbbf01d612509a11028beb04";
      branchTree = "17bb6e0f4a6fc92dcb70f74291aaa81fa59d0aec";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      branchCommit = "ef8ad5cc9451191ed2c9479e5adc2fc953f2f391";
      branchTree = "769886ed8eb07d5a3e638a755522a7d9f266d950";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
    {
      file = "0062-crucible-block-transport-reset.patch";
      branchSubject = "crucible: add transactional block transport reset";
      branchCommit = "cc7556a83a789b3d24c357263c5ed940dc31cb09";
      branchTree = "40aa08b52a8d75286934f4dc7f9ee13a6ff09744";
      catalogName = "crucible-block-transport-reset";
      class = "F";
      enforces = "STOR-RESET,STOR-RESULT,DET-16,PATCH-26";
      capability = "transactional epoch-scoped block reset, recovery admission, retry dispositions, and declared topology re-enumeration";
    }
    {
      file = "0063-crucible-plugin-vmstop.patch";
      branchSubject = "crucible: hand exact checkpoint boundaries to VM stop";
      branchCommit = "b5359cb225a69c70bf78c77b89dcc2b856754db7";
      branchTree = "c9c7ac19cb199df911a52b24d23f883efe36d7c2";
      catalogName = "crucible-plugin-vmstop";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43";
      capability = "RR-global exact plugin checkpoint handoff with native pause and QMP flush-error propagation";
    }
    {
      file = "0064-crucible-terminal-lifecycle-completion.patch";
      branchSubject = "crucible: stage terminal lifecycle completion";
      branchCommit = "66e2da5f2d6e188567ddf33104effcf126d208c7";
      branchTree = "25b257bf815cd5655b535baa7304b9a12e808583";
      catalogName = "crucible-terminal-lifecycle-completion";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "two-phase typed terminal lifecycle evidence, QMP authorization, and exact process-exit staging";
    }
    {
      file = "0065-crucible-authenticated-terminal-lifecycle.patch";
      branchSubject = "crucible: authenticate terminal lifecycle completion";
      branchCommit = "1a79194c5107d521afbbb8ac7a4c571c29b00413";
      branchTree = "adb104e5aacbe5b01cd3be7e6e6217459a0dee04";
      catalogName = "crucible-authenticated-terminal-lifecycle";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "dedicated idempotent QAPI terminal authorization bound to action, evidence, and process generation without guest resume";
    }
    {
      file = "0066-crucible-immutable-process-generation.patch";
      branchSubject = "crucible: provision immutable process generations";
      branchCommit = "2a4946689f5344a0786d6a24decefb87331e7b6d";
      branchTree = "c92bf267862b10cb8c9ab0779617712971598710";
      catalogName = "crucible-immutable-process-generation";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "launch-time immutable process generation provisioning before fault-command admission";
    }
    {
      file = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      branchSubject = "crucible: serialize and harden core fault state";
      branchCommit = "7316e4193367a272051fe36e048328cc6299146b";
      branchTree = "6613ddcef9a483777f3ecb6b3e399c7a5f8dcdf0";
      catalogName = "crucible-core-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,FAULT-ORDER";
      capability = "transactional bounded VMState for core command, memory, CPU, interrupt, hardware-error, service, and lifecycle fault state";
    }
    {
      file = "0068-crucible-guest-clock-faults.patch";
      branchSubject = "crucible: guest clock faults";
      branchCommit = "9a4cd65501fa2b46f515deca6b30369e588390f0";
      branchTree = "aeb38cb218ebc82277c4f10493166518eed32e4b";
      catalogName = "crucible-guest-clock-faults";
      class = "D";
      enforces = "QFP-CLOCK-1,QFP-CLOCK-2,FAULT-ORDER";
      capability = "transactional guest-clock transforms, source-state transitions, timer rearming, and typed causal evidence";
    }
    {
      file = "0069-crucible-accelerator-fault-device.patch";
      branchSubject = "crucible: add deterministic accelerator device";
      branchCommit = "b42d32fb840bafccd68a0f0eb3f7610bc076e7dd";
      branchTree = "aaebb8e3cd08b819909e4ff6219b3de008636624";
      catalogName = "crucible-accelerator-fault-device";
      class = "D";
      enforces = "QFP-ACCEL-1,QFP-ACCEL-2,FAULT-ORDER";
      capability = "migration-safe virtio accelerator co-simulation transport with lifecycle, result, memory/ECC, and service mutations for closed GPU, TPU, and FPGA job schemas";
    }
    {
      file = "0070-crucible-fault-vmstate.patch";
      branchSubject = "crucible: finalize fault VMState identity";
      branchCommit = "75cf7565a4f0aa66e5775e611c37cc70073a786c";
      branchTree = "b8145c50e12dd2f62d91b28c9773522af2fb9e09";
      catalogName = "crucible-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,QFP-STATE-3";
      capability = "live fail-closed build, patch-series, shared-memory ABI, and exact aggregate fault VMState identity";
    }
    {
      file = "0071-crucible-lifecycle-precondition.patch";
      branchSubject = "crucible: bind lifecycle preconditions to VM state";
      branchCommit = "1af14005a370063855c5aca5ff0c49ec6eb64d7b";
      branchTree = "7459bbf0d152a6faaf84931a3bdf903f93215a14";
      catalogName = "crucible-lifecycle-precondition";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "atomic lifecycle prepare and commit over the same authenticated VM-state precondition";
    }
    {
      file = "0072-crucible-typed-node-result-schema.patch";
      branchSubject = "crucible: preserve typed node result schema";
      branchCommit = "7f29d67a61015fe147a481e4e64e756e5d97db8f";
      branchTree = "35d366e0131686fe9bdb0b6bcaa19c05d5fa9e7c";
      catalogName = "crucible-typed-node-result-schema";
      class = "D";
      enforces = "QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "fixed typed-command results with command-specific evidence retained on authenticated occurrence events";
    }
    {
      file = "0073-crucible-device-wait-vmstop.patch";
      branchSubject = "crucible: admit checkpoint stop from exact callbacks";
      branchCommit = "af40681c6ed675142aed7d6476b7770db4d908e5";
      branchTree = "bb3ae96021fd635dd626e28d5458a21f376bacbb";
      catalogName = "crucible-device-wait-vmstop";
      class = "F";
      enforces = "QFP-STATE-2,DET-1,INV-10";
      capability = "synchronous exact stop at drained control wakes with nonblocking admission from device-completion callbacks";
    }
    {
      file = "0074-crucible-arm-accelerator-result-opportunities.patch";
      branchSubject = "crucible: arm accelerator result opportunities";
      branchCommit = "5a98ebc63217309578a332ef4eb7e6d4de8b633c";
      branchTree = "f9ddfca20003686769b684038c0568df4bc24a47";
      catalogName = "crucible-accelerator-result-opportunity";
      class = "F";
      enforces = "QFP-ACCEL-3,QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "atomic one-shot accelerator result arming with durable reservations and typed deferred completion results";
    }
    {
      file = "0075-crucible-restore-authenticated-fault-event-requests.patch";
      branchSubject = "crucible: restore authenticated fault event requests";
      branchCommit = "6ef1f5368869dfd7681dc2ee55d5cafb036b444f";
      branchTree = "7edd6be7e6234c1074afadd24bf2e2c69297e064";
      catalogName = "crucible-authenticated-event-request-envelope";
      class = "F";
      enforces = "QFP-STATE-2,QFP-ACCEL-3,QFP-EVENT-1,FAULT-ORDER";
      capability = "mandatory authenticated request/evidence envelopes for fresh-process restore and exact accelerator-opportunity binding";
    }
    {
      file = "0076-crucible-9p-completion-wake-registration.patch";
      branchSubject = "crucible: register 9p completion wakes before plugin install";
      branchCommit = "81a85876e7711245f8fa0019c775233b05304a62";
      branchTree = "3e003e2d69afd81de44091d804164de1c47aed7f";
      catalogName = "crucible-9p-completion-wake-registration";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "realize-time 9p completion notifier registration independent of plugin installation order";
    }
    {
      file = "0077-crucible-serialize-rr-cursor.patch";
      branchSubject = "crucible: serialize authoritative RR cursor";
      branchCommit = "ff280b6f598d66ef1dce2e59fdbf2cae80cdb2d2";
      branchTree = "e6db2f465415ee1ecf0da580f8af868643ce2c9d";
      catalogName = "crucible-serialized-rr-cursor";
      class = "D";
      enforces = "DET-29,QEMU-34,QEMU-43,QFP-STATE-2";
      capability = "authoritative multi-vCPU round-robin cursor accounting and VMState restoration across host scheduling ceilings";
    }
    {
      file = "0078-crucible-fingerprint-guest-state-domains.patch";
      branchSubject = "crucible: fingerprint guest-visible state domains";
      branchCommit = "f60b5eb5820be8aefe1dbf1d81e83cbbe16e5b95";
      branchTree = "1c79ab66488480245a652fbba65d41535ef3646b";
      catalogName = "crucible-fingerprint-guest-state-domains";
      class = "D";
      enforces = "DET-29,QEMU-34,QFP-STATE-2";
      capability = "guest black-box fingerprints exclude separately authenticated process-local control state and target-declared transient CPU notifications";
    }
    {
      file = "0079-crucible-stopped-state-control-progress.patch";
      branchSubject = "crucible: bound stopped-state control progress";
      branchCommit = "ed4e353790d234a09a5ba3e68986fbaf3d64d9d5";
      branchTree = "221c70feb63dd57678f0af2e8dd83d78801a71b9";
      catalogName = "crucible-stopped-state-control-progress";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43,QFP-STATE-2";
      capability = "level-triggered stopped-state control progress with queued-work admission and a bounded BQL wait";
    }
    {
      file = "0080-crucible-inactive-retention-clock-guard.patch";
      branchSubject = "crucible: guard inactive retention clock reads";
      branchCommit = "eb0f39e89d7b654e9789817a4e46bcfcfe1640ee";
      branchTree = "3254fb4a2498bce37b59b4ba491b09d6aa413bc4";
      catalogName = "crucible-inactive-retention-clock-guard";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "memory-retention clock sampling only after an active-rule admission check so fresh-process restore cannot observe an irrelevant transient clock sentinel";
    }
    {
      file = "0081-crucible-deferred-result-evidence-test.patch";
      branchSubject = "crucible: validate deferred result evidence";
      branchCommit = "ab9fcc50feaf65378d83f7423e921fb5dfe7a4b1";
      branchTree = "66789a2289f1c77bdf096cd43592094ffebe9bae";
      catalogName = "crucible-deferred-result-evidence-test";
      class = "F";
      enforces = "QEMU-44,FAULT-EVIDENCE";
      capability = "live instruction-fault coverage validates the canonical typed evidence added to deferred completions";
    }
    {
      file = "0082-crucible-deterministic-instruction-input-state.patch";
      branchSubject = "crucible: stabilize instruction input selectors";
      branchCommit = "e30c082c9d7ed373f49a1b8a14a5078c64d925b1";
      branchTree = "bb02c404887b00ab7b5d591d9f9ca59ff3d8993a";
      catalogName = "crucible-deterministic-instruction-input-state";
      class = "D";
      enforces = "DET-1,QEMU-44,FAULT-EVIDENCE";
      capability = "instruction input-state selectors use a cross-process-stable architectural-register digest while full CPU, RAM, and device state hashes remain in canonical evidence";
    }
    {
      file = "0083-crucible-inert-clock-restore.patch";
      branchSubject = "crucible: preserve clocks across VMState restore";
      branchCommit = "4d4a025c222f9ab08f651767ad3287249632a321";
      branchTree = "a227081aeef108a3b068f13db47700eb88771adb";
      catalogName = "crucible-inert-clock-restore";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,QFP-STATE-2";
      capability = "the complete VMState load transaction suppresses transient guest-clock transforms, then a successful outermost restore retains native timers, including HPET timers without a fault-managed generation, and rearms effective Crucible transforms";
    }
    {
      file = "0084-crucible-exact-restore-network-announcement.patch";
      branchSubject = "crucible: suppress migration announcements on exact restore";
      branchCommit = "59d4ee3399f5deb029a950738a64f456ca66816d";
      branchTree = "59ff745d17c9b05dbae9542c5ab993a73eb189d6";
      catalogName = "crucible-exact-restore-network-announcement";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "exact Crucible VMState restore suppresses migration-only virtio-net guest announcements while ordinary QEMU migration retains its upstream announcement behavior";
    }
    {
      file = "0085-crucible-register-rejection-atomicity.patch";
      branchSubject = "crucible: prove register rejection atomicity";
      branchCommit = "1a716d10558d50d10acdf83184a3f58f813f501d";
      branchTree = "d9194a953d52706d1e2a4a4c350cd1be391a8200";
      catalogName = "crucible-register-rejection-atomicity";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-REG-2,FAULT-EVIDENCE";
      capability = "exact RR ownership gates canonical register observation; every realized CPU manifest is validated; rejected register commands preserve every canonical GDB register byte and all six mutation side-effect counters";
    }
    {
      file = "0086-crucible-genesis-observation-boundary.patch";
      branchSubject = "crucible: admit genesis observation boundary";
      branchCommit = "22ec637a620acd10ef9f1d1839d2254631ad071c";
      branchTree = "5b861bf3ffd247ca7bb330bafcd747a905ad89cb";
      catalogName = "crucible-genesis-observation-boundary";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "the BQL-held prelaunch genesis boundary admits complete all-vCPU architectural observation only at exact raw icount zero";
    }
    {
      file = "0087-crucible-deterministic-rcu-quiescence.patch";
      branchSubject = "crucible: defer host RCU kicks in sim";
      branchCommit = "02896460405fcdbcd9c24034e4cc44b62fd85c6d";
      branchTree = "b5f0556d2153b5caba5db3861b2e1faca5f5b7a2";
      catalogName = "crucible-deterministic-rcu-quiescence";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "sim mode reaches RCU quiescence at its bounded deterministic RR execution boundaries without host-timed translation-block exits";
    }
    {
      file = "0088-crucible-deterministic-host-kick-boundary.patch";
      branchSubject = "crucible: defer generic host kicks in active sim slices";
      branchCommit = "1517b77b12d689694606015153d505d6b4be4cb7";
      branchTree = "f18e3e9b04703161ce004b713446ecbb1d19ed75";
      catalogName = "crucible-deterministic-host-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "during an active bounded sim slice, state-free host latency hints cannot choose a guest boundary, while between-slice, zero-icount startup, admitted terminal pause, stop, unplug, halted, stopped, and interrupt-request kicks retain immediate exits";
    }
    {
      file = "0089-crucible-exact-boundary-vcpu-introspection.patch";
      branchSubject = "crucible: admit vCPU introspection at exact boundaries";
      branchCommit = "e88e6128fb825607404d265d8c661474e1adad97";
      branchTree = "8aa4a0330f3d982bb8f80822dcf678bf32096523";
      catalogName = "crucible-exact-boundary-vcpu-introspection";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact BQL-held main-loop boundaries read every quiescent vCPU register file and the committed RR cursor without a current vCPU, while arbitrary unowned contexts remain rejected";
    }
    {
      file = "0090-crucible-active-tcg-kick-boundary.patch";
      branchSubject = "crucible: defer generic kicks to TCG boundaries";
      branchCommit = "fb3cafb1babc566281f053eced39e2324ada242a";
      branchTree = "394ec0f646445a2295128bc00fd1a757e06487a5";
      catalogName = "crucible-active-tcg-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "state-free sim kicks request exit at the next deterministic translation-block boundary while committed transitions preserve immediate liveness";
    }
    {
      file = "0091-crucible-canonical-rr-genesis-cursor.patch";
      branchSubject = "crucible: expose the canonical RR genesis cursor";
      branchCommit = "8c67bab8b70823609ccc4b0efd4d2879020ae2e3";
      branchTree = "42a8e0b42c3b1b7dfa329aa141764e4605955ce1";
      catalogName = "crucible-canonical-rr-genesis-cursor";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact raw-zero observers read the unique next RR coordinate without mutating scheduler state while every later invalid cursor remains rejected";
    }
    {
      file = "0092-crucible-canonical-terminal-rr-cursor.patch";
      branchSubject = "crucible: canonicalize terminal RR observations";
      branchCommit = "d0c43f81075113b39931891a7d90f2178d8ffa34";
      branchTree = "352b0e300e23895def9d4a529dcfabd93eb613f4";
      catalogName = "crucible-canonical-terminal-rr-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "live observers at a quantum terminal project onto the next scheduler-owned vCPU at position zero without mutating serialized RR state";
    }
    {
      file = "0093-crucible-canonical-register-cursor.patch";
      branchSubject = "crucible: canonicalize after-instruction register cursors";
      branchCommit = "75699f932a8c777b1720ed4b9f917fd3c42b66e8";
      branchTree = "4a30fdcc8d8f5045d1ff8190afcccb327ce60e30";
      catalogName = "crucible-canonical-register-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "after-instruction register evidence advances its callback-local prefix and projects an exact quantum terminal onto the canonical next RR coordinate";
    }
    {
      file = "0094-crucible-retention-virtual-time-origin.patch";
      branchSubject = "crucible: anchor retention to virtual time";
      branchCommit = "b915d69610eef06b55acaa1c7f4ac5e3060be70e";
      branchTree = "31d68b34586b8d941e078ece87d9052490a143bd";
      catalogName = "crucible-retention-virtual-time-origin";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "memory-retention expiry originates in authoritative virtual nanoseconds instead of mixing raw instruction coordinates with clock-biased deadlines";
    }
    {
      file = "0095-crucible-raw-pte-update-identity.patch";
      branchSubject = "crucible: preserve raw PTE update identity";
      branchCommit = "35ca17079191d3a2d17cbdff06321e9018b2973f";
      branchTree = "e1a80c2354683c03d75e54deeb77e84e92fdb22f";
      catalogName = "crucible-raw-pte-update-identity";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "x86 page-table translation consumes corrected transient PTE bytes while accessed/dirty cmpxchg preserves the canonical backing entry and cannot retry forever";
    }
    {
      file = "0096-crucible-physical-page-table-region-fixture.patch";
      branchSubject = "tests/tcg: target page-table regions physically";
      branchCommit = "75b7e9eb9316d35c2e561a76eff4575a5a9aaf32";
      branchTree = "b0d41b84b1e42dfba0c0cf68c00da05d3ea8eb87";
      catalogName = "crucible-physical-page-table-region-fixture";
      class = "F";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-EVIDENCE";
      capability = "live persistent page-table-region tests address descriptor storage by GPA while ordinary guest-memory region tests retain GVA targeting";
    }
    {
      file = "0097-crucible-canonicalize-memory-retry-identity.patch";
      branchSubject = "crucible: canonicalize memory retry identity";
      branchCommit = "bc1ca3959e981085b07d73f4612b60e46c7c3943";
      branchTree = "58f21f64e413e22769dad8bd4decc5eed7bc7d72";
      catalogName = "crucible-canonical-memory-retry-identity";
      class = "D";
      enforces = "DET-1,QFP-MEMA-1,QFP-STATE-2";
      capability = "memory retry keys exclude TB-local instruction ordinals and serialize that compatibility field at canonical zero across fault-driven retranslation";
    }
    {
      file = "0098-crucible-inactive-nested-tsc-guard.patch";
      branchSubject = "crucible: guard inactive nested TSC reads";
      branchCommit = "6fa8435c73198ec75bba0eac1b47d8ba32b3e75a";
      branchTree = "f795ae19b2891ae9925b246019b04e4ab8ee45de";
      catalogName = "crucible-inactive-nested-tsc-guard";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,PATCH-3";
      capability = "inactive guest-clock faults avoid TSC sampling inside SVM entry and exit so nested execution preserves upstream icount accounting";
    }
    {
      file = "0099-crucible-valid-aarch64-abort-fixture.patch";
      branchSubject = "tests/tcg: use valid AArch64 abort syndrome";
      branchCommit = "ad21f093377c03ff90bda6288147a4032018fbeb";
      branchTree = "a27fb06b5f37d12fb56336c7465cf7dd9b01bf51";
      catalogName = "crucible-valid-aarch64-abort-fixture";
      class = "F";
      enforces = "QFP-MEMA-1,FAULT-EVIDENCE,PATCH-3";
      capability = "the live AArch64 poison-exception and retry fixtures submit the data-abort vector and a same-EL syndrome accepted by the production architecture validator";
    }
    {
      file = "0100-crucible-aarch64-memory-exception-vectors.patch";
      branchSubject = "crucible: validate AArch64 memory exception vectors";
      branchCommit = "8c53d72a6e1a3c2a97608f2c501986fbaffba8fd";
      branchTree = "8a7f8eeebd00f79ab0b6740dabd467dd604d3793";
      catalogName = "crucible-aarch64-memory-exception-vectors";
      class = "D";
      enforces = "QFP-MEMA-1,FAULT-EVIDENCE,PATCH-3";
      capability = "AArch64 memory exception admission requires instruction-abort vector 2 for fetches and data-abort vector 3 for non-fetch accesses";
    }
    {
      file = "0101-crucible-canonicalize-snapshot-rr-resume.patch";
      branchSubject = "crucible: canonicalize snapshot RR resume";
      branchCommit = "398ca2bb3f4d535046605d52e5b429defaab86e8";
      branchTree = "2d74fa124525cfb98d05ef356fc3cfe549a1f7af";
      catalogName = "crucible-canonical-snapshot-rr-resume";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "successful sim-mode snapshots arm the same one-shot serialized-owner selection used after load so source continuation preserves the RR owner and intra-turn position";
    }
    {
      file = "0102-crucible-bql-exact-register-capture.patch";
      branchSubject = "crucible: admit BQL exact register capture";
      branchCommit = "6e8938bc9a4e4e229ea9770e3dded50047619647";
      branchTree = "c0c27c6f65dc72c14660651b72c9d8154fa2c752";
      catalogName = "crucible-bql-exact-register-capture";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "BQL-held exact callbacks read quiescent vCPU registers while post-snapshot RR owner reselection is pending, and idle-time completion is explicitly scoped as exact";
    }
    {
      file = "0103-crucible-isolate-checkpoint-control-wake.patch";
      branchSubject = "crucible: isolate checkpoint control wake";
      branchCommit = "17a25e2de1c880e67ca6fde96c4d5302b132bee7";
      branchTree = "74e995da573d6e439186bf04fa9738944658ba5c";
      catalogName = "crucible-isolate-checkpoint-control-wake";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,PATCH-20";
      capability = "a pending exact VM-stop handoff wakes QEMU's main loop without resuming parked block coroutines or admitting post-pause completions";
    }
    {
      file = "0104-crucible-preserve-checkpoint-block-durability.patch";
      branchSubject = "crucible: preserve checkpoint block durability";
      branchCommit = "86693f22283090cbd4e288aed2734a4906261686";
      branchTree = "5ea17be518945fe35cac0131b51f792582fc0003";
      catalogName = "crucible-preserve-checkpoint-block-durability";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QFP-BLOCK-3";
      capability = "synthetic QEMU stop-time flushes preserve the checkpointed Apache durability continuation and cannot create post-quiescence Crucible block requests";
    }
    {
      file = "0105-crucible-selector-control-plane-fixtures.patch";
      branchSubject = "crucible: isolate selector control-plane fixtures";
      branchCommit = "0145ecb07a02d7daa8465e36c294afb073553fc8";
      branchTree = "8f18f9adaf46a8a41574d8884419cb10607abcb1";
      catalogName = "crucible-selector-control-plane-fixtures";
      class = "F";
      enforces = "FAULT-ORDER,PATCH-3,QFP-INST-3";
      capability = "live instruction selector overlap and exclusivity fixtures use unreachable occurrences so admission checks remain isolated from data-plane fault delivery";
    }
    {
      file = "0106-crucible-defer-active-slice-host-wakes.patch";
      branchSubject = "crucible: defer active-slice host wake requests";
      branchCommit = "a8d1b8176697c52d469d3a9d89759bde63d04262";
      branchTree = "a07968add00322b9f012fba1049e4f62fa0a1461";
      catalogName = "crucible-defer-active-slice-host-wakes";
      class = "D";
      enforces = "DET-1,QFP-KICK-3,QEMU-43";
      capability = "an atomic idle-active-pending handshake admits multi-vCPU state-free wakes only before TCG starts and never lets them select a translation-block endpoint, while single-vCPU soft exits and explicit terminal and committed lifecycle wakes remain live";
    }
    {
      file = "0107-crucible-anchor-rr-cursor-genesis.patch";
      branchSubject = "crucible: anchor RR cursor at guest genesis";
      branchCommit = "3cd18ce07997fc1fc09335b65ee657c6bf29bbf6";
      branchTree = "5044ba844266ad9ffa632d9d2cb26c0f4ce7c45e";
      catalogName = "crucible-anchor-rr-cursor-genesis";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "fresh sim-mode execution establishes vCPU 0 position 0 before the first budget, and the serialized owner remains authoritative across partial turns and VMState restore";
    }
    {
      file = "0108-crucible-deterministic-network-kick.patch";
      branchSubject = "crucible: preserve deterministic network continuation";
      branchCommit = "a67d7272625822752049fcd6ec3377213966133b";
      branchTree = "fcbbecee5221c512aa0951bb302375830d91acf8";
      catalogName = "crucible-deterministic-network-kick";
      class = "D";
      enforces = "DET-1,PLUG-23,PLUG-24,QEMU-43";
      capability = "sim-mode virtio-net queue kicks and serialized tx_waiting resumes drain every deferred TX bottom half synchronously, supply one committed raw transmit icount, preserve the virtqueue notification cursor in an optional sim VMState subsection, symmetrically flush pre-checkpoint translation history, and use bounded cache-independent TB shapes without direct chains on both continuations so VMState restore preserves packet and fault-decision continuation";
    }
    {
      file = "0109-crucible-control-boundary-node-faults.patch";
      branchSubject = "crucible: dispatch exact control-boundary node faults";
      branchCommit = "b530ba5eff47bcad3a66218be5f5a44673beaeb2";
      branchTree = "f4f000af585e114869909d6cd69ea924536af5df";
      catalogName = "crucible-control-boundary-node-faults";
      class = "F";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "a node-boundary command submitted while QEMU is halted at an exact drained control wake is dispatched at that same raw icount, so PREPARE and APPLY complete without requiring guest progress; terminal authorization hashes zero the raw evidence coordinate before the plugin maps it into scheduler-logical space";
    }
    {
      file = "0110-crucible-release-halted-rr-turn.patch";
      branchSubject = "crucible: release halted partial RR turns";
      branchCommit = "6951400c17fda333625f64578fbc658fafd33c15";
      branchTree = "7beb6b8e8155adcd1ca9026632f2f7d540dd3ac9";
      catalogName = "crucible-release-halted-rr-turn";
      class = "D";
      enforces = "DET-1,PLUG-24,QEMU-43";
      capability = "a vCPU that executes HLT before exhausting its serialized RR turn leaves the execution loop when no alternative vCPU is runnable; a helper-marked multi-vCPU guest PAUSE fences control-boundary acknowledgement until it commits a cursor-zero early handoff immediately after icount accounting and before callbacks or host-work exits, so a released spin lock cannot be reacquired before a waiting peer runs; and that exact completed-turn handoff admits safe register capture while other owner mismatches fail closed";
    }
    {
      file = "0111-crucible-accelerator-service-schema.patch";
      branchSubject = "crucible: correct accelerator service schema";
      branchCommit = "5f559022c45d354a2b491be6c941206f298cbe67";
      branchTree = "d1622c093b62adf2fdb08d06beb419c2e9cdce13";
      catalogName = "crucible-accelerator-service-schema";
      class = "F";
      enforces = "QFP-ACCEL-SERVICE,FAULT-ORDER";
      capability = "typed accelerator service commands admit the ratio-valued capacity field used by the versioned node-fault payload before atomically installing compute, memory-rate, thermal, and power service policy";
    }
    {
      file = "0112-crucible-compile-affected-clock-sources.patch";
      branchSubject = "crucible: compile only affected clock sources";
      branchCommit = "8f5e59b97d414b49f27b520606b878bc73989e28";
      branchTree = "f12dc20b5b7fb1cbf250faa5e4ea7409d3e86322";
      catalogName = "crucible-compile-affected-clock-sources";
      class = "F";
      enforces = "QFP-CLOCK-SOURCE,FAULT-ORDER";
      capability = "a committed clock rule recompiles and rearms only sources selected by that exact rule, so an unrelated source that cannot project raw time at the stopped boundary cannot invalidate the authenticated transition";
    }
    {
      file = "0113-crucible-restore-accelerator-rule-indexes.patch";
      branchSubject = "crucible: restore accelerator rule indexes";
      branchCommit = "8761a5f3176c31b99799c209ddaef6ddd5303e67";
      branchTree = "58e3f85bdc06be733e76433308905503257fe71e";
      catalogName = "crucible-restore-accelerator-rule-indexes";
      class = "F";
      enforces = "QFP-ACCEL-SERVICE,FAULT-RESTORE";
      capability = "fresh-process VMState restore rebuilds each accelerator lifecycle, result, memory, and service rule index from the authenticated staged node-rule ledger before commit, preserving persistent accelerator behavior without duplicating rule ownership";
    }
    {
      file = "0114-crucible-authenticate-fault-result-payloads.patch";
      branchSubject = "crucible: authenticate every fault result payload";
      branchCommit = "660c7dc151df2c3029f909c66f315ac28d7842d5";
      branchTree = "c1774a2f59b36c44d7c49bfdcd0296af2ae6f58c";
      catalogName = "crucible-authenticate-fault-result-payloads";
      class = "F";
      enforces = "QFP-RESULT,FAULT-ORDER";
      capability = "every queued fault result authenticates the exact payload retained beside it, including prepare-time rejection evidence, so the host can classify a typed rejection without losing transaction ownership";
    }
    {
      file = "0115-crucible-clock-impulse-read-error-policies.patch";
      branchSubject = "crucible: honor clock impulse and read-error policies";
      branchCommit = "1cd4986eef4655488f2e4fece775d0b9a556a7d3";
      branchTree = "df3dabd962e88a0b2b44561489c2b15c0da2e422";
      catalogName = "crucible-clock-impulse-read-error-policies";
      class = "F";
      enforces = "QFP-CLOCK-TRANSFORM,QFP-CLOCK-SOURCE,FAULT-ORDER";
      capability = "impulse clock transforms retain their effective monotonicity and overdue-timer policies in versioned clock VMState, while an x86 TSC read-error transition raises a deterministic guest #GP and internal projections retain the last source value";
    }
    {
      file = "0116-crucible-qemu-11-api-port.patch";
      branchSubject = "crucible: port integrations to QEMU 11 APIs";
      branchCommit = "7273c8ae7bfa040cda1d234fba811767e484df53";
      branchTree = "6eda9f6128a9e0da59db559717be6c466516c992";
      catalogName = "crucible-qemu-11-api-port";
      class = "D";
      enforces = "DET-1,QEMU-43";
      capability = "Crucible accelerator, fault, migration, timer, and plugin integrations use QEMU 11's public headers and current callback, atomic, TCG, and VMState APIs";
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
