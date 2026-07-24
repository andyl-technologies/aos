# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "eaf62153b1de4837d003a552a984f848ed7b7486cc35d30304945ff383196040";
  patchBranchBaseCommit = "36ac68e25469b93cc91f6350b998b486ac41669d";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "08389eff3f11ceb3a5082150eddcb44df36af911";
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
      branchCommit = "ae4c5e2e063c7fd6157bd831e0df83dffeb3bcd1";
      branchTree = "cbf71b413c512947e07aada223138ea3bb5e05b6";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "2dcf491cb48cbd4b387ab4b5f9255bd58dcc0b5a";
      branchTree = "8e9855420d222793f05534b4d20566a645b36328";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "58da0d4ae6ef056ede9e0127ee4b87164f768a79";
      branchTree = "089b732dc41f16edf3e45b6c8e78756efb57baf3";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "9a8d7782b158807c6ae92292eed68a79626d1f40";
      branchTree = "b1b8e19f9cda5f8f5d4fa6be2748e36dacbbb430";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "81ea3b39520bffb97d34e2a717565ca8ba21efe7";
      branchTree = "2eaad98fab8a262cc8f29c9641b23c9341927128";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "d5b59a08e61d544cc7fc7468e646569203641cb0";
      branchTree = "feb3725b65650c66a87f0ed3e0dc6cf24ce5aea3";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "49379d83ca97e648d39ccb835b92f1e7df52bda1";
      branchTree = "2eff81f45f912b04858afdbc24fb76990f1ba790";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "c25a34b0d908ac9d66b2c074b6920f6886e1fa4a";
      branchTree = "26f0a4793a3c71275a253a9b0775bf49d3fcd85e";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "a974a643763f05e0fac84cbbc64536e729b7de60";
      branchTree = "12d82fd65459d99f2d1e3ecb46e5fc962508d064";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "ef939f28d4ed0cfb686271d9a6016bf3074130c2";
      branchTree = "ec548f482e66f3a29063721395b956b017308513";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "2bdd0d0e6b3cf3a03184572e4041fd47d246b885";
      branchTree = "5164a6e36d6697ada96e1445ee39cc5affa5fea5";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "bc7e4a0dad5adeb3a27b47f16d054dfb4195dbda";
      branchTree = "cf3d4193dbb87aee506a759d7bc93ed076fca538";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "9de508059e8e280c75a9e056d2c8a48f02063335";
      branchTree = "1dc8d3e48d5ebd940255907a9f2fe5f60d768f7f";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "70af8733fb3a80aaaa50aaaa8640d510f4d2be62";
      branchTree = "09b7e495b788f993297d0230e741b1832c165041";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "22282cc8c7438169ec099b0accf76da5612d45f4";
      branchTree = "d196ce171aba620c16d0714cfbdcc959773994a2";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "026f412c9afcfa3bcb9d7f8e947f933edd562a79";
      branchTree = "d4264c242951ecc85fdad32d68060462581123dc";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "f8f929f5681d908313a47fb3b611104b1a9a1145";
      branchTree = "93329f4e6416c2a662afbfc539e06dcc2cec8841";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "7afc478c10a676b8799d147c61af2a83bcb36082";
      branchTree = "e354369499662821c9bf2e980f9d9a7def980bf0";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "49ae6d844a87468cc03132b5c2973b1aa19aeb21";
      branchTree = "15d45915237f35b3a126c8621ea02839856af537";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "a9692aef2770541dcb4295f4937882c0bb5bc4ef";
      branchTree = "b75158ea7d9d380403e26fa75fe243630487ab9f";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "0a806a76a682b5b83d9f5679cdc2cfb225351523";
      branchTree = "49031b7f7c2a06a86d9a3ed3afbd9d876df5f9e5";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "972ac3678bfcf805333926af47a5819fd5dc01a5";
      branchTree = "f498d4a9c7bcb5f52d25fff43e044e1e09628e59";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "955f0ec718b5bec0b3d6cdadfba7e007e6da181c";
      branchTree = "c92fb96931f33bd5fda586e412e786663cd0dd53";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "ba0edce7dcdc42c04dd787dbd55108f891edcc10";
      branchTree = "9187c4712a682274c773a13596f7bfc3cb469fc5";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "512a646bc3f6c957f555384d83525d2d3e7db825";
      branchTree = "8e7b88e83498c38467eda0c90e4f29207b651755";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "050d3daebca946e74f14c73dcec277b79f3bf0e4";
      branchTree = "a620c292ef86582fee147d67286626cfcf97593b";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "5d1ad5f70b2620f38a2d255f863cf83c48c119e8";
      branchTree = "8f8434c04f3a28aaec1c098674fa847ab44c9d5f";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "fa2a25bc4a1ba631ae60a68f158095ed9fe8c5a8";
      branchTree = "e5fcffc28a994e68e62909f604def8a90bc7fe19";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "004d96b0d3e172a76ab13d0217dfa9056c8e5e9c";
      branchTree = "91490ddc325c6966f76e02572710be6fe2e7c78b";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "c1c828e041cc3c0288889fa2082611446bce30f6";
      branchTree = "4510ba15a4bce6522d3411f946c8ca7541f94246";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "8ea215eb344381f4a99ae4b56b39589bd1574a20";
      branchTree = "e5323d92fae064e92b0cd17c70675e36821a1ac2";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "c183c890e8c7ce5dbc3528946c887d137ff3efb6";
      branchTree = "ee4e042feafe52148ecd4263ce07b7df364acda3";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "7e1a23b3350eaf97d642bbc254038bb8738d5958";
      branchTree = "9ed1168b46579e950cc213ab47afa5215ec14bca";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "3764ac0450991711627fc8bf7cb1396f3d167677";
      branchTree = "3b354ae4005898f8f833525f86cc414d96b56739";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "afe0fe0be52a54b9dfb2d5f2edfd8bf809260a41";
      branchTree = "96b725ecdbb3436eda69c12aaaaf3c110b9bfd2e";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "3b00b68888ab9bb2e2c0ecbbcba32b19bc4bd520";
      branchTree = "2a9115d1b66638024931dfdf0300e626efab747f";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "3ea2f4afd7def3f7216af4f350eba59651331d69";
      branchTree = "69f8f0ac9801e3644eb22b776f1ff328f07983ef";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "08389eff3f11ceb3a5082150eddcb44df36af911";
      branchTree = "6f0cc08c1f17767f3b4382d3827f42a2123b2fda";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
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
