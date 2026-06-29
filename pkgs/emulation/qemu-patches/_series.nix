# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "7303bd3457f99949472161dc4230c2cd49f4040c023b128c4e802dd4d85db96c";
  patchBranchBaseCommit = "36ac68e25469b93cc91f6350b998b486ac41669d";
  patchBranchBaseTree = "0cd2d9a4fc104d62436a431eddc2dac955068986";
  patchBranchHeadCommit = "7139b855b35536eb5a975c1e0fe23b1d55637598";
  deterministicAuthorName = "Crucible Patch Regenerator";
  deterministicAuthorEmail = "crucible@aos.invalid";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";
  patches = [
    {
      file = "0001-crucible-sim-accel.patch";
      branchCommit = "da1c51da2955cc9b3a5ed9f544629b9bfe3ad235";
      branchTree = "4f338ad519a5934bc4a842f1ca3a34e7409130fc";
      catalogName = "crucible-sim-accel";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "-accel sim deterministic TCG accelerator";
    }
    {
      file = "0002-crucible-rr-fingerprint-helpers.patch";
      branchCommit = "51629bee51f38f67e1e5c8d7167c10666d617fe0";
      branchTree = "59337aa46638df8fd6cb251c187ca0a277388b7a";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "325d017fa20b32f68c8c1b074ccf668283bfdce0";
      branchTree = "db613cfc1d85e1632963cb18bc1cd54fece99eb3";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "e1e4d50cba81b88a8d0f15bd0f6b269ef0196f07";
      branchTree = "9940be0dd025f72bd986e0e6ca6f2bf9b8ae9d81";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "5c556f523c8c5218cb4f2d5dc297feb48b93b8d1";
      branchTree = "e4a3036876996df30cadcb02441685cc3a170fd9";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "15d832bf06cacd42845f780ef5523aaabd733ed2";
      branchTree = "0f870303e3d6602fdfaef0b65c2e3599dbf88bb6";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "c898067b7ebcd35a0865e7e547d2acd5e4652a87";
      branchTree = "2c6844dda592b6df374194b88ec22aa37596d798";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "c2e2994805335f76d910d5cfc7f2d816918fc3f3";
      branchTree = "2dcd22fcbe76fed7424df086b6350ffae715d2f0";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "c394057d44413f55b487a5db7ea41432f61be35a";
      branchTree = "c820071ec63d89235b0e12dfb189b104c96cbb66";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "4a3e8c1ef471a3b217e559bd18b42b1e8b7b214d";
      branchTree = "4e01795374ab3ce62e669e4597d8d98a3525016d";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "plugin-owned synchronous virtual-time advance and BH/main-loop drains";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "1a641a66902eaf882dfe660e707b2efe5fbfe681";
      branchTree = "73dc2183ff99d7bc2b8646f61c8e2717d98ec5f3";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "bfabf8c9439d558aa900d815f037358efd489942";
      branchTree = "5b189e7909bb3cef28285db6cc4356c8bcbc3101";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "780d8e71d5d34d4821730aed42a52119109857cd";
      branchTree = "e4f39636cc7ae1fd540b41955ba02738dd743a01";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "plugin wake fd registration and blocking main-loop wait";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "a8e1066a413ebd4e7742805b4df3c266677e960e";
      branchTree = "66ed0e1291b04e3db9763408402e9c2c744e51a1";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "bd694f92c4110851397cd40c280814609da137d7";
      branchTree = "be9d9a0613760f22056adbcd7e284b6a4bad9560";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,E19";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "84b631979f8e502d9275f2628232fb06c7b1382a";
      branchTree = "64f07c75d937bdf4dbc46d98f1829c3d687923f5";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "d24944bf3a99c5e874472605a07a8717a2faeddd";
      branchTree = "682ae5807e749ffc4f520cf0d61fa39dab2ef439";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "791cca9c5a616d646108c7fd865c40977d474194";
      branchTree = "666003733d02f0a205866197be8d1eb2acd97843";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "f264afd2f8497b2403184273f5ab502eeb720f1f";
      branchTree = "3da901f1bff5b25f97d6fc0b6e7ac4a0e42cd9d1";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "42218fce8d24f780fb90bf6d41c61d2a2edac60f";
      branchTree = "435f24602798297cd896446762a9eb593493f2c8";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "9acd664ced630c54a2b069d567ea3fca551f6a97";
      branchTree = "79865f678a90151930eae2e1dfff188489ad4fda";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "fbfaa0b19da55669c491ce6305d474036c8ead5b";
      branchTree = "fae4e4159d29baee86dfa3a570a5b4d3b7d34b77";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "1d55dfe58c4ac35f24ce083d5450462a092083ea";
      branchTree = "66a2cd83af7948d267c28e4c483fe6e53810b9fb";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "4180357955428dfe98602dcf1ac5de8df1218139";
      branchTree = "4ebb5bfada727fad773e3fc25616cec9fd6301e6";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "sim-mode time-control-guarded shmem drain and one-shot re-poll before coroutine yield";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "a4e5e42a09177de2e1450a01c28e48860d1e7e81";
      branchTree = "f3cea7be470e4ab5bfbd9eec89c879ec5ddaaaf7";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "174da7d9c45b9e7822b5ba26a3f6a60ffea0a32a";
      branchTree = "67af4f44f451ba0f1abea8c11d5661e33982d84a";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "b5ca497e6ce46d85328bb1dfac989cd8fef8463c";
      branchTree = "602b1cc28070164551e41837dd2bb6ffcec7915a";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "fbf8e4ce171ad2bc47c49a13b269c5f2b712ec1e";
      branchTree = "418e9d3d368372405e00aa077c277109e2b21e74";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "400a43550486eabb4299a6a33414c721207e1b9b";
      branchTree = "48045dd5a23a745c5e64f4d614a0559b256a2fc9";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "7139b855b35536eb5a975c1e0fe23b1d55637598";
      branchTree = "2494d9ccf97f83a6bef0778f16b2f2f33ae282df";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
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
    ;
  patchFiles = builtins.map (patch: patch.file) patches;
}
