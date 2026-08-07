# Authoritative QEMU patch-series manifest. The underscore keeps package
# discovery from treating this data file as a package derivation.
let
  qemuVersion = "10.0.0";
  qemuSourceHash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
  qemuSourceUrl = "https://download.qemu.org/qemu-${qemuVersion}.tar.xz";
  patchBranchRef = "crucible/qemu-${qemuVersion}";
  patchBranchModel = "tracked-quilt-stack-linearized-into-git-commits";
  patchBranchBundle = ./crucible-qemu-10.0.0.bundle;
  patchBranchBundleSha256 = "9a7f0816c8ae533c743e12cac5c7ccf0f69fd588517bc14088c722501cd9ef75";
  patchBranchBaseCommit = "44442f88bbe1c899d35ee2f9e50e5a2eb8ef72cf";
  patchBranchBaseTree = "388a223a0b6be3e939b0c0dcda9c5ab50ed4b77f";
  patchBranchHeadCommit = "ee93a577e78766c893e72e20fdcf72565cf98b0b";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";
  patches = [
    {
      file = "0001-crucible-sim-accel.patch";
      branchCommit = "78fae741ee7b51ac59ee573a2f808517be960b63";
      branchTree = "5c86d3f1a93bce096514ca76a1601785a49fa162";
      catalogName = "crucible-sim-accel";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "-accel sim deterministic TCG accelerator";
    }
    {
      file = "0002-crucible-rr-fingerprint-helpers.patch";
      branchCommit = "30ea7f5460b3f21f9ebc6b7bcf057bc496806f99";
      branchTree = "31ac37d570b43dbace35ad1c7fb9a565e33e567f";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      branchCommit = "35611ac08c04a69c64f02aadddbb0cad58a3a192";
      branchTree = "4608693b4b338d6a582edd49e1388e4bb9af838c";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      branchCommit = "ac164561d06df62fd1955eea992640939f56a106";
      branchTree = "b6b4ffcb8c2c81281f5f09e6328c624c9ec6e190";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      branchCommit = "944d2f5d0be0709c88933bd324f270f3c153ff83";
      branchTree = "3d8d89b7c9f17d41a4872b0eefea5a169fcaf77c";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      branchCommit = "a7ea0b936f8620876277209faac9fe824e2e1a25";
      branchTree = "0d18a6f17e8f54daabc1447c70c431f25d043c94";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      branchCommit = "f13b937924ed287df835fc21c1d9ebbd94d81928";
      branchTree = "5633dcbcdef12d2cfa106fc0cd41f6a815b09f64";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      branchCommit = "5c197dafbb65f1e1e4b71477577a92adb086a315";
      branchTree = "85e094d77563b3a33b0671225367bec05663b93c";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      branchCommit = "ebaa62c1dc323f4a98b8b7b3f6ccf4e9b64eba9e";
      branchTree = "9fd8d1f0a26e2be9dde40a08e2b6cb94e5c62691";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      branchCommit = "0586274d6314ff7e64f526659551cb3e47778cdd";
      branchTree = "1c044475258f0d9c2eb116558312ecaf3faf76e2";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      branchCommit = "1d28d816c2a2fea7c9c0703b37e7135779f5307c";
      branchTree = "d6caff79eed9249200c072d55386227070366d97";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      branchCommit = "1477fc0993a70c185e22bf80b84a290808f0eb86";
      branchTree = "20f93da29524669d65b2268e135a3c8a79abb231";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      branchCommit = "85600ee41f223e4e69cb5d78d15dfbe1151b7de4";
      branchTree = "2dc7db14faa7a064296ec0cc2cd9e7e2471d6068";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      branchCommit = "2e758d9b11d89f1283c9f6acb04913bb941daa70";
      branchTree = "287a6cf6ba74da64d45a9dbffea46d10e51c79ac";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      branchCommit = "40b15279b4f37e2a0c6bd738e9af33f0c48a55a6";
      branchTree = "7d58afb5ca879b1f4cda39da9c6debfd42b7eb6b";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,DET-16,E19,SHM-13";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      branchCommit = "133fa2a71e7e61dd3445dd3e76bda2b0d7d699d3";
      branchTree = "1d495e4fbdab33ca89c40f58d1891737bc892b93";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,DET-16,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      branchCommit = "f3c27d71d992613ea90eb7c85f336bd8c60c384f";
      branchTree = "c440c47dcabb2c6aafe5c44af978fb80830d1c2d";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,DET-16,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      branchCommit = "c0b0e8f4acb7f7d0f3cae5c005c146ac68ccf00c";
      branchTree = "8072ba7966445b4c5723e2c97e745fcf3df2c528";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      branchCommit = "2797ce69498228a9896bbe76468d0ec7d01a7e80";
      branchTree = "19aca0f122612b13bdcd93c1dfda2fbd9f282c68";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,DET-16,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      branchCommit = "f2078f357c49aa4d49fc5678dd9a08805eec3a75";
      branchTree = "89a162f56d583266178e7b8e95ff3c9dad2a0086";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,DET-18,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      branchCommit = "9a31c3856c05d8bc63d7db4229b088d91dfe712c";
      branchTree = "7cfafe73ea0102a5727d0cd7de401dbe2fa8ac1d";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      branchCommit = "55def978f02ebc424757e1ed4462d7d9deb55119";
      branchTree = "74a86c340269e8a7223269b15b1caa7b6a608259";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      branchCommit = "456bf985f3bb36238c1b1b1bcc6957fbd869978c";
      branchTree = "ba820148a08a34490e79221a3558de78bf1dc095";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      branchCommit = "cde20e8949cd425ec0d2fda3be7e04db1eb20f7f";
      branchTree = "96c73b4800ba58cde3df260627fdcd277e961a7d";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      branchCommit = "d932911a0b36198c2d689438da41cdd4f19cd2bb";
      branchTree = "c8d826c955115963fb0d5db5f079c48afb8d2fe6";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      branchCommit = "fa340a90c46b377457438030ce09f1f88c901686";
      branchTree = "eb45fb6ffd989f1bb788e3d650db7b136119782b";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      branchCommit = "a3f66fd2f71960eb3300b343c9a3635ddc5f8ef1";
      branchTree = "3bade39ecb3b915f207cc43daaabcf417d646891";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      branchCommit = "86a142bb3b43c7f4232b819a2c8504ec1ca410ec";
      branchTree = "1e03b9da28f330e08c4011b25cd43d83452d8f51";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      branchCommit = "b63bb1b261abbc08ff2e73f541bad8b5b2427c42";
      branchTree = "bd5a6d7df58b0e23f54f2ba2b45505925fd1a595";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      branchCommit = "8139522811a7da3945eec324017d8fd981da0639";
      branchTree = "6a42b344589a3330879b382f08ec56a74753a863";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      branchCommit = "19e2751549649ac092d2fd0676d35b8da218194a";
      branchTree = "09c7eb08be5dd27083952d16a88296929a02798c";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      branchCommit = "f7aa3aa5a10cfb79cc759139da27e755fdffd33b";
      branchTree = "31fcbab7b4eea2f47f5aeafad79101db904cde1f";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      branchCommit = "e98611227395658bed93268f2d6c748396a244f7";
      branchTree = "66f6ae7049f61ad993ceae8eb0b6bae881245116";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      branchCommit = "76bcc2558f95858a2cbe4c48bfd7735d957f631e";
      branchTree = "8b47a72bc4f8fa5ca3c1bac575f795d8fd6da845";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      branchCommit = "014721049a2c21e802ec84b84fc79d043adcbe90";
      branchTree = "c98d58e03d0d7d37f15ca558916d23d4b3cb77cc";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      branchCommit = "6b35e493b283680130de5d5546767fc7c93c555a";
      branchTree = "f70ab80d8489a1a343c27cb016b7b257de13f87a";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      branchCommit = "8f2403b613bdafd630f4e61f7525ccbbe65cba51";
      branchTree = "ea8466e8ee7faeb749f0c8ae88b650a6383e7128";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      branchCommit = "fc19dcd561337eb0bd3b135016316d8fd09ee7a1";
      branchTree = "fd854c7847d6c5100402c9a5d080e327bac181d0";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      branchCommit = "a0523c5377fd590fadb665c45b35192185045d76";
      branchTree = "5dc3e40469ce88cb6ecf0dfce675e1ddd20a390d";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      branchCommit = "eb45dda8f0dd3e4a49e34f33ce97a6ea85a593ae";
      branchTree = "2b059c91016fe8d1497afda39971fbcd7da01d12";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      branchCommit = "cd02bddcd204d82afc2bd0a944232abb24083939";
      branchTree = "78125cf9a7d3a6157da82c1939d66effd70c705f";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-34,PLUG-51,GHC-32,GHC-37";
      capability = "callback-scoped guest virtual-memory writes for synchronous white-box doorbell replies";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      branchCommit = "a26f20528260c4f606345931e0766201508e9950";
      branchTree = "6634fb522e4c03c62b7c74189eda82a896a7584c";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      branchCommit = "201500ed510d76bc4fefe5febce6d9ed2dbc25d2";
      branchTree = "139fceb8fbd2ef4aada24e616f1f86dd5bb3675b";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      branchCommit = "841528c3b1810afe3346a0767e0ffe30c3bc40b0";
      branchTree = "1c6a4f316cf6fe690c31af8c5a084c9553d0cdc9";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      branchCommit = "fd9d7711baaafc9f228c8461a8400b42fd72b381";
      branchTree = "986b83e49eb4e97a98085026b956b97330f60309";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      branchCommit = "6e43d87aa3cf87ae838601edee7bbbd3f7bd6293";
      branchTree = "a4da2b8e76a653700222764b15b5881db5d6481b";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      branchCommit = "9c3b251cec99e4340328a1e1314c3c9d43a07fbb";
      branchTree = "877fa4897456509ca9e54f3a96e410d8e073a7be";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,FAULT-ORDER";
      capability = "versioned fault command registry, bounded result queue, and plugin ABI";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      branchCommit = "db100b8eec2fbf42b12954969baf3153f1668ea0";
      branchTree = "1f0d33b7a2d367870ae9bb65326c55bcc47b6813";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement and same-boundary prepare/commit completion";
    }
    {
      file = "0049-crucible-memory-boundary-mutate.patch";
      branchSubject = "crucible: atomically mutate guest memory batches";
      branchCommit = "527e82fe2ee5ac24d50339eaf4cf5c77f8f1805d";
      branchTree = "7eae01786eba97e67296f9f20a98b2948b31c25a";
      catalogName = "crucible-memory-boundary-mutate";
      class = "F";
      enforces = "QFP-MEM-1,QFP-MEM-2,FAULT-ORDER";
      capability = "atomic ordered GPA/GVA mutation batches with translation, RAM-map, dirty-page, and TB evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      branchCommit = "a436a1f6a9caff713a3a3dabf2f52b3dbaca8df4";
      branchTree = "3abb7c9f9175b0d176bbf953f9d25b8a6fb57b4e";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      branchCommit = "3f724c59e77e89202e35b544b9d58f11fbb70dd8";
      branchTree = "9c632975b33c0ab91a9371346bea77f253806b7d";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
    {
      file = "0062-crucible-block-transport-reset.patch";
      branchSubject = "crucible: add transactional block transport reset";
      branchCommit = "ee93a577e78766c893e72e20fdcf72565cf98b0b";
      branchTree = "8d939631d502601e0a6172facb68b654cd486fec";
      catalogName = "crucible-block-transport-reset";
      class = "F";
      enforces = "STOR-RESET,STOR-RESULT,DET-16,PATCH-26";
      capability = "transactional epoch-scoped block reset, recovery admission, retry dispositions, and declared topology re-enumeration";
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
