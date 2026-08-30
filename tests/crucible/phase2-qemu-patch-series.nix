{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPatchSeries",
  taskIds ? ["T-PATCH-1" "T-PATCH-20"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  packagingSpec = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  decisionRegister = builtins.readFile ../../docs/rfcs/0010-crucible/31-decision-register.md;
  pluginFailLoudCheck = builtins.readFile ./phase2-plugin-fail-loud.nix;
  qemuPluginFailLoud = import ./phase2-plugin-fail-loud.nix {inherit pkgs lib;};

  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));

  carriedPatches = [
    {
      file = "0001-crucible-sim-accel.patch";
      catalogName = "crucible-sim-accel";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "-accel sim deterministic TCG accelerator";
    }
    {
      file = "0002-crucible-rr-fingerprint-helpers.patch";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX direct injection with canonical shared-memory backpressure";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "callback-safe queued virtual-time advance with ordered main-loop completion";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "live single-threaded RR proof, plugin wake fd drain, and clean or fail-loud shutdown request";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,E19";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
    {
      file = "0020-crucible-net-tx-callback.patch";
      catalogName = "crucible-net-tx-callback";
      class = "F";
      enforces = "PATCH-31,E18,SHM-17";
      capability = "guest network TX callback interception with upstream fallback";
    }
    {
      file = "0021-crucible-sim-loop-fix.patch";
      catalogName = "crucible-sim-loop-fix";
      class = "D";
      enforces = "PATCH-34,DET-1,NG-1";
      capability = "sim-mode single-vCPU loop and exit-request bookkeeping";
    }
    {
      file = "0022-crucible-sim-first-exit.patch";
      catalogName = "crucible-sim-first-exit";
      class = "D";
      enforces = "PATCH-34,DET-1,INV-10";
      capability = "sim-mode first-exit phase normalization";
    }
    {
      file = "0023-crucible-sim-skip-second-events.patch";
      catalogName = "crucible-sim-skip-second-events";
      class = "D";
      enforces = "PATCH-34,DET-1";
      capability = "sim-mode redundant post-wait events pass suppression";
    }
    {
      file = "0024-crucible-sim-poll-immediate.patch";
      catalogName = "crucible-sim-poll-immediate";
      class = "D";
      enforces = "PATCH-34,DET-13,E19";
      capability = "wake-generation-safe event-driven shmem completion through a coroutine queue";
    }
    {
      file = "0025-crucible-sim-idle-callbacks.patch";
      catalogName = "crucible-sim-idle-callbacks";
      class = "D";
      enforces = "PATCH-34,TIME-24,INV-8";
      capability = "sim-mode vCPU idle and resume callback boundaries";
    }
    {
      file = "0026-crucible-sim-shmem-dispatch.patch";
      catalogName = "crucible-sim-shmem-dispatch";
      class = "F";
      enforces = "PATCH-34,SHM-1";
      capability = "sim-mode shmem callback bridge for current-icount publish, max-advance reads, and TCG budget clamp";
    }
    {
      file = "0027-crucible-sim-batch-tcg-exec.patch";
      catalogName = "crucible-sim-batch-tcg-exec";
      class = "F";
      enforces = "PATCH-35,DET-1,INV-10,PERF";
      capability = "sim-mode fixed-count TCG exec batching with timer refresh and shmem ceiling discipline";
    }
    {
      file = "0028-crucible-det-ipi.patch";
      catalogName = "crucible-det-ipi";
      class = "D";
      enforces = "PATCH-45,DET-1,INV-7";
      capability = "sim-mode inter-vCPU IPI/SIPI/INIT delivery queued to deterministic RR handoff";
    }
    {
      file = "0029-crucible-vcpu-introspect.patch";
      catalogName = "crucible-vcpu-introspect";
      class = "F";
      enforces = "PATCH-46,DET-29,INV-10";
      capability = "formal per-vCPU register-file and RR cursor plugin exports";
    }
    {
      file = "0030-crucible-preemption-inject.patch";
      catalogName = "crucible-preemption-inject";
      class = "D";
      enforces = "PATCH-47,DET-1,PLUG-50";
      capability = "sim-mode commanded vCPU-switch and interrupt preemption injection";
    }
    {
      file = "0031-crucible-det-rng-delivery.patch";
      catalogName = "crucible-det-rng-delivery";
      class = "D";
      enforces = "DET-1,E7,E9";
      capability = "sim-mode deterministic synchronous virtio-rng entropy completion at request icount";
    }
    {
      file = "0032-crucible-det-virtio-ioeventfd.patch";
      catalogName = "crucible-det-virtio-ioeventfd";
      class = "D";
      enforces = "DET-1,E7";
      capability = "sim-mode synchronous virtio-rng vq-kick dispatch under icount (ioeventfd disabled for rng)";
    }
    {
      file = "0033-crucible-sim-observer.patch";
      catalogName = "crucible-sim-observer";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "observation-only post-execution sim-boundary callback alongside the scheduler-owned dispatch";
    }
    {
      file = "0034-crucible-safe-fingerprint-boundary.patch";
      catalogName = "crucible-safe-fingerprint-boundary";
      class = "F";
      enforces = "DET-29,PLUG-35";
      capability = "exact observer budget clamp and BQL-held fingerprint capture boundary";
    }
    {
      file = "0035-crucible-process-argv-attestation.patch";
      catalogName = "crucible-process-argv-attestation";
      class = "F";
      enforces = "DET-31,QEMU-34";
      capability = "process-entry raw Unix argc/argv v2 SHA-256 self-attestation exposed to observation plugins";
    }
    {
      file = "0036-crucible-raw-state-export.patch";
      catalogName = "crucible-raw-state-export";
      class = "F";
      enforces = "DET-29,PLUG-47";
      capability = "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot";
    }
    {
      file = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      catalogName = "crucible-sim-freeze-warp-at-observation-boundary";
      class = "D";
      enforces = "DET-8,DET-29";
      capability = "sim freezes the virtual clock at the observation boundary so terminal fingerprint capture is deterministic";
    }
    {
      file = "0038-crucible-sim-gate-rr-kick.patch";
      catalogName = "crucible-sim-gate-rr-kick";
      class = "D";
      enforces = "DET-30";
      capability = "sim omits the redundant stock round-robin vCPU-kick timer for deterministic quantum switching";
    }
    {
      file = "0039-crucible-blk-device-completion-advance.patch";
      catalogName = "crucible-blk-device-completion-advance";
      class = "D";
      enforces = "DET-16,PATCH-27,PLUG-21,IO-31";
      capability = "device-wait callback advances an I/O-blocked guest to its deterministic completion and resumes polling after commit";
    }
    {
      file = "0040-crucible-9p-sync-kick.patch";
      catalogName = "crucible-9p-sync-kick";
      class = "D";
      enforces = "DET-16,PATCH-29,PLUG-22,IO-32";
      capability = "sim-mode virtio-9p kicks enter deterministic raw-message forwarding synchronously";
    }
    {
      file = "0041-crucible-whitebox-guest-write.patch";
      catalogName = "crucible-whitebox-guest-write";
      class = "F";
      enforces = "PLUG-14,GHC-12,GHC-16";
      capability = "synchronous plugin callbacks can write typed white-box replies through the current or exact resume-vCPU guest-memory mapping";
    }
    {
      file = "0042-crucible-aarch64-det-ipi-adapter.patch";
      catalogName = "crucible-aarch64-det-ipi-adapter";
      class = "D";
      enforces = "DET-4,PLUG-14,GHC-4";
      capability = "AArch64 deterministic IPI adapter for the shared RR and commanded-preemption paths";
    }
    {
      file = "0043-crucible-time-advance-commit-barrier.patch";
      catalogName = "crucible-time-advance-commit-barrier";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "RR and plugin logical-time commits remain fenced until both owners release";
    }
    {
      file = "0044-crucible-time-advance-enqueue-kick.patch";
      catalogName = "crucible-time-advance-enqueue-kick";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "queued time advance kicks the active sim vCPU into the pending barrier";
    }
    {
      file = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      catalogName = "crucible-time-advance-arm-at-vcpu-boundary";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "pending time advance arms synchronously at a stopped-vCPU work boundary";
    }
    {
      file = "0046-crucible-translation-prefetch-helper.patch";
      catalogName = "crucible-translation-prefetch-helper";
      class = "F";
      enforces = "PERF-32";
      capability = "off-by-default sim translation generation on a dedicated registered TCG helper";
    }
    {
      file = "0047-crucible-fault-command-abi.patch";
      catalogName = "crucible-fault-command-abi";
      class = "F";
      enforces = "FAULT-ABI,FAULT-CAP,REP-15";
      capability = "versioned closed fault command/result rings and exact capability manifest";
    }
    {
      file = "0048-crucible-fault-safe-boundary.patch";
      catalogName = "crucible-fault-safe-boundary";
      class = "D";
      enforces = "FAULT-BOUNDARY,FAULT-AUTH,DET-1";
      capability = "exact node-icount fault boundary with authorization-ceiling enforcement";
    }
    {
      file = "0049-crucible-memory-boundary-mutate.patch";
      catalogName = "crucible-memory-boundary-mutate";
      class = "F";
      enforces = "QFP-MEM-1,QFP-MEM-2,FAULT-ORDER";
      capability = "atomic GPA/GVA mutation with translation, RAM-map, dirty-page, and TB evidence";
    }
    {
      file = "0050-crucible-memory-access-faults.patch";
      catalogName = "crucible-memory-access-faults";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "typed fetch, load, store, atomic, and identified virtio DMA memory fault rules with shared service and persistent region state";
    }
    {
      file = "0051-crucible-add-architecture-register-fault-mutations.patch";
      catalogName = "crucible-architecture-register-faults";
      class = "D";
      enforces = "QFP-REG-1,QFP-REG-2,FAULT-ORDER";
      capability = "manifest-bound x86-64 and AArch64 register mutations at exact instruction boundaries";
    }
    {
      file = "0052-crucible-instruction-and-exception-faults.patch";
      catalogName = "crucible-instruction-and-exception-faults";
      class = "D";
      enforces = "QFP-INSN-1,QFP-EXC-1,FAULT-ORDER";
      capability = "exact x86-64 and AArch64 instruction result, skip, replay, and architectural exception faults";
    }
    {
      file = "0053-crucible-interrupt-faults.patch";
      catalogName = "crucible-interrupt-faults";
      class = "D";
      enforces = "QFP-IRQ-1,QFP-IRQ-2,FAULT-ORDER";
      capability = "manifest-bound interrupt drop, delay, duplication, replacement, and bounded storms through realized x86-64 and AArch64 controllers";
    }
    {
      file = "0054-crucible-inject-architecture-hardware-errors.patch";
      catalogName = "crucible-hardware-error-inject";
      class = "D";
      enforces = "QFP-HWERR-1,QFP-HWERR-2,FAULT-ORDER";
      capability = "manifest-bound x86 machine-check, AArch64 RAS, and realized memory ECC delivery with transactional evidence";
    }
    {
      file = "0055-crucible-vcpu-service-control.patch";
      catalogName = "crucible-vcpu-service-control";
      class = "D";
      enforces = "QFP-VCPU-1,QFP-VCPU-2,FAULT-ORDER";
      capability = "exact rational vCPU service, fixed-topology stall and offline state, bounded work conservation, and replay evidence";
    }
    {
      file = "0056-crucible-node-lifecycle-faults.patch";
      catalogName = "crucible-node-lifecycle-faults";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "deterministic node lifecycle transitions and schedulable node or vCPU hangs with closed state treatment and replay evidence";
    }
    {
      file = "0060-crucible-block-typed-errors.patch";
      catalogName = "crucible-block-typed-errors";
      class = "F";
      enforces = "STOR-RESULT,IO-8,PATCH-26";
      capability = "closed block result ABI translated to exact guest-visible Linux errno values";
    }
    {
      file = "0061-crucible-block-discard.patch";
      catalogName = "crucible-block-discard";
      class = "F";
      enforces = "STOR-DISCARD,DET-16,PATCH-26";
      capability = "payload-free block discard transported through the deterministic shmem completion path";
    }
    {
      file = "0062-crucible-block-transport-reset.patch";
      catalogName = "crucible-block-transport-reset";
      class = "F";
      enforces = "STOR-RESET,STOR-RESULT,DET-16,PATCH-26";
      capability = "transactional epoch-scoped block reset, recovery admission, retry dispositions, and declared topology re-enumeration";
    }
    {
      file = "0063-crucible-plugin-vmstop.patch";
      catalogName = "crucible-plugin-vmstop";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43";
      capability = "exact plugin-boundary handoff into QEMU's native paused runstate";
    }
    {
      file = "0064-crucible-terminal-lifecycle-completion.patch";
      catalogName = "crucible-terminal-lifecycle-completion";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "two-phase typed terminal lifecycle evidence, QMP authorization, and exact process-exit staging";
    }
    {
      file = "0065-crucible-authenticated-terminal-lifecycle.patch";
      catalogName = "crucible-authenticated-terminal-lifecycle";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "dedicated idempotent QAPI terminal authorization bound to action, evidence, and process generation without guest resume";
    }
    {
      file = "0066-crucible-immutable-process-generation.patch";
      catalogName = "crucible-immutable-process-generation";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "launch-time immutable process generation provisioning before fault-command admission";
    }
    {
      file = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      catalogName = "crucible-core-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,FAULT-ORDER";
      capability = "transactional bounded VMState for core command, memory, CPU, interrupt, hardware-error, service, and lifecycle fault state";
    }
    {
      file = "0068-crucible-guest-clock-faults.patch";
      catalogName = "crucible-guest-clock-faults";
      class = "D";
      enforces = "QFP-CLOCK-1,QFP-CLOCK-2,FAULT-ORDER";
      capability = "transactional guest-clock transforms, source-state transitions, timer rearming, and typed causal evidence";
    }
    {
      file = "0069-crucible-accelerator-fault-device.patch";
      catalogName = "crucible-accelerator-fault-device";
      class = "D";
      enforces = "QFP-ACCEL-1,QFP-ACCEL-2,FAULT-ORDER";
      capability = "migration-safe virtio accelerator co-simulation transport with lifecycle, result, memory/ECC, and service mutations for closed GPU, TPU, and FPGA job schemas";
    }
    {
      file = "0070-crucible-fault-vmstate.patch";
      catalogName = "crucible-fault-vmstate";
      class = "D";
      enforces = "QFP-STATE-1,QFP-STATE-2,QFP-STATE-3";
      capability = "live fail-closed build, patch-series, shared-memory ABI, and exact aggregate fault VMState identity";
    }
    {
      file = "0071-crucible-lifecycle-precondition.patch";
      catalogName = "crucible-lifecycle-precondition";
      class = "D";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "atomic lifecycle prepare and commit over the same authenticated VM-state precondition";
    }
    {
      file = "0072-crucible-typed-node-result-schema.patch";
      catalogName = "crucible-typed-node-result-schema";
      class = "D";
      enforces = "QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "fixed typed-command results with command-specific evidence retained on authenticated occurrence events";
    }
    {
      file = "0073-crucible-device-wait-vmstop.patch";
      catalogName = "crucible-device-wait-vmstop";
      class = "F";
      enforces = "QFP-STATE-2,DET-1,INV-10";
      capability = "synchronous exact stop at drained control wakes with nonblocking admission from device-completion callbacks";
    }
    {
      file = "0074-crucible-arm-accelerator-result-opportunities.patch";
      catalogName = "crucible-accelerator-result-opportunity";
      class = "F";
      enforces = "QFP-ACCEL-3,QFP-RESULT-1,QFP-EVENT-1,FAULT-ORDER";
      capability = "atomic one-shot accelerator result arming with durable reservations and typed deferred completion results";
    }
    {
      file = "0075-crucible-restore-authenticated-fault-event-requests.patch";
      catalogName = "crucible-authenticated-event-request-envelope";
      class = "F";
      enforces = "QFP-STATE-2,QFP-ACCEL-3,QFP-EVENT-1,FAULT-ORDER";
      capability = "mandatory authenticated request/evidence envelopes for fresh-process restore and exact accelerator-opportunity binding";
    }
    {
      file = "0076-crucible-9p-completion-wake-registration.patch";
      catalogName = "crucible-9p-completion-wake-registration";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "realize-time 9p completion notifier registration independent of plugin installation order";
    }
    {
      file = "0077-crucible-serialize-rr-cursor.patch";
      catalogName = "crucible-serialize-rr-cursor";
      class = "D";
      enforces = "DET-1,DET-18,INV-10";
      capability = "authoritative record/replay cursor accounting and VMState restore before guest execution";
    }
    {
      file = "0078-crucible-fingerprint-guest-state-domains.patch";
      catalogName = "crucible-fingerprint-state-domains";
      class = "D";
      enforces = "DET-18,DET-19,INV-10";
      capability = "guest-semantic CPU and interrupt fingerprint domains with target-declared transient interrupt canonicalization";
    }
    {
      file = "0079-crucible-stopped-state-control-progress.patch";
      catalogName = "crucible-stopped-state-control-progress";
      class = "D";
      enforces = "DET-1,INV-10,QEMU-43,QFP-STATE-2";
      capability = "level-triggered native-stop progress with all-vCPU queued-work admission and a bounded BQL-aware wait";
    }
    {
      file = "0080-crucible-inactive-retention-clock-guard.patch";
      catalogName = "crucible-inactive-retention-clock-guard";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "inactive memory-retention boundaries return before sampling a transient fresh-process restore clock";
    }
    {
      file = "0081-crucible-deferred-result-evidence-test.patch";
      catalogName = "crucible-deferred-result-evidence-test";
      class = "F";
      enforces = "QEMU-44,FAULT-EVIDENCE";
      capability = "live instruction-fault coverage validates the canonical typed evidence added to deferred completions";
    }
    {
      file = "0082-crucible-deterministic-instruction-input-state.patch";
      catalogName = "crucible-deterministic-instruction-input-state";
      class = "D";
      enforces = "DET-1,QEMU-44,FAULT-EVIDENCE";
      capability = "instruction input selectors use a cross-process-stable architectural-register digest while retaining full RAM and device state in canonical evidence";
    }
    {
      file = "0083-crucible-inert-clock-restore.patch";
      catalogName = "crucible-inert-clock-restore";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,QFP-STATE-2";
      capability = "fresh-process restore retains QEMU-native timer state for inactive guest clocks while rearming only clocks with an effective Crucible transform";
    }
    {
      file = "0084-crucible-exact-restore-network-announcement.patch";
      catalogName = "crucible-exact-restore-network-announcement";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,FAULT-ORDER";
      capability = "exact Crucible restore suppresses migration-only virtio-net guest announcements without changing ordinary migration behavior";
    }
    {
      file = "0085-crucible-register-rejection-atomicity.patch";
      catalogName = "crucible-register-rejection-atomicity";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-REG-2,FAULT-EVIDENCE";
      capability = "exact RR ownership gates canonical register observation; every realized CPU manifest is validated; rejected register commands preserve every canonical GDB register byte and all six mutation side-effect counters";
    }
    {
      file = "0086-crucible-genesis-observation-boundary.patch";
      catalogName = "crucible-genesis-observation-boundary";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "the BQL-held prelaunch genesis boundary admits complete all-vCPU architectural observation only at exact raw icount zero";
    }
    {
      file = "0087-crucible-deterministic-rcu-quiescence.patch";
      catalogName = "crucible-deterministic-rcu-quiescence";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "sim mode reaches RCU quiescence at its bounded deterministic RR execution boundaries without host-timed translation-block exits";
    }
    {
      file = "0088-crucible-deterministic-host-kick-boundary.patch";
      catalogName = "crucible-deterministic-host-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "state-free host latency hints cannot end an active sim translation block, while between-slice and committed stop, unplug, halted, stopped, and interrupt-request kicks retain immediate progress";
    }
    {
      file = "0089-crucible-exact-boundary-vcpu-introspection.patch";
      catalogName = "crucible-exact-boundary-vcpu-introspection";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact BQL-held main-loop boundaries read every quiescent vCPU register file and the committed RR cursor without a current vCPU, while arbitrary unowned contexts remain rejected";
    }
    {
      file = "0090-crucible-active-tcg-kick-boundary.patch";
      catalogName = "crucible-active-tcg-kick-boundary";
      class = "D";
      enforces = "DET-1,DET-29,QEMU-43";
      capability = "state-free sim kicks request exit at the next deterministic translation-block boundary while committed transitions preserve immediate liveness";
    }
    {
      file = "0091-crucible-canonical-rr-genesis-cursor.patch";
      catalogName = "crucible-canonical-rr-genesis-cursor";
      class = "D";
      enforces = "DET-1,QFP-REG-1,QFP-STATE-2";
      capability = "exact raw-zero observers read the unique next RR coordinate without mutating scheduler state while every later invalid cursor remains rejected";
    }
    {
      file = "0092-crucible-canonical-terminal-rr-cursor.patch";
      catalogName = "crucible-canonical-terminal-rr-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "live observers at a quantum terminal project onto the next scheduler-owned vCPU at position zero without mutating serialized RR state";
    }
    {
      file = "0093-crucible-canonical-register-cursor.patch";
      catalogName = "crucible-canonical-register-cursor";
      class = "D";
      enforces = "DET-1,DET-29,QFP-STATE-2";
      capability = "after-instruction register evidence advances its callback-local prefix and projects an exact quantum terminal onto the canonical next RR coordinate";
    }
    {
      file = "0094-crucible-retention-virtual-time-origin.patch";
      catalogName = "crucible-retention-virtual-time-origin";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "memory-retention expiry originates in authoritative virtual nanoseconds instead of mixing raw instruction coordinates with clock-biased deadlines";
    }
    {
      file = "0095-crucible-raw-pte-update-identity.patch";
      catalogName = "crucible-raw-pte-update-identity";
      class = "D";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-ORDER";
      capability = "x86 page-table translation consumes corrected transient PTE bytes while accessed/dirty cmpxchg preserves the canonical backing entry and cannot retry forever";
    }
    {
      file = "0096-crucible-physical-page-table-region-fixture.patch";
      catalogName = "crucible-physical-page-table-region-fixture";
      class = "F";
      enforces = "QFP-MEMA-1,QFP-MEMA-2,FAULT-EVIDENCE";
      capability = "live persistent page-table-region tests address descriptor storage by GPA while ordinary guest-memory region tests retain GVA targeting";
    }
    {
      file = "0097-crucible-canonicalize-memory-retry-identity.patch";
      catalogName = "crucible-canonical-memory-retry-identity";
      class = "D";
      enforces = "DET-1,QFP-MEMA-1,QFP-STATE-2";
      capability = "memory retry keys exclude TB-local instruction ordinals and serialize that compatibility field at canonical zero across fault-driven retranslation";
    }
    {
      file = "0098-crucible-inactive-nested-tsc-guard.patch";
      catalogName = "crucible-inactive-nested-tsc-guard";
      class = "D";
      enforces = "DET-1,QFP-CLOCK-2,PATCH-3";
      capability = "inactive guest-clock faults avoid TSC sampling inside SVM entry and exit so nested execution preserves upstream icount accounting";
    }
    {
      file = "0099-crucible-valid-aarch64-abort-fixture.patch";
      catalogName = "crucible-valid-aarch64-abort-fixture";
      class = "F";
      enforces = "QFP-MEMA-1,FAULT-EVIDENCE,PATCH-3";
      capability = "the live AArch64 poison-exception and retry fixtures submit the data-abort vector and a same-EL syndrome accepted by the production architecture validator";
    }
    {
      file = "0100-crucible-aarch64-memory-exception-vectors.patch";
      catalogName = "crucible-aarch64-memory-exception-vectors";
      class = "D";
      enforces = "QFP-MEMA-1,FAULT-EVIDENCE,PATCH-3";
      capability = "AArch64 memory exception admission requires instruction-abort vector 2 for fetches and data-abort vector 3 for non-fetch accesses";
    }
    {
      file = "0101-crucible-canonicalize-snapshot-rr-resume.patch";
      catalogName = "crucible-canonical-snapshot-rr-resume";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "successful sim-mode snapshots arm the same one-shot serialized-owner selection used after load so source continuation preserves the RR owner and intra-turn position";
    }
    {
      file = "0102-crucible-bql-exact-register-capture.patch";
      catalogName = "crucible-bql-exact-register-capture";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "BQL-held exact callbacks read quiescent vCPU registers while post-snapshot RR owner reselection is pending, and idle-time completion is explicitly scoped as exact";
    }
    {
      file = "0103-crucible-isolate-checkpoint-control-wake.patch";
      catalogName = "crucible-isolate-checkpoint-control-wake";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,PATCH-20";
      capability = "a pending exact VM-stop handoff wakes QEMU's main loop without resuming parked block coroutines or admitting post-pause completions";
    }
    {
      file = "0104-crucible-preserve-checkpoint-block-durability.patch";
      catalogName = "crucible-preserve-checkpoint-block-durability";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QFP-BLOCK-3";
      capability = "synthetic QEMU stop-time flushes preserve the checkpointed Apache durability continuation and cannot create post-quiescence Crucible block requests";
    }
    {
      file = "0105-crucible-selector-control-plane-fixtures.patch";
      catalogName = "crucible-selector-control-plane-fixtures";
      class = "F";
      enforces = "FAULT-ORDER,PATCH-3,QFP-INST-3";
      capability = "live instruction selector overlap and exclusivity fixtures use unreachable occurrences so admission checks remain isolated from data-plane fault delivery";
    }
    {
      file = "0106-crucible-defer-active-slice-host-wakes.patch";
      catalogName = "crucible-defer-active-slice-host-wakes";
      class = "D";
      enforces = "DET-1,QFP-KICK-3,QEMU-43";
      capability = "an atomic idle-active-pending handshake admits multi-vCPU state-free wakes only before TCG starts and never lets them select a translation-block endpoint, while single-vCPU soft exits and explicit terminal and committed lifecycle wakes remain live";
    }
    {
      file = "0107-crucible-anchor-rr-cursor-genesis.patch";
      catalogName = "crucible-anchor-rr-cursor-genesis";
      class = "D";
      enforces = "DET-1,QFP-STATE-2,QEMU-43";
      capability = "fresh sim-mode execution establishes vCPU 0 position 0 before the first budget, the serialized owner remains authoritative across partial turns and VMState restore, and terminal live observation emits canonical RR-switch transitions";
    }
    {
      file = "0108-crucible-deterministic-network-kick.patch";
      catalogName = "crucible-deterministic-network-kick";
      class = "D";
      enforces = "DET-1,PLUG-23,PLUG-24,QEMU-43";
      capability = "sim-mode virtio-net queue kicks and serialized tx_waiting resumes drain every deferred TX bottom half synchronously, supply one committed raw transmit icount, preserve the virtqueue notification cursor in an optional sim VMState subsection, symmetrically flush pre-checkpoint translation history, and use bounded cache-independent TB shapes without direct chains on both continuations so VMState restore preserves packet and fault-decision continuation";
    }
    {
      file = "0109-crucible-control-boundary-node-faults.patch";
      catalogName = "crucible-control-boundary-node-faults";
      class = "F";
      enforces = "QFP-LIFE-1,QFP-LIFE-2,FAULT-ORDER";
      capability = "a node-boundary command submitted while QEMU is halted at an exact drained control wake is dispatched at that same raw icount, so PREPARE and APPLY complete without requiring guest progress; terminal authorization hashes zero the raw evidence coordinate before the plugin maps it into scheduler-logical space";
    }
    {
      file = "0110-crucible-release-halted-rr-turn.patch";
      catalogName = "crucible-release-halted-rr-turn";
      class = "D";
      enforces = "DET-1,PLUG-24,QEMU-43";
      capability = "a vCPU that executes HLT before exhausting its serialized RR turn leaves the execution loop when no alternative vCPU is runnable; a helper-marked multi-vCPU guest PAUSE fences control-boundary acknowledgement until it commits a cursor-zero early handoff immediately after icount accounting and before callbacks or host-work exits, so a released spin lock cannot be reacquired before a waiting peer runs; and that exact completed-turn handoff admits safe register capture while other owner mismatches fail closed";
    }
    {
      file = "0111-crucible-accelerator-service-schema.patch";
      catalogName = "crucible-accelerator-service-schema";
      class = "F";
      enforces = "QFP-ACCEL-SERVICE,FAULT-ORDER";
      capability = "typed accelerator service commands admit the ratio-valued capacity field used by the versioned node-fault payload before atomically installing compute, memory-rate, thermal, and power service policy";
    }
    {
      file = "0112-crucible-compile-affected-clock-sources.patch";
      catalogName = "crucible-compile-affected-clock-sources";
      class = "F";
      enforces = "QFP-CLOCK-SOURCE,FAULT-ORDER";
      capability = "a committed clock rule recompiles and rearms only sources selected by that exact rule, so an unrelated source that cannot project raw time at the stopped boundary cannot invalidate the authenticated transition";
    }
    {
      file = "0113-crucible-restore-accelerator-rule-indexes.patch";
      catalogName = "crucible-restore-accelerator-rule-indexes";
      class = "F";
      enforces = "QFP-ACCEL-SERVICE,FAULT-RESTORE";
      capability = "fresh-process VMState restore rebuilds each accelerator lifecycle, result, memory, and service rule index from the authenticated staged node-rule ledger before commit, preserving persistent accelerator behavior without duplicating rule ownership";
    }
    {
      file = "0114-crucible-hot-fork-readiness.patch";
      catalogName = "crucible-hot-fork-readiness";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded versioned QMP query reports QEMU-owned precise-icount, single-threaded sim RR, and exact paused/device-flush proofs while keeping every unimplemented subsystem, mapping, and child-reinitialization proof clear so ordinary paused state can never advertise hot fork";
    }
    {
      file = "0115-crucible-hot-fork-thread-ownership.patch";
      catalogName = "crucible-hot-fork-thread-ownership";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "the bounded thread registry identifies unresolved RCU callback and AIO-context workers through subsystem-owned entry-point registration while retaining both in the exact unresolved blocker count and leaving every readiness bit unchanged";
    }
    {
      file = "0116-crucible-hot-fork-rcu-inventory.patch";
      catalogName = "crucible-hot-fork-rcu-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded QMP inventory exposes every registered RCU reader plus instantaneous read-side, callback, and drain state without claiming a held barrier or acknowledging the RCU readiness proof";
    }
    {
      file = "0117-crucible-hot-fork-aio-inventory.patch";
      catalogName = "crucible-hot-fork-aio-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded QMP inventory exposes every registered AioContext plus instantaneous poll, dispatch, bottom-half, coroutine, and notification activity without claiming a held barrier or acknowledging the AIO readiness proof";
    }
    {
      file = "0118-crucible-hot-fork-mutex-inventory.patch";
      catalogName = "crucible-hot-fork-mutex-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded QMP inventory exposes every live QemuMutex and QemuRecMutex plus exact instantaneous ownership, recursion, acquisition, condition-wait, and unlock-transition state without claiming a held barrier, child reinitializer, or readiness proof";
    }
    {
      file = "0119-crucible-hot-fork-timer-inventory.patch";
      catalogName = "crucible-hot-fork-timer-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded QMP inventory exposes every pending timer and active callback with exact process-local identities, clock, expiry, scale, attributes, and state without claiming a retained timer barrier or readiness proof";
    }
    {
      file = "0120-crucible-hot-fork-bottom-half-inventory.patch";
      catalogName = "crucible-hot-fork-bottom-half-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded QMP inventory exposes every allocated QEMUBH, including inert, pending, active, canceled, and deferred-deletion instances, with exact AioContext binding and state without claiming a retained AIO/BH/timer barrier or readiness proof";
    }
    {
      file = "0121-crucible-hot-fork-aio-handler-inventory.patch";
      catalogName = "crucible-hot-fork-aio-handler-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a bounded QMP inventory exposes every allocated POSIX AioHandler, including deferred deletion, exact AioContext and descriptor binding, callback classes, and active callback count without claiming a retained AIO-handler barrier or readiness proof";
    }
    {
      file = "0122-crucible-hot-fork-block-backend-inventory.patch";
      catalogName = "crucible-hot-fork-block-backend-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-5";
      capability = "a bounded OOB QMP inventory exposes every allocated BlockBackend with stable backend/AioContext identity, visibility, attachment, permission, quiesce, queue-policy, and in-flight state without claiming block-graph traversal, a retained writable-root barrier, or readiness proof";
    }
    {
      file = "0123-crucible-hot-fork-plugin-resource-inventory.patch";
      catalogName = "crucible-hot-fork-plugin-resource-inventory";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "a fixed OOB QMP report binds the sealed Crucible plugin resource manifest to QEMU-observed callback registration, exact control/wake descriptors, shared-memory identity and topology, and optional modes without claiming an executing-callback count, ring freeze, callback parking, child reconstruction, or readiness proof";
    }
    {
      file = "0124-crucible-hot-fork-plugin-callback-barrier.patch";
      catalogName = "crucible-hot-fork-plugin-callback-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4";
      capability = "a versioned OOB QMP operation holds, observes, and releases the plugin-owned reversible callback-admission barrier; holding rejects new registered callback work and reports already-admitted in-flight callbacks without blocking QMP, while readiness bit 6 remains clear until host ring writers, plugin workers, and child reconstruction are also frozen";
    }
    {
      file = "0125-crucible-hot-fork-template-coordinator.patch";
      catalogName = "crucible-hot-fork-template-coordinator";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "a serialized versioned OOB QMP coordinator owns retained template preparation, acquires the plugin callback barrier only at the exact paused/device-flush boundary, reports draining without blocking QMP, rolls every acquired barrier back when complete readiness remains unavailable, and refuses to claim prepared until all nine proof bits are present in one retained transaction";
    }
    {
      file = "0126-crucible-hot-fork-rcu-barrier.patch";
      catalogName = "crucible-hot-fork-rcu-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "a process-lifetime reversible RCU barrier gates every new outer read-side entry and callback submission, retains exact admission, reader, callback, and drain state, wakes parked submitters only on release, and lets the template coordinator acknowledge proof bit 4 only while the complete held barrier is quiescent";
    }
    {
      file = "0127-crucible-hot-fork-bh-timer-barrier.patch";
      catalogName = "crucible-hot-fork-bh-timer-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "a process-lifetime reversible source barrier race-closes bottom-half and timer creation, mutation, and callback dispatch, drains already-admitted work, retains queued work as parked state, remains OOB-queryable, and deliberately leaves AIO proof bit 3 clear until handler and coroutine admission are also closed";
    }
    {
      file = "0128-crucible-hot-fork-aio-barrier.patch";
      catalogName = "crucible-hot-fork-aio-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "the retained asynchronous-source barrier additionally race-closes AioContext polling and GLib dispatch, POSIX AioHandler mutation and callbacks, and coroutine scheduling; reports bounded complete inventories and exact active counts; and lets the retained template coordinator derive AIO proof bit 3 only while the complete held barrier is quiescent";
    }
    {
      file = "0129-crucible-hot-fork-block-drain-barrier.patch";
      catalogName = "crucible-hot-fork-block-drain-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "a process-lifetime QEMU-native all-block drain section quiesces every rooted BlockBackend without synchronously waiting for already-issued I/O, retains the drain until explicit release, reports bounded exact backend and in-flight aggregates, and deliberately leaves block proof bit 5 clear until an immutable external-snapshot root is authenticated";
    }
    {
      file = "0130-crucible-hot-fork-block-template-coordinator.patch";
      catalogName = "crucible-hot-fork-block-template-coordinator";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "the version-5 template coordinator asynchronously acquires QEMU's native all-block drain on the main AioContext before parking asynchronous sources, releases asynchronous sources before scheduling main-loop block release, rejects standalone barrier mutation while any transaction phase is reserved, and keeps block proof bit 5 clear until an immutable external-snapshot root is authenticated";
    }
    {
      file = "0131-crucible-hot-fork-block-graph-barrier.patch";
      catalogName = "crucible-hot-fork-block-graph-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "the retained native block barrier also closes block-graph writer admission, parks later main-loop writers until release, binds the exact completed-mutation generation captured at hold, and reports active or waiting writers without acknowledging immutable-snapshot proof bit 5";
    }
    {
      file = "0132-crucible-bind-hot-fork-block-snapshot-roots.patch";
      catalogName = "crucible-hot-fork-block-snapshot-roots";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "while the retained block graph and drain barriers are quiescent, the template coordinator binds every writable rooted backend to an exact guest-allocation-empty active overlay over an immediate read-only snapshot, with exact backend, node, content, size, backend-generation, and graph-generation identity, and acknowledges immutable writable-root proof bit 5; branch-private child overlay reconstruction remains open";
    }
    {
      file = "0133-crucible-authenticate-fault-result-payloads.patch";
      catalogName = "crucible-authenticate-fault-result-payloads";
      class = "F";
      enforces = "QFP-RESULT,FAULT-ORDER";
      capability = "every queued fault result authenticates the exact payload retained beside it, including prepare-time rejection evidence, so the host can classify a typed rejection without losing transaction ownership";
    }
    {
      file = "0134-crucible-clock-impulse-read-error-policies.patch";
      catalogName = "crucible-clock-impulse-read-error-policies";
      class = "F";
      enforces = "QFP-CLOCK-TRANSFORM,QFP-CLOCK-SOURCE,FAULT-ORDER";
      capability = "impulse clock transforms retain their effective monotonicity and overdue-timer policies in versioned clock VMState, while an x86 TSC read-error transition raises a deterministic guest #GP and internal projections retain the last source value";
    }
    {
      file = "0135-crucible-freeze-hot-fork-rings.patch";
      catalogName = "crucible-hot-fork-ring-producer-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "the retained plugin barrier also holds every ABI-v19 shared-memory ring producer, reports exact ring and already-admitted producer counts, and requires both callback and ring admission to drain before quiescence; worker parking, ring cloning, and child reconstruction remain open under proof bit 6";
    }
    {
      file = "0136-crucible-seal-hot-fork-plugin-workers.patch";
      catalogName = "crucible-hot-fork-plugin-worker-manifest";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "the version-2 plugin resource manifest seals the mandatory run-control and teardown workers plus the fingerprint digest worker exactly when fingerprinting is enabled, giving future parking and child reconstruction a closed worker set without yet acknowledging proof bit 6";
    }
    {
      file = "0137-crucible-park-hot-fork-plugin-workers.patch";
      catalogName = "crucible-hot-fork-plugin-worker-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "the version-3 plugin barrier reports the sealed worker mask, exact parked worker classes, and bounded operations admitted before the hold, and requires every worker to park before subsystem quiescence without yet cloning queued work or acknowledging proof bit 6";
    }
    {
      file = "0138-crucible-drain-hot-fork-ring-consumers.patch";
      catalogName = "crucible-hot-fork-ring-consumer-barrier";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "the version-4 plugin barrier reports shared-ring consumers admitted before the hold and requires every producer and consumer to drain before subsystem quiescence without yet cloning queued bytes or acknowledging proof bit 6";
    }
    {
      file = "0139-crucible-retain-hot-fork-private-rings.patch";
      catalogName = "crucible-hot-fork-private-ring-stage";
      class = "F";
      enforces = "HFORK-3,HFORK-8,HFORK-9";
      capability = "QEMU duplicates and authenticates one bounded standard-QMP getfd entry by name, device, inode, length, regular-file type, and shrink seal, then retains it independently for future child remapping while explicitly keeping readiness bits 6 and 7 clear";
    }
    {
      file = "0140-crucible-account-hot-fork-worker-local-state.patch";
      catalogName = "crucible-hot-fork-worker-local-state";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-5";
      capability = "the version-5 plugin barrier distinguishes an idle parked worker from a parked worker retaining one dequeued item in thread-local state, requires pending workers to remain parked, and keeps quiescence false until every local item is either discarded or admitted without acknowledging proof bit 6";
    }
    {
      file = "0141-crucible-stage-hot-fork-plugin-endpoints.patch";
      catalogName = "crucible-hot-fork-plugin-endpoint-stage";
      class = "F";
      enforces = "HFORK-3,HFORK-8,HFORK-9";
      capability = "QEMU retains and authenticates distinct connected-empty AF_UNIX control and empty eventfd wake endpoints against exact kernel identities, normalizes and verifies the retained eventfd as nonblocking after standard-QMP import, and binds both to one retained private-ring generation without installing either endpoint in a child or acknowledging readiness bits 6 through 8";
    }
    {
      file = "0142-crucible-retain-hot-fork-resource-staging.patch";
      catalogName = "crucible-hot-fork-retained-resource-stage";
      class = "F";
      enforces = "HFORK-3,HFORK-8,HFORK-9";
      capability = "the version-10 template coordinator retains a fully drained incomplete transaction until explicit abort and admits exact private-ring and plugin-endpoint staging only while the retained plugin barrier is quiescent, without acknowledging readiness bits 6 through 8 or forking";
    }
    {
      file = "0143-crucible-bind-hot-fork-resource-generations.patch";
      catalogName = "crucible-hot-fork-resource-generation-binding";
      class = "F";
      enforces = "HFORK-3,HFORK-8,HFORK-9";
      capability = "QEMU atomically binds retained private-ring and plugin-endpoint generations to the exact version-11 template transaction, rejects cross-transaction composition, and reports retained-but-unbound resources after abort without acknowledging readiness bits 6 through 8";
    }
    {
      file = "0144-crucible-bind-hot-fork-worker-dispositions.patch";
      catalogName = "crucible-hot-fork-worker-disposition-binding";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-8,HFORK-9";
      capability = "QEMU binds an explicit empty-local-state parent-resume and child-reinitialize plan for every sealed plugin worker class to the exact quiescent plugin-barrier generation retained by the version-12 template transaction, while leaving child application and readiness bits 6 through 8 incomplete";
    }
    {
      file = "0145-crucible-exclude-source-rings-from-fork-children.patch";
      catalogName = "crucible-hot-fork-source-ring-noninheritance";
      class = "F";
      enforces = "HFORK-3,HFORK-8,HFORK-9,HFORK-12";
      capability = "the version-6 plugin barrier applies MADV_DONTFORK to the exact source shared-memory mapping only after callback, ring, and worker admission closes, rolls every hold back on failure, and restores MADV_DOFORK before reopening the retained parent without yet installing a child mapping or acknowledging readiness bits 6 through 8";
    }
    {
      file = "0146-crucible-register-hot-fork-child-runtime.patch";
      catalogName = "crucible-hot-fork-child-runtime-registration";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-8,HFORK-9,HFORK-12";
      capability = "QEMU and the plugin share a fixed version-1 child-runtime ABI that binds the exact template, private-ring, endpoint, plugin-barrier, kernel endpoint, mapping, descriptor, and worker basis while retaining the reconstruction callback without invoking a child transaction or acknowledging readiness bits 6 through 8";
    }
    {
      file = "0147-crucible-bind-hot-fork-child-process-generation.patch";
      catalogName = "crucible-hot-fork-child-process-generation";
      class = "F";
      enforces = "HFORK-3,HFORK-8,HFORK-9,HFORK-11,HFORK-12";
      capability = "the fixed version-2 child-runtime ABI advances one exact nonzero process generation in both QEMU lifecycle state and the plugin live-device owner, and rejects stale, skipped, overflowed, or drifting generation bases without invoking a child transaction or acknowledging readiness bits 6 through 8";
    }
    {
      file = "0148-crucible-expose-hot-fork-child-runtime-state.patch";
      catalogName = "crucible-hot-fork-child-runtime-observation";
      class = "F";
      enforces = "HFORK-3,HFORK-8,HFORK-9,HFORK-11,HFORK-12";
      capability = "the out-of-band version-2 child-runtime observation binds registration to the complete plugin resource manifest and exact process generation, reports exact phase/resource/endpoint/worker state with a stable mutation generation, and remains inert without acknowledging readiness bits 6 through 8";
    }
    {
      file = "0149-crucible-bind-hot-fork-endpoint-replacement-slots.patch";
      catalogName = "crucible-hot-fork-endpoint-replacement-plan";
      class = "F";
      enforces = "HFORK-3,HFORK-4,HFORK-8,HFORK-9,HFORK-12";
      capability = "version 4 of the retained plugin-endpoint stage binds exact QEMU-owned replacement sources to the distinct sealed plugin-manifest control and wake slots under the current template basis, while leaving application and readiness bits 6 through 8 incomplete";
    }
    {
      file = "0150-crucible-add-fork-child-endpoint-replacement-primitive.patch";
      catalogName = "crucible-hot-fork-child-endpoint-replacement-primitive";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-12";
      capability = "the Linux-only GPL-side endpoint replacement helper validates two pairwise-distinct source/target pairs, preserves target descriptor flags, verifies the installed pair, restores both targets on rejection, and reports an unrecoverable poisoned disposition when rollback cannot be proved; it remains internal and unwired pending the immediate-child coordinator";
    }
    {
      file = "0151-crucible-authenticate-immediate-hot-fork-children.patch";
      catalogName = "crucible-hot-fork-immediate-child-identity";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-11,HFORK-12";
      capability = "the Linux-only GPL-side child identity primitive pins the parent process generation before fork, accepts only its exact live immediate child, arms parent-death termination before disposition, and proves child-only endpoint replacement under a real fork without yet wiring the production coordinator";
    }
    {
      file = "0152-crucible-acknowledge-frozen-hot-fork-plugin-rings.patch";
      catalogName = "crucible-hot-fork-plugin-ring-proof";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-11,HFORK-12";
      capability = "version-13 template preparation acknowledges plugin-ring proof bit 6 only for an exact transaction-bound private ring, endpoint pair, worker plan, and frozen plugin barrier; descriptor and child-reinitialization proofs remain clear";
    }
    {
      file = "0153-crucible-close-inherited-child-descriptor-tables.patch";
      catalogName = "crucible-hot-fork-closed-child-descriptor-table";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12";
      capability = "the Linux-only unwired immediate-child primitive authenticates the exact parent generation, blocks signals, replaces both staged plugin endpoint slots, and applies a sorted bounded final table with close_range so every other inherited descriptor is closed; production coordinator admission closure, mapping disposition, child reinitialization, and readiness bits 7 and 8 remain open";
    }
    {
      file = "0154-crucible-close-fork-child-descriptor-admission.patch";
      catalogName = "crucible-hot-fork-child-descriptor-admission";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12";
      capability = "the Linux-only unwired one-shot child transaction proves close_range support, authenticates the exact immediate child, blocks every blockable signal before retain-table construction, consumes the parent anchor, and requires that exact transaction for closed-table application; mapping disposition, production fork composition, child reinitialization, and readiness bits 7 and 8 remain open";
    }
    {
      file = "0155-crucible-verify-fork-child-mapping-dispositions.patch";
      catalogName = "crucible-hot-fork-child-mapping-disposition";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12,HFORK-21,HFORK-22";
      capability = "after exact child descriptor closure, the Linux-only unwired one-shot verifier streams procfs without heap allocation under 65,536-record, 8-KiB-record, and 16-MiB aggregate bounds; private VMAs remain COW, read-only shared VMAs cannot mutate siblings, and every writable shared VMA must exactly match one sorted bounded branch-private allowlist range in both directions; production fork composition, child reinitialization, and readiness bits 7 and 8 remain open";
    }
    {
      file = "0156-crucible-authenticate-fork-child-shared-mapping-backings.patch";
      catalogName = "crucible-hot-fork-child-shared-backing-authentication";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12,HFORK-21,HFORK-22";
      capability = "the unwired child mapping verifier now requires every exact writable shared range to name a retained page-aligned offset in one shrink-sealed regular-file descriptor, then authenticates the procfs device/inode/offset tuple against fstat before accepting the VMA; a wrong same-sized backing consumes and rejects the child transaction; production fork composition, child reinitialization, and readiness bits 7 and 8 remain open";
    }
    {
      file = "0157-crucible-compose-fork-child-resource-disposition.patch";
      catalogName = "crucible-hot-fork-child-resource-transaction";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12,HFORK-21,HFORK-22";
      capability = "one unwired immediate-child transaction now preflights the complete retained descriptor and writable-shared mapping tables, closes descriptor admission, applies exact endpoint replacements and descriptor closure, invokes one held child reinitializer, and authenticates the resulting mapping table in that order; invalid tables preserve the active child transaction while any failure after replacement is destructive; production fork invocation, complete QEMU subsystem reinitialization, host continuation pairing, guest admission, and readiness bits 7 and 8 remain open";
    }
    {
      file = "0158-crucible-bind-hot-fork-source-mappings.patch";
      catalogName = "crucible-hot-fork-source-mapping-binding";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12,HFORK-21,HFORK-22";
      capability = "under one active retained template barrier, QEMU now streams procfs under fixed record and byte bounds and binds exactly one writable shared source VMA to the complete registered plugin setup-region device, inode, zero offset, and length; duplicate, partial, missing, malformed, and oversized mappings fail closed before child mutation; the version-3 private-ring stage exposes the exact process-local range needed to build a future child mapping allowlist, while production fork invocation, registered child-runtime composition, host continuation pairing, guest admission, and readiness bits 7 and 8 remain open";
    }
    {
      file = "0159-crucible-bind-child-runtime-source-mappings.patch";
      catalogName = "crucible-hot-fork-child-runtime-source-binding";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12,HFORK-21,HFORK-22";
      capability = "the fixed-layout version-3 registered child-runtime plan and status carry the exact authenticated source setup-region start, length, and zero file offset; QEMU rejects unaligned, overflowing, differently sized, or nonzero-offset geometry before callback invocation, and the plugin independently requires the plan to match its retained mapping owner before exact-address replacement; production fork invocation, complete registered-runtime composition, host continuation pairing, guest admission, and readiness bits 7 and 8 remain open";
    }
    {
      file = "0160-crucible-compose-registered-fork-child-runtime.patch";
      catalogName = "crucible-hot-fork-registered-child-runtime-composition";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12,HFORK-21,HFORK-22";
      capability = "QEMU now prepares a copied fixed-layout child-runtime plan and exposes a one-shot reinitializer for the destructive authenticated child resource transaction; initialization calls the process-global registered plugin runtime exactly once and accepts success only when the exact plan is echoed with callbacks held, the private mapping installed, every sealed worker parked, and no pending local operation; a real-fork unit path composes this adapter with exact descriptor closure and mapping verification, while production fork invocation, complete non-plugin subsystem reinitialization, host continuation pairing, guest admission, and readiness bits 7 and 8 remain open";
    }
    {
      file = "0161-crucible-bind-retained-plugin-child-plan.patch";
      catalogName = "crucible-hot-fork-retained-plugin-child-plan";
      class = "F";
      enforces = "HFORK-4,HFORK-8,HFORK-9,HFORK-10,HFORK-11,HFORK-12,HFORK-21,HFORK-22";
      capability = "QEMU now derives and copies the exact registered plugin child-runtime plan before admitting a retained endpoint stage, binds the checked adjacent parent and child process generations plus every template, ring, endpoint, barrier, mapping, descriptor, identity, and worker field into one unconsumed one-shot adapter, requires exact plan retention on idempotent staging, and clears the parent adapter on exact release; the version-14 template report exposes that plan binding without acknowledging descriptor/mapping bit 7 or child-reinitialization bit 8, while production fork invocation, complete non-plugin subsystem reinitialization, host continuation pairing, and guest admission remain open";
    }
  ];

  carriedPatchFiles = map (patch: patch.file) carriedPatches;
  seriesPatchFiles = series.patchFiles;

  noPatchDecisions = [
    {
      item = "T-PATCH-15";
      enforces = "PATCH-33";
      capability = "guest-to-host doorbell reuses upstream QEMU translated-instruction callbacks and virtual memory reads";
      evidence = "checks.crucible.phase1.qemuDoorbellNoPatch";
    }
    {
      item = "T-PATCH-18";
      enforces = "PATCH-36";
      capability = "diagnostic-only QEMU patches are absent from the shipped qemu-crucible package";
      evidence = "checks.crucible.phase1.qemuDiagnosticPatchesDevOnly";
    }
  ];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  qemuNixAppliesManifestSeries =
    hasInfix "patchCommand = file:" qemuNix
    && hasInfix "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)" qemuNix;

  missingCarriedPatches =
    builtins.filter (patch: !(builtins.elem patch patchFiles)) carriedPatchFiles;
  unmanifestedPatches =
    builtins.filter (patch: !(builtins.elem patch carriedPatchFiles)) patchFiles;
  uncatalogedPatches =
    builtins.filter
    (patch: !(hasInfix patch.catalogName qemuPatchSpec))
    carriedPatches;

  failures =
    map (patch: "tests/crucible/phase2-qemu-patch-series.nix: manifest references absent patch ${patch}")
    missingCarriedPatches
    ++ map (patch: "pkgs/emulation/qemu-patches/${patch}: carried patch is absent from the T-PATCH-1 manifest")
    unmanifestedPatches
    ++ lib.optionals (!qemuNixAppliesManifestSeries) [
      "pkgs/emulation/qemu.nix: QEMU patch phase must be generated from qemu-patches/_series.nix"
    ]
    ++ map (patch: "docs/rfcs/0010-crucible/11-qemu-patches.md: catalog missing carried patch name ${patch.catalogName}")
    uncatalogedPatches
    ++ lib.optionals (seriesPatchFiles != carriedPatchFiles) [
      "pkgs/emulation/qemu-patches/_series.nix: patch manifest does not match phase2 carried-patch catalog"
    ]
    ++ lib.optionals (!(hasInfix "series ? import ./qemu-patches/_series.nix" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU package must consume the patch-series manifest"
    ]
    ++ lib.optionals (!(hasInfix "version = series.qemuVersion;" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU version must be read from qemu-patches/_series.nix"
    ]
    ++ lib.optionals (!(hasInfix "hash = series.qemuSourceHash;" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU source hash must be read from qemu-patches/_series.nix"
    ]
    ++ lib.optionals (series.qemuVersion != "10.0.0") [
      "pkgs/emulation/qemu-patches/_series.nix: QEMU pin must be 10.0.0 for this carried series"
    ]
    ++ lib.optionals (series.qemuSourceHash != "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=") [
      "pkgs/emulation/qemu-patches/_series.nix: QEMU 10.0.0 source hash is not the recorded pin"
    ]
    ++ lib.optionals (!(hasInfix "pinned minimum QEMU version of 10.0 or" qemuPatchSpec)) [
      "docs/rfcs/0010-crucible/11-qemu-patches.md: PATCH-40 QEMU >=10.0 requirement missing"
    ]
    ++ lib.optionals (!(hasInfix "no QEMU patch was added" qemuPatchSpec)) [
      "docs/rfcs/0010-crucible/11-qemu-patches.md: T-PATCH-15 must state that no QEMU patch was added"
    ]
    ++ lib.optionals (hasInfix "crucible-tcg-exec-diag.patch" qemuNix || hasInfix "crucible-virtserial-socket.patch" qemuNix) [
      "pkgs/emulation/qemu.nix: diagnostic-only patches must not be applied by the shipped package"
    ]
    ++ lib.optionals (!(hasInfix "The pinned QEMU version MUST be" packagingSpec && hasInfix "10.0" packagingSpec)) [
      "docs/rfcs/0010-crucible/26-packaging-aos-integration.md: PKG-9 QEMU >=10.0 requirement missing"
    ]
    ++ lib.optionals (!(hasInfix "qemu_version=10.0.0" decisionRegister)) [
      "docs/rfcs/0010-crucible/31-decision-register.md: current QEMU version pin is not recorded"
    ]
    ++ lib.optionals (!(hasInfix "qemu_source_hash=sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=" decisionRegister)) [
      "docs/rfcs/0010-crucible/31-decision-register.md: current QEMU source hash pin is not recorded"
    ]
    ++ lib.optionals (!(hasInfix "missing_capability=distinct-errors" pluginFailLoudCheck)) [
      "tests/crucible/phase2-plugin-fail-loud.nix: missing required capabilities must produce distinct diagnostics"
    ]
    ++ lib.optionals (!(hasInfix "wall_clock_fallback=forbidden" pluginFailLoudCheck)) [
      "tests/crucible/phase2-plugin-fail-loud.nix: wall-clock fallback must be forbidden when capability setup fails"
    ]
    ++ lib.optionals (!(hasInfix "registration_order_fails_loud_when_exact_deadline_capability_missing" pluginFailLoudCheck)) [
      "tests/crucible/phase2-plugin-fail-loud.nix: exact-deadline capability failure is not covered"
    ]
    ++ lib.optionals (!(hasInfix "registration_order_fails_loud_when_queued_idle_advance_missing" pluginFailLoudCheck)) [
      "tests/crucible/phase2-plugin-fail-loud.nix: queued idle-advance capability failure is not covered"
    ]
    ++ lib.optionals (!(hasInfix "registration_coverage_on_requires_basic_block_callback_capability" pluginFailLoudCheck)) [
      "tests/crucible/phase2-plugin-fail-loud.nix: coverage-on TCG exec capability failure is not covered"
    ];

  manifestLines =
    lib.concatMapStringsSep "\n" (patch: ''
      echo "patch=${patch.file}"
      echo "catalog_name=${patch.catalogName}"
      echo "class=${patch.class}"
      echo "enforces=${patch.enforces}"
      echo "capability=${patch.capability}"
      echo
    '')
    carriedPatches;

  noPatchDecisionLines =
    lib.concatMapStringsSep "\n" (decision: ''
      echo "no_patch_item=${decision.item}"
      echo "no_patch_enforces=${decision.enforces}"
      echo "no_patch_capability=${decision.capability}"
      echo "no_patch_evidence=${decision.evidence}"
      echo
    '')
    noPatchDecisions;
in
  if failures != []
  then throw "crucible phase2 QEMU patch-series conformance failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-patch-series";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.gawk
        pkgs.grep
      ];

      phases = [
        {
          name = "check-qemu-patch-series";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            mkdir -p "$out"

            for patch in ${builtins.concatStringsSep " " carriedPatchFiles}; do
              case "$patch" in
                [0-9][0-9][0-9][0-9]-crucible-*.patch) ;;
                *) fail "patch name is not stable NNNN-crucible-*.patch: $patch" ;;
              esac

              file="${patchDir}/$patch"
              [ -f "$file" ] || fail "missing patch file: $patch"

              if grep -E '^\+.*(crucible-replay-start|replay_configure|replay_add|replay_save|replay_read|REPLAY_MODE_RECORD|REPLAY_MODE_PLAY)' "$file"; then
                fail "record/replay-start scaffolding added by $patch"
              fi
            done

            cat > "$out/manifest" <<'MANIFEST'
            ${manifestLines}
            MANIFEST

            cat > "$out/no-patch-decisions" <<'NO_PATCH_DECISIONS'
            ${noPatchDecisionLines}
            NO_PATCH_DECISIONS

            awk '
              /^patch=/ { patch = $0 }
              /^class=/ {
                if ($0 != "class=D" && $0 != "class=F") {
                  printf "bad patch class after %s: %s\n", patch, $0 > "/dev/stderr"
                  exit 1
                }
              }
              /^enforces=/ {
                if ($0 == "enforces=") {
                  printf "missing invariant after %s\n", patch > "/dev/stderr"
                  exit 1
                }
              }
            ' "$out/manifest"

            cp "${qemuPluginFailLoud}/result" "$out/qemu-plugin-fail-loud.result"
            grep -q '^PASS$' "$out/qemu-plugin-fail-loud.result"
            grep -q '^missing_capability=distinct-errors$' "$out/qemu-plugin-fail-loud.result"
            grep -q '^wall_clock_fallback=forbidden$' "$out/qemu-plugin-fail-loud.result"

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            qemu_version=${series.qemuVersion}
            qemu_minimum_version=10.0.0
            qemu_minimum_version_satisfied=true
            qemu_source_hash=${series.qemuSourceHash}
            gate=gate:patch-series
            carried_patch_count=${toString (builtins.length carriedPatches)}
            plugin_api_capability_catalog_count=${toString (builtins.length carriedPatches)}
            patches=${builtins.concatStringsSep "," carriedPatchFiles}
            patch_manifest=pkgs/emulation/qemu-patches/_series.nix
            patch_manifest_matches_carried_catalog=true
            stable_numeric_crucible_patch_names=true
            significant_order_is_manifested=true
            qemu_package_patch_phase_generated_from_manifest=true
            every_carried_patch_has_class=true
            every_carried_patch_has_invariant_or_capability=true
            qemu_package_applies_manifested_series=true
            record_replay_start_scaffolding_absent=true
            no_patch_decisions=${builtins.concatStringsSep "," (map (decision: decision.item) noPatchDecisions)}
            no_patch_evidence=${builtins.concatStringsSep "," (map (decision: decision.evidence) noPatchDecisions)}
            missing_required_capability_check=checks.crucible.phase2.qemuPluginFailLoud
            qemu_plugin_fail_loud_gate_passed=true
            missing_required_capability_fails_loud=true
            RESULT
          '';
        }
      ];
    }
