{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginQuantumSmp",
  taskIds ? ["T-PLUG-24"],
}: let
  fullSeries = import ../../pkgs/emulation/qemu-patches/_series.nix;
  smpGuest = import ./phase2-qemu-live-plugin-quantum-smp-guest.nix {inherit pkgs;};
  liveQuantumSmp = import ./phase2-qemu-live-plugin-quantum.nix {
    inherit pkgs lib;
    attrPath = "${attrPath}.live";
    taskIds = [];
    openTaskIds = [];
    smpVcpus = "4";
    memoryMib = "64";
    requireSmpPauseRendezvous = "1";
    maxSearch = "80000000";
    idleHorizonMargin = "80000000";
    customGuestKernel = "${smpGuest}/smp-idle-guest.elf";
  };
  qemuEarlyPauseYieldTrap = pkgs.qemuCrucibleNonDistributableTestPrefix {
    pname = "qemu-crucible-early-pause-yield-trap";
    series = fullSeries;
    testOnlyPostPatch = ./fixtures/qemu-trap-early-pause-yield.patch;
  };
  pluginEarlyPauseYieldTrap = pkgs.crucibleQemuPluginFor qemuEarlyPauseYieldTrap;
  earlyPauseYieldNegative = import ./phase2-qemu-live-plugin-quantum.nix {
    inherit pkgs lib;
    attrPath = "${attrPath}.earlyPauseYieldNegative";
    taskIds = [];
    openTaskIds = [];
    smpVcpus = "4";
    memoryMib = "64";
    requireSmpPauseRendezvous = "1";
    secondRunSchedulerPreemption = "0";
    maxSearch = "80000000";
    idleHorizonMargin = "80000000";
    customGuestKernel = "${smpGuest}/smp-idle-guest.elf";
    qemuPackage = qemuEarlyPauseYieldTrap;
    pluginPackage = pluginEarlyPauseYieldTrap;
    expectedQemuFailureMarker = "CRUCIBLE_TEST_CRITICAL_EARLY_PAUSE_YIELD_REACHED";
    expectedQemuFailureProvenance = "AAAB-issued-before-critical-arm";
  };

  pluginDoc = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  idlePatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0025-crucible-sim-idle-callbacks.patch;
  haltedRrPatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0110-crucible-release-halted-rr-turn.patch;
  earlyPauseTrapPatch = builtins.readFile ./fixtures/qemu-trap-early-pause-yield.patch;
  smpGuestSource = builtins.readFile ./phase2-qemu-live-plugin-quantum-smp-guest.nix;
  quantumGate = builtins.readFile ./phase2-qemu-live-plugin-quantum.nix;
  nodeSource = builtins.readFile ../../crates/crucible-qemu/src/node.rs;
  hostRuntimeSource = builtins.readFile ../../crates/crucible-qemu/src/supervision/host_io_runtime.rs;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginDoc [
      {
        label = "live SMP idle completion gate";
        needle = "checks.crucible.phase2.qemuLivePluginQuantumSmp";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0025-crucible-sim-idle-callbacks.patch" idlePatch [
      {
        label = "all-vCPU idle predicate";
        needle = "rr_crucible_sim_all_vcpus_halted";
      }
      {
        label = "all-idle callback dispatch";
        needle = "qemu_plugin_maybe_fire_vcpu_idle_cb(cpu);";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0110-crucible-release-halted-rr-turn.patch" haltedRrPatch [
      {
        label = "halted partial RR turn escape";
        needle = "if (rr_crucible_sim_vcpu_is_halted(cpu))";
      }
      {
        label = "all-halted callback handoff";
        needle = "the canonical idle boundary";
      }
      {
        label = "exact completed-turn register capture";
        needle = "current_cpu && owner == UINT64_MAX";
      }
      {
        label = "zero-cursor serialized handoff";
        needle = "cursor_position == 0";
      }
      {
        label = "guest PAUSE canonical handoff";
        needle = "icount_crucible_rr_yield_cpu(cpu);";
      }
      {
        label = "guest PAUSE explicit marker";
        needle = "cs->crucible_guest_pause_yield = true;";
      }
      {
        label = "guest PAUSE marker consumed";
        needle = "cpu->crucible_guest_pause_yield = false;";
      }
      {
        label = "generic interrupt excluded";
        needle = "guest_pause_yield &&";
      }
      {
        label = "guest PAUSE committed before host-work exits";
        needle = "Commit the helper-authenticated PAUSE transition before any";
      }
      {
        label = "guest PAUSE owner handoff";
        needle = "if (owner == cpu->cpu_index)";
      }
      {
        label = "guest PAUSE control-boundary fence begin";
        needle = "qemu_plugin_crucible_guest_pause_handoff_begin();";
      }
      {
        label = "guest PAUSE control-boundary fence completion";
        needle = "qemu_plugin_crucible_guest_pause_handoff_complete();";
      }
      {
        label = "completed quantum avoids double handoff";
        needle = "else if (cursor != 0)";
      }
    ]
    ++ lib.optional
    (hasInfix "cpu && !cpu->exit_request && !cpu->stop && !cpu->unplug" haltedRrPatch)
    "pkgs/emulation/qemu-patches/0110-crucible-release-halted-rr-turn.patch: guest PAUSE handoff is incorrectly conditional on late host work"
    ++ failuresFor "tests/crucible/fixtures/qemu-trap-early-pause-yield.patch" earlyPauseTrapPatch [
      {
        label = "critical PAUSE test-only arm";
        needle = "crucible_test_critical_pause_armed";
      }
      {
        label = "critical PAUSE guest marker";
        needle = "port == 0x80 && value == 0xa7";
      }
      {
        label = "critical partial-yield abort marker";
        needle = "CRUCIBLE_TEST_CRITICAL_EARLY_PAUSE_YIELD_REACHED";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-live-plugin-quantum-smp-guest.nix" smpGuestSource [
      {
        label = "directed AP startup";
        needle = "directed-init-sipi-sipi";
      }
      {
        label = "all-vCPU HLT workload";
        needle = "guest_idle=all-vcpus-hlt";
      }
      {
        label = "live PIT deadline";
        needle = ''then "periodic-pit-channel-0"'';
      }
      {
        label = "compact high ELF load layout";
        needle = "Keep every ELF PT_LOAD segment above the option-ROM window";
      }
      {
        label = "runtime AP trampoline copy";
        needle = "movl $ap_trampoline_start, %esi";
      }
      {
        label = "AP lock contention before handoff";
        needle = "ap_acquire_handoff_lock:";
      }
      {
        label = "BSP observes every AP online";
        needle = "wait_for_all_aps_online:";
      }
      {
        label = "PAUSE immediate reacquire negative";
        needle = "lock cmpxchgw %cx, 0x7002";
      }
      {
        label = "critical PAUSE negative armed after AAAB";
        needle = ''
          movb $'B', %al
                  call serial_byte

                  /*
                   * This otherwise inert POST-port write arms only the test-only QEMU
        '';
      }
      {
        label = "PAUSE handoff failure marker";
        needle = "movb $'F', %al";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-live-plugin-quantum.nix" quantumGate [
      {
        label = "SMP vCPU launch control";
        needle = "CRUCIBLE_QUANTUM_SMP_VCPUS = smpVcpus;";
      }
      {
        label = "all-vCPUs-halted live result assertion";
        needle = "all_vcpus_halted_idle_observed=true";
      }
      {
        label = "live guest PAUSE rendezvous assertion";
        needle = "guest_smp_pause_rendezvous_observed=true";
      }
      {
        label = "exact production fingerprint regression";
        needle = "stale_execution_fingerprint_requests_production_control_boundary";
      }
      {
        label = "test-only QEMU package injection";
        needle = "qemuPackage ? pkgs.qemu-crucible";
      }
      {
        label = "causal QEMU failure marker";
        needle = "EXPECTED_QEMU_FAILURE_MARKER";
      }
      {
        label = "causal QEMU failure provenance";
        needle = "EXPECTED_QEMU_FAILURE_PROVENANCE";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" nodeSource [
      {
        label = "node requests stale fingerprint boundary";
        needle = ".publish_current_execution_fingerprint(remaining)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/supervision/host_io_runtime.rs" hostRuntimeSource [
      {
        label = "production fingerprint control request";
        needle = "fn publish_current_execution_fingerprint(";
      }
      {
        label = "production fingerprint ack ownership";
        needle = "control_boundary_request_is_acknowledged(request, &snapshot)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "live SMP quantum gate import";
        needle = "qemuLivePluginQuantumSmp = import ./phase2-qemu-live-plugin-quantum-smp.nix";
      }
    ];
in
  if failures != []
  then throw "crucible live SMP plugin quantum check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-live-plugin-quantum-smp";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        earlyPauseYieldNegative
        liveQuantumSmp
      ];

      phases = [
        {
          name = "run-live-smp-plugin-quantum";
          script = ''
            set -eu
            grep -Fxq PASS ${liveQuantumSmp}/result
            grep -Fxq 'smp_vcpus=4' ${liveQuantumSmp}/result
            grep -Fxq 'memory_mib=64' ${liveQuantumSmp}/result
            grep -Fxq 'all_vcpus_halted_idle_observed=true' ${liveQuantumSmp}/result
            grep -Fxq 'guest_smp_pause_rendezvous_observed=true' ${liveQuantumSmp}/result
            grep -Fxq 'idle_kind=timer-deadline' ${liveQuantumSmp}/result
            grep -Fxq 'idle_jump_proven=true' ${liveQuantumSmp}/result
            grep -Fxq 'deterministic_under_scheduler_preemption=true' ${liveQuantumSmp}/result
            grep -Fxq 'host_adversary=bounded-scheduler-preemption' ${liveQuantumSmp}/result
            grep -Fxq 'sim_double_schedule_matches=true' ${liveQuantumSmp}/result
            grep -Fxq 'guest_load_segments=compact-high-only' ${smpGuest}/evidence.env
            grep -Fxq PASS ${earlyPauseYieldNegative}/result
            grep -Fxq \
              'expected_qemu_failure_marker=CRUCIBLE_TEST_CRITICAL_EARLY_PAUSE_YIELD_REACHED' \
              ${earlyPauseYieldNegative}/result
            grep -Fxq \
              'expected_qemu_failure_provenance=AAAB-issued-before-critical-arm' \
              ${earlyPauseYieldNegative}/result

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            live_backend=qemu-system-x86_64
            smp_vcpus=4
            memory_mib=64
            rr_subdivision=fixed-quantum-ascending
            all_vcpus_halted_idle_observed=true
            halted_partial_rr_turn_reaches_idle=true
            guest_pause_rr_handoff=canonical-cursor-zero
            guest_pause_classification=dedicated-transient-marker
            guest_pause_rendezvous=release-pause-immediate-reacquire-fails-before-ap-lock-chain
            guest_pause_early_yield_negative=critical-arm-branch-trap-observed-after-AAAB
            guest_smp_pause_rendezvous_observed=true
            ap_trampoline=high-load-copy-to-sipi-vector
            guest_load_segments=compact-high-only
            exact_rr_handoff_register_capture=safe-zero-cursor
            idle_wake=minimum-live-timer-deadline
            deterministic_under_scheduler_preemption=true
            host_adversary=bounded-scheduler-preemption
            RESULT
          '';
        }
      ];
    }
