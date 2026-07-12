{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.layer0Determinism",
  taskIds ? ["T-DET-10"],
  openTaskIds ? ["T-TIME-8" "T-TIME-9" "T-DET-30" "T-DET-31"],
  dependencies ? [],
}: let
  deterministicLaunch = import ./phase1-deterministic-launch.nix {inherit pkgs lib;};
  qemuDeterministicEntropy = import ./phase1-qemu-deterministic-entropy.nix {inherit pkgs lib;};
  qemuDeterministicGetrandom = import ./phase1-qemu-deterministic-getrandom.nix {inherit pkgs lib;};
  guestEntropyLaunch = import ./phase1-guest-entropy-launch.nix {inherit pkgs lib;};
  kaslrAslrDefault = import ./phase1-kaslr-aslr-default.nix {inherit pkgs lib;};
  decisionRecording = import ./phase1-decision-recording.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase1.decisionRecording";
    taskIds = [];
    openTaskIds = ["T-DET-31"];
  };
  contractAIsolation = import ./phase1-contract-a-isolation.nix {inherit pkgs lib;};
  qemuMultiVcpuLaunch = import ./phase2-qemu-multi-vcpu-launch.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase1.qemuMultiVcpuLaunch";
    taskIds = ["T-DET-29"];
    openTaskIds = ["T-DET-30"];
  };
  qemuPluginPreemption = import ./phase2-plugin-preemption.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase1.qemuPluginPreemption";
    taskIds = [];
    openTaskIds = ["T-DET-30" "T-PLUG-25"];
  };
  qemuPluginAppRandomDoorbell = import ./phase2-plugin-app-random-doorbell.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase1.qemuPluginAppRandomDoorbell";
    taskIds = [];
    openTaskIds = ["T-DET-31" "T-PLUG-27"];
  };
  timeContractADeterminism = import ./phase1-time-contract-a-determinism.nix {inherit pkgs lib;};
  timeMultiVcpuAggregateClock = import ./phase1-time-multi-vcpu-aggregate-clock.nix {inherit pkgs lib;};
  clockDeadline = import ./phase1-clock-deadline.nix {inherit pkgs lib;};
  noWarpWithPlugin = import ./phase1-no-warp-with-plugin.nix {inherit pkgs lib;};
  pluginTimeAdvance = import ./phase1-plugin-time-advance.nix {inherit pkgs lib;};
  icountNoRealtime = import ./phase1-icount-no-realtime.nix {inherit pkgs lib;};
  blockRtcRead = import ./phase1-block-rtc-read.nix {inherit pkgs lib;};
  singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix {inherit pkgs lib;};

  simGate = builtins.readFile ../../crates/crucible-sim/tests/gate_layer0_determinism.rs;
  engineGate = builtins.readFile ../../crates/crucible/tests/gate_layer0_determinism.rs;
  assertGate = builtins.readFile ../../crates/crucible-assert/tests/gate_layer0_determinism.rs;
  assertLib = builtins.readFile ../../crates/crucible-assert/src/lib.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "crates/crucible-sim/tests/gate_layer0_determinism.rs" simGate [
      {
        label = "reduce-twice Contract A gate test";
        needle = "gate_layer0_determinism_reduces_fixed_contract_a_twice";
      }
      {
        label = "fixed input sensitivity";
        needle = "gate_layer0_determinism_is_sensitive_to_each_fixed_input";
      }
      {
        label = "named decision stream stability";
        needle = "gate_layer0_determinism_keeps_named_streams_stable_under_entity_addition";
      }
      {
        label = "recorded input ordering rejection";
        needle = "gate_layer0_determinism_rejects_unordered_recorded_inputs";
      }
    ]
    ++ forbiddenFor "crates/crucible-sim/tests/gate_layer0_determinism.rs" simGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_layer0_determinism.rs" engineGate [
      {
        label = "sim backend reduce-twice gate test";
        needle = "gate_layer0_determinism_reduces_sim_backend_twice";
      }
      {
        label = "explicit schedule ordering";
        needle = "gate_layer0_determinism_keeps_schedule_decisions_explicitly_ordered";
      }
      {
        label = "scheduler total-order property";
        needle = "gate_layer0_determinism_orders_scheduler_event_keys_canonically";
      }
      {
        label = "prefix rejection property";
        needle = "gate_layer0_determinism_rejects_implicit_schedule_prefixes";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_layer0_determinism.rs" engineGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "crates/crucible-assert/src/lib.rs" assertLib [
      {
        label = "assertion vocabulary version";
        needle = "ASSERTION_VOCABULARY_VERSION";
      }
      {
        label = "assertion kind data contract";
        needle = "pub enum AssertionKind";
      }
      {
        label = "assertion spec data contract";
        needle = "pub struct AssertionSpec";
      }
    ]
    ++ failuresFor "crates/crucible-assert/tests/gate_layer0_determinism.rs" assertGate [
      {
        label = "canonical assertion ids";
        needle = "gate_layer0_determinism_assertion_ids_are_canonical";
      }
      {
        label = "stable assertion ordering";
        needle = "gate_layer0_determinism_assertion_order_is_stable";
      }
      {
        label = "ambiguous subject rejection";
        needle = "gate_layer0_determinism_assertions_reject_ambiguous_subjects";
      }
    ]
    ++ forbiddenFor "crates/crucible-assert/tests/gate_layer0_determinism.rs" assertGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "crucible-sim layer0 target implemented";
        needle = "package: \"crucible-sim\",\n        test_target: \"gate_layer0_determinism\",\n        required_features: &[],\n        placeholder: false,";
      }
      {
        label = "crucible-assert layer0 target implemented";
        needle = "package: \"crucible-assert\",\n        test_target: \"gate_layer0_determinism\",\n        required_features: &[],\n        placeholder: false,";
      }
      {
        label = "crucible layer0 target implemented";
        needle = "package: \"crucible\",\n        test_target: \"gate_layer0_determinism\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented canonical layer0 gate status";
        needle = "name: \"gate:layer0-determinism\",\n        phase: GatePhase::Phase1,\n        owner: \"crucible-sim\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "layer0 implemented status assertion";
        needle = "find_gate(\"gate:layer0-determinism\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented layer0 targets in Nix lint";
        needle = "placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=2";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes layer0 determinism check";
        needle = "layer0Determinism = import ./phase1-layer0-determinism.nix";
      }
      {
        label = "layer0 gate no longer uses red placeholder";
        needle = "attrPath = \"checks.crucible.phase1.gates.layer0Determinism\"";
      }
      {
        label = "layer0 gate lists T-DET-10";
        needle = "\"T-DET-10\"";
      }
      {
        label = "phase1 exposes multi-vCPU launch evidence";
        needle = "qemuMultiVcpuLaunch = import ./phase2-qemu-multi-vcpu-launch.nix";
      }
      {
        label = "phase1 exposes deterministic IPI evidence";
        needle = "qemuPluginPreemption = import ./phase2-plugin-preemption.nix";
      }
      {
        label = "phase1 exposes app-random doorbell evidence";
        needle = "qemuPluginAppRandomDoorbell = import ./phase2-plugin-app-random-doorbell.nix";
      }
      {
        label = "phase1 exposes decision recording evidence";
        needle = "decisionRecording = import ./phase1-decision-recording.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-10 checklist complete";
        needle = "- [x] **T-DET-10**";
      }
      {
        label = "T-DET-30 remains open";
        needle = "- [ ] **T-DET-30**";
      }
      {
        label = "T-DET-31 remains open";
        needle = "- [ ] **T-DET-31**";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 layer0 determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-layer0-determinism";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ] ++ dependencies;

      phases = [
        {
          name = "record-layer0-determinism";
          script = ''
            set -eu
            mkdir -p "$out"

            require_line() {
              result="$1/result"
              line="$2"
              grep -Fxq "$line" "$result" || {
                echo "dependency missing evidence: $line" >&2
                cat "$result" >&2
                exit 1
              }
            }

            require_leaf() {
              dependency="$1"
              shift
              require_line "$dependency" "PASS"
              for line in "$@"; do
                require_line "$dependency" "$line"
              done
            }

            require_leaf ${deterministicLaunch} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-1" \
              "cpu=qemu64,-rdrand,-rdseed" \
              "accelerator=sim,thread=single" \
              "accelerator_family=tcg-derived-sim" \
              "simulation_mode=on" \
              "stock_tcg_crucible_runtime=forbidden" \
              "smp_vcpus=1" \
              "icount=shift=0,sleep=off,align=off,rr_switch_quantum=4096" \
              "rtc=base=2026-01-01T00:00:00,clock=vm" \
              "timers=virtual-clock-driven" \
              "interrupt_timing=icount-tb-boundaries" \
              "virtual_time_ns=icount<<shift" \
              "tsc_source=icount" \
              "machine_reset=deterministic-zeroed-ram-fixed-devices" \
              "ram_reset=zeroed-fresh-anonymous-memory" \
              "input_policy=no-interactive-input"
            require_leaf ${qemuDeterministicEntropy} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-4" \
              "qemu_seed_option_controls_guest_random=true" \
              "qemu_thread_seed_part1_uses_deterministic_guest_random=true" \
              "qemu_thread_seed_part2_gated_by_deterministic_guest_random=true" \
              "qemu_seed_option_controls_glib_global_prng=true" \
              "patched_fixture_exercised=true"
            require_leaf ${qemuDeterministicGetrandom} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-4,T-DET-5" \
              "qemu_guest_getrandom_sim_unseeded_policy=fail_closed" \
              "sim_unseeded_guest_random_fails_closed=true" \
              "sim_unseeded_host_entropy_calls=0" \
              "host_entropy_calls_under_seed=0" \
              "non_sim_unseeded_guest_random_uses_host_crypto=true"
            require_leaf ${guestEntropyLaunch} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-5" \
              "firmware_seed_source=scenario-seed" \
              "hwrng_same_seed_reproducible=true" \
              "guest_csprng_same_seed_reproducible=true" \
              "cpu_entropy_features=rdrand-disabled,rdseed-disabled" \
              "guest_entropy_seal=host-side-qemu-icount-seeded-entropy" \
              "host_guest_entropy_sources=disabled"
            require_leaf ${kaslrAslrDefault} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-6" \
              "global_default=stock-no-entropy-suppression" \
              "determinism_mechanism=host-side-qemu-icount-seeded-entropy"
            require_leaf ${decisionRecording} \
              "gate=gate:layer0-determinism" \
              "tasks=" \
              "open_tasks=T-DET-31" \
              "status=partial" \
              "rng_source=crucible-sim::DecisionRng" \
              "app_random_source=single-seeded-decision-rng" \
              "app_random_stream_fork=per-node-stream-name" \
              "app_random_records=RngDraw+Decision::AppRandom" \
              "app_random_request_id=caller-supplied" \
              "app_random_override=recorded-value-no-reroll" \
              "engine_ambient_randomness=false" \
              "ambient_fw_cfg_entropy=separate-launch-entropy"
            require_leaf ${contractAIsolation} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-7,T-DET-28" \
              "driver=crucible-sim::contract_a::ContractADriver" \
              "inputs=icount-stamped-recorded-list" \
              "live_scheduler_transport=false" \
              "rr_vcpu_cursor=fixed-content-addressed" \
              "multi_vcpu_fingerprint=per-vcpu-register-files-plus-rr-cursor" \
              "aggregate_icount_trajectory=bit-identical-across-runs" \
              "recorded_inputs_enforced=monotonic-within-run"
            require_leaf ${qemuMultiVcpuLaunch} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-29" \
              "open_tasks=T-DET-30" \
              "status=partial" \
              "accelerator=sim,thread=single" \
              "accelerator_family=tcg-derived-sim" \
              "stock_tcg_crucible_runtime=forbidden" \
              "smp_vcpus=N>=1" \
              "rr_switch_quantum=content-addressed-node-icount" \
              "rr_vcpu_rotation=ascending-vcpu-id" \
              "cpu_model_scope=uniform-all-vcpus" \
              "per_vcpu_tsc_source=node-icount" \
              "per_vcpu_rng_source=scenario-seed-and-run-seed" \
              "per_vcpu_rng_timing_axis=node-icount" \
              "vcpu_topology=fixed-at-genesis" \
              "runtime_cpu_hotplug=false" \
              "secondary_vcpu_bringup=rr-sim-tcg-icount-deterministic" \
              "rejects_mttcg=true" \
              "rejects_unpinned_rr_switch_quantum=true" \
              "rejects_adaptive_rr_quantum=true" \
              "rejects_realtime_switching=true" \
              "scenario_hash_folds=smp_vcpus,rr_switch_quantum,rr_vcpu_rotation,cpu_model,per_vcpu_entropy,vcpu_topology"
            require_leaf ${qemuPluginPreemption} \
              "gate=gate:layer0-determinism" \
              "tasks=" \
              "open_tasks=T-DET-30,T-PLUG-25" \
              "status=partial" \
              "preemption_capability=qemu_plugin_inject_preemption" \
              "dispatch=vCPU-switch-or-interrupt-at-commanded-icount" \
              "deterministic_ipi_delivery=sender-icount-plus-fixed-latency-next-rr-switch" \
              "ipi_latency_model=fixed-node-icount" \
              "ipi_delivery_path=preemption-injector-commanded-icount" \
              "ipi_realtime_delivery=false"
            require_leaf ${qemuPluginAppRandomDoorbell} \
              "gate=gate:layer0-determinism" \
              "tasks=" \
              "open_tasks=T-DET-31,T-PLUG-27" \
              "status=partial" \
              "doorbell_kind=random_request" \
              "whitebox_opt_in=required" \
              "decision=Decision::AppRandom" \
              "source=seeded-decision-source-trait" \
              "reply=trap-icount-host-to-guest-injection" \
              "zero_requests=no-decisions-no-replies" \
              "zero_requests_byte_identical=true" \
              "ambient_fw_cfg_entropy=not-app-random-source"
            require_leaf ${timeContractADeterminism} \
              "gate=gate:layer0-determinism" \
              "tasks=" \
              "open_tasks=T-TIME-8" \
              "status=partial" \
              "time_trajectory=icount_shift_pure_function" \
              "time_fingerprint_fields=final_icount,final_virtual_time_ns,trajectory_digest,time_derived_fields_digest" \
              "host_time_reads_on_time_path=false"
            require_leaf ${timeMultiVcpuAggregateClock} \
              "gate=gate:layer0-determinism" \
              "tasks=" \
              "open_tasks=T-TIME-9" \
              "status=partial" \
              "aggregate_node_clock=true" \
              "per_vcpu_shmem_fields=false" \
              "rr_switch_quantum_units=node-icount" \
              "multi_vcpu_deadline=min-armed-vcpu-deadline"
            require_leaf ${clockDeadline} \
              "gate=gate:layer0-determinism" \
              "gate=gate:scheduler-liveness" \
              "tasks=T-PATCH-10,T-TIME-6" \
              "open_tasks=" \
              "status=partial" \
              "deadline_symbol=qemu_plugin_clock_deadline_ns" \
              "deadline_source=QEMU_CLOCK_VIRTUAL" \
              "deadline_delta_ns=123456" \
              "virtual_timer_armed=true" \
              "guest_idle_for_deadline_query=true" \
              "min_virtual_timer_selected=true" \
              "realtime_deadline_source=false" \
              "host_deadline_source=false" \
              "capability_required=true" \
              "missing_capability_fails_closed=true" \
              "install_missing_deadline_isolated=true" \
              "overshoot_and_correct_fallback=false" \
              "patch41_upstream_api_absent_documented=true" \
              "scheduler_liveness_gate_consumed=true" \
              "scheduler_horizon_exact_local_event=true"
            require_leaf ${noWarpWithPlugin} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-3" \
              "time_control_predicate=qemu_plugin_has_time_control" \
              "wall_clock_warp_under_time_control=false" \
              "notify_preserved_under_time_control=true"
            require_leaf ${pluginTimeAdvance} \
              "gate.layer0=gate:layer0-determinism" \
              "qemu_time_control_public_predicate=true" \
              "qemu_time_control_single_owner=true" \
              "qemu_time_advance_callback_enqueue_only=true" \
              "qemu_time_advance_cpu_work_handoff=true" \
              "qemu_time_advance_runs_virtual_timers=true" \
              "qemu_time_advance_completion_bh=true" \
              "qemu_time_advance_two_stage_bh_barrier=true" \
              "timer_bh_precedes_plugin_completion=true" \
              "qemu_main_loop_reentry_from_callback=false"
            require_leaf ${icountNoRealtime} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-2" \
              "qemu_mode=ICOUNT_PRECISE" \
              "realtime_deadline_in_precise_budget=false"
            require_leaf ${blockRtcRead} \
              "gate=gate:layer0-determinism" \
              "tasks=T-DET-8" \
              "guest_realtime_source=fixed_epoch_plus_virtual_clock" \
              "direct_cmos_rtc_source=fixed_epoch_plus_virtual_clock" \
              "non_sim_realtime_source=upstream" \
              "residual_host_clock_read_under_sim=false"
            require_leaf ${singleVmFingerprint} \
              "gate=gate:single-vm-fingerprint" \
              "real_qemu_source=checks.crucible.phase0.s1Fingerprint" \
              "run_model=run-twice-and-diff" \
              "scenario=stock-linux-diskless-initramfs-workload" \
              "host_adversary=jitter-load" \
              "samples=32" \
              "horizon_icount=3200000000" \
              "mismatch_policy=first-mismatch-is-failure"

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:layer0-determinism
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            status=partial
            crates=crucible-sim,crucible-assert,crucible
            cargo_targets=crucible-sim::gate_layer0_determinism,crucible-assert::gate_layer0_determinism,crucible::gate_layer0_determinism
            aggregate_model=leaf-evidence-plus-crate-gate-targets
            reduce_twice_digest_compare=true
            scheduler_ordering_properties=true
            decision_stream_entity_addition_stability=true
            elimination_sources=E1,E2,E3,E4,E5,E6,E7,E8,E9,E10,E13,E14,E15,E16,E17,E22,E23,E24
            evidence.E1=deterministicLaunch.cpu+guestEntropyLaunch.cpu_entropy_features
            evidence.E2=noWarpWithPlugin.wall_clock_warp_under_time_control
            evidence.E3=icountNoRealtime.realtime_deadline_in_precise_budget
            evidence.E4=deterministicLaunch.tsc_source
            evidence.E5=deterministicLaunch.rtc+blockRtcRead.guest_realtime_source+blockRtcRead.direct_cmos_rtc_source
            evidence.E6=deterministicLaunch.timers
            evidence.E7=deterministicLaunch.interrupt_timing
            evidence.E8=guestEntropyLaunch.firmware_seed_source+guest_csprng_same_seed_reproducible
            evidence.E9=qemuDeterministicEntropy.qemu_seed_option_controls_guest_random+qemu_seed_option_controls_glib_global_prng+qemuDeterministicGetrandom.qemu_guest_getrandom_sim_unseeded_policy
            evidence.E10=deterministicLaunch.cpu+singleVmFingerprint.run_model
            evidence.E13=deterministicLaunch.smp_vcpus+qemuMultiVcpuLaunch.rr_switch_quantum+qemuMultiVcpuLaunch.rr_vcpu_rotation+qemuMultiVcpuLaunch.rejects_mttcg+contractAIsolation.rr_vcpu_cursor+contractAIsolation.multi_vcpu_fingerprint+timeMultiVcpuAggregateClock.aggregate_node_clock
            evidence.E14=noWarpWithPlugin.time_control_predicate+notify_preserved_under_time_control+pluginTimeAdvance.qemu_time_advance_completion_bh+clockDeadline.deadline_source
            evidence.E15=deterministicLaunch.cpu+singleVmFingerprint.run_model
            evidence.E16=deterministicLaunch.machine_reset+ram_reset
            evidence.E17=deterministicLaunch.input_policy+contractAIsolation.recorded_inputs_enforced
            evidence.E22=qemuPluginPreemption.deterministic_ipi_delivery+ipi_delivery_path+ipi_realtime_delivery
            evidence.E23=qemuMultiVcpuLaunch.cpu_model_scope+per_vcpu_tsc_source+per_vcpu_rng_source+per_vcpu_rng_timing_axis+qemuDeterministicEntropy.qemu_seed_option_controls_guest_random+qemuDeterministicGetrandom.qemu_guest_getrandom_sim_unseeded_policy
            evidence.E24=qemuMultiVcpuLaunch.vcpu_topology+runtime_cpu_hotplug+secondary_vcpu_bringup
            evidence.DET44=decisionRecording.app_random_source+app_random_stream_fork+app_random_records+qemuPluginAppRandomDoorbell.whitebox_opt_in+zero_requests_byte_identical+guestEntropyLaunch.firmware_seed_source
            app_random_ambient_fw_cfg_distinct=true
            leaf_checks=deterministicLaunch,qemuDeterministicEntropy,qemuDeterministicGetrandom,guestEntropyLaunch,kaslrAslrDefault,decisionRecording,contractAIsolation,qemuMultiVcpuLaunch,qemuPluginPreemption,qemuPluginAppRandomDoorbell,timeContractADeterminism,timeMultiVcpuAggregateClock,clockDeadline,noWarpWithPlugin,pluginTimeAdvance,icountNoRealtime,blockRtcRead,singleVmFingerprint
            RESULT
          '';
        }
      ];
    }
