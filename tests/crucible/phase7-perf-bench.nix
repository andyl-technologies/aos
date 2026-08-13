{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.perfBench",
  taskIds ? [
    "T-PERF-1"
    "T-PERF-2"
    "T-PERF-3"
    "T-PERF-4"
    "T-PERF-5"
    "T-PERF-6"
    "T-PERF-7"
    "T-PERF-8"
    "T-PERF-9"
    "T-PERF-10"
    "T-PERF-11"
    "T-PERF-12"
    "T-PERF-13"
    "T-PERF-14"
    "T-PERF-15"
    "T-PERF-16"
    "T-PERF-17"
    "T-PERF-18"
    "T-PERF-19"
    "T-PERF-20"
    "T-PERF-21"
    "T-PERF-22"
    "T-PERF-23"
    "T-PERF-24"
    "T-PERF-25"
    "T-PERF-26"
    "T-PERF-27"
    "T-PERF-28"
  ],
  openTaskIds ? [],
  dependencies ? [],
  hostParallelism ? null,
  fingerprintOffload ? null,
  deviceWorkOverlap ? null,
  translationPrefetch ? null,
  segmentReplay ? null,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  # The perf substrate is split across a `perf/` module directory (each file is
  # kept under the engineering-hygiene soft line limit); concatenate the facade
  # and its submodules so the public-surface needles match wherever a symbol
  # lands.
  perfModule = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-harness/src/perf.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/admission.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/model.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/sweeps.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/report.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/gate.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/corpus.rs)
  ];
  perfGate = builtins.readFile ../../crates/crucible-harness/tests/gate_perf_bench.rs;
  perfHotPathIo = builtins.readFile ../../crates/crucible-harness/tests/gate_perf_bench/hot_path_io.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  libRs = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;
  rootChecks = builtins.readFile ../../default.nix;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  perfDoc = builtins.readFile ../../docs/rfcs/0010-crucible/25-performance-targets.md;
  liveCoverageGate = builtins.readFile ./phase6-basic-block-coverage.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  perfCheckboxFailures =
    lib.concatMap (
      id:
        lib.optionals (!(hasInfix "- [x] **${id}**" perfDoc)) [
          "docs/rfcs/0010-crucible/25-performance-targets.md: ${id} checklist box must be ticked"
        ]
    )
    taskIds
    ++ lib.concatMap (
      id:
        lib.optionals (!(hasInfix "- [ ] **${id}**" perfDoc)) [
          "docs/rfcs/0010-crucible/25-performance-targets.md: ${id} unexpectedly remains open"
        ]
    )
    openTaskIds;

  failures =
    perfCheckboxFailures
    ++ failuresFor "docs/rfcs/0010-crucible/25-performance-targets.md" perfDoc [
      {
        label = "perf-bench completed-evidence note";
        needle = "Completed by `checks.crucible.phase7.gates.perfBench`";
      }
      {
        label = "cost-model term attribution";
        needle = "wall_clock ≈";
      }
    ]
    ++ failuresFor "tests/crucible/phase6-basic-block-coverage.nix" liveCoverageGate [
      {
        label = "production coverage observation-only fingerprint proof";
        needle = "loaded_qemu_fingerprint_equivalence=coverage-off-equals-coverage-on";
      }
      {
        label = "production coverage observation-only canonical-log proof";
        needle = "canonical_event_log_effect=none";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "canonical perf-bench gate row";
        needle = "`gate:perf-bench`";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/perf.rs" perfModule [
      {
        label = "cost-model evaluator";
        needle = "pub fn evaluate_cost_model(";
      }
      {
        label = "cost-model term breakdown";
        needle = "pub struct CostModelBreakdown";
      }
      {
        label = "busy-execution term";
        needle = "pub busy_term: u64,";
      }
      {
        label = "idle term pinned to zero";
        needle = "pub idle_term: u64,";
      }
      {
        label = "amortized-boot term";
        needle = "pub amortized_boot_term: u64,";
      }
      {
        label = "sync-overhead term";
        needle = "pub sync_overhead_term: u64,";
      }
      {
        label = "realized parallelism";
        needle = "pub fn realized_parallelism(";
      }
      {
        label = "host-parallelism admission register";
        needle = "pub fn canonical_host_parallelism_admissions(";
      }
      {
        label = "closed proving-gate catalog";
        needle = "const PROVING_GATES: [&str; 6]";
      }
      {
        label = "fail-closed admission validator";
        needle = "pub fn validate_host_parallelism_admissions(";
      }
      {
        label = "latency/parallelism sweep";
        needle = "pub fn latency_parallelism_sweep(";
      }
      {
        label = "core-count speedup sweep";
        needle = "pub fn core_count_speedup_sweep(";
      }
      {
        label = "rendezvous-frequency sweep";
        needle = "pub fn rendezvous_frequency_sweep(";
      }
      {
        label = "fleet host sweep";
        needle = "pub fn fleet_host_sweep(";
      }
      {
        label = "serial/parallel fingerprint";
        needle = "pub fn scenario_result_fingerprint(";
      }
      {
        label = "delta-bounded fork cost";
        needle = "pub fn fork_cost_bytes(";
      }
      {
        label = "suffix-bounded replay cost";
        needle = "pub fn replay_cost_units(";
      }
      {
        label = "state-bounded peak RSS";
        needle = "pub fn peak_rss_units(";
      }
      {
        label = "advance-path syscall accounting";
        needle = "pub fn advance_syscall_count(";
      }
      {
        label = "snapshot capture/restore latency series";
        needle = "pub fn snapshot_latency_series(";
      }
      {
        label = "pinned host profile";
        needle = "pub fn canonical_host_profile(";
      }
      {
        label = "content-addressed corpus+baseline digest";
        needle = "pub fn perf_corpus_digest(";
      }
      {
        label = "perf-bench report metric set";
        needle = "pub struct PerfBenchReport";
      }
      {
        label = "regression baseline";
        needle = "pub struct PerfBaseline";
      }
      {
        label = "observed fuzz-throughput input";
        needle = "pub observed_fuzz_throughput: u64,";
      }
      {
        label = "gate assertion pass";
        needle = "pub fn run_perf_bench_gate(";
      }
      {
        label = "canonical hermetic corpus";
        needle = "pub fn canonical_bench_corpus(";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_perf_bench.rs" perfGate [
      {
        label = "cost-model term coverage";
        needle = "gate_perf_bench_reports_every_cost_model_term";
      }
      {
        label = "throughput regression negative control";
        needle = "input.observed_fuzz_throughput = input.baseline.fuzz_throughput / 2;";
      }
      {
        label = "idle compression";
        needle = "gate_perf_bench_idle_is_fast_forwarded_to_zero";
      }
      {
        label = "host idle-compression flatness";
        needle = "gate_perf_bench_idle_compression_is_flat_in_wall_clock";
      }
      {
        label = "core-count speedup";
        needle = "gate_perf_bench_core_count_speedup_is_monotone";
      }
      {
        label = "latency-is-the-budget";
        needle = "gate_perf_bench_parallelism_scales_with_lookahead";
      }
      {
        label = "serial/parallel bit-identity";
        needle = "gate_perf_bench_serial_and_parallel_are_bit_identical";
      }
      {
        label = "low-latency trade";
        needle = "gate_perf_bench_low_latency_trades_parallelism_not_determinism";
      }
      {
        label = "sync-overhead budget";
        needle = "gate_perf_bench_sync_overhead_is_within_budget";
      }
      {
        label = "per-TB node independence";
        needle = "gate_perf_bench_per_tb_overhead_is_node_count_independent";
      }
      {
        label = "rendezvous neutrality";
        needle = "gate_perf_bench_rendezvous_frequency_is_result_neutral";
      }
      {
        label = "coverage observation-only";
        needle = "gate_perf_bench_coverage_is_observation_only";
      }
      {
        label = "coverage budget rejection";
        needle = "gate_perf_bench_rejects_below_budget_coverage_ratio";
      }
      {
        label = "fleet near-linear scaling";
        needle = "gate_perf_bench_fleet_throughput_scales_to_saturation";
      }
      {
        label = "coverage ratchet";
        needle = "gate_perf_bench_coverage_ratchet_rejects_decrease";
      }
      {
        label = "snapshot latency tracks changed state";
        needle = "gate_perf_bench_snapshot_latency_tracks_changed_state";
      }
      {
        label = "host profile + content-address";
        needle = "gate_perf_bench_pins_host_profile_and_content_addresses_corpus";
      }
      {
        label = "complete host-parallelism register";
        needle = "gate_perf_bench_requires_complete_host_parallelism_admission_register";
      }
      {
        label = "missing proving gate rejection";
        needle = "gate_perf_bench_rejects_unproved_host_parallelism_admission";
      }
      {
        label = "unknown proving gate rejection";
        needle = "gate_perf_bench_rejects_unknown_proving_gate";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_perf_bench/hot_path_io.rs" perfHotPathIo [
      {
        label = "no advance/delivery socket or control IPC";
        needle = "advance_and_delivery_owners_have_no_socket_or_control_io";
      }
      {
        label = "hot-path IPC negative control";
        needle = "hot_path_io_scanner_rejects_socket_qmp_and_plugin_control_fixture";
      }
    ]
    ++ forbiddenFor "crates/crucible-harness/tests/gate_perf_bench.rs" perfGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" libRs [
      {
        label = "perf module exported";
        needle = "pub mod perf;";
      }
      {
        label = "perf-bench gate marked implemented";
        needle = "name: \"gate:perf-bench\",\n        phase: GatePhase::Phase7,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented perf-bench gate target";
        needle = "gate: \"gate:perf-bench\",\n        package: \"crucible-harness\",\n        test_target: \"gate_perf_bench\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalog [
      {
        label = "perf-bench catalog status implemented";
        needle = "find_gate(\"gate:perf-bench\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "perf-bench target in mapping lint";
        needle = "gate = \"gate:perf-bench\";\n      package = \"crucible-harness\";\n      testTarget = \"gate_perf_bench\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 perf-bench gate imported";
        needle = "gate = import ./phase7-perf-bench.nix";
      }
      {
        label = "phase7 e2e determinism depends on perf-bench";
        needle = "dependencies = [phase1.gates.licenseBoundary.rawGate perfBench.rawGate";
      }
    ]
    ++ failuresFor "default.nix" rootChecks [
      {
        label = "live fleet performance check";
        needle = "crucible-perf = let";
      }
      {
        label = "live QEMU backend selection";
        needle = "--backend qemu";
      }
      {
        label = "live performance verification uses a valid reduction count";
        needle = "verify \"$scenario\" --runs 2";
      }
      {
        label = "logical fleet-host sweep";
        needle = "for hosts in 1 2 4 8";
      }
      {
        label = "live throughput result";
        needle = "throughput_per_core_hour=$throughput_per_core_hour";
      }
      {
        label = "per-core throughput normalization";
        needle = "par_ms * parallel_workers";
      }
      {
        label = "live fleet scaling assertion";
        needle = "test \"$fleet_per_hour\" -ge \"$minimum_linear\"";
      }
      {
        label = "thin replay restore source required";
        needle = "restore_source=thin-replay-from-live-qemu-artifact";
      }
      {
        label = "live loadvm restore latency required";
        needle = "loadvm_boot_window_restore_ms=$loadvm_boot_ms";
      }
      {
        label = "restore measurement covers loadvm and replay fallback";
        needle = "metric_restore_latency=live-qmp-loadvm-plus-thin-replay-fallback [PERF-12]";
      }
      {
        label = "live coverage IPS check";
        needle = "metric_coverage_ips=checks.crucible.phase0.coverageOverhead [PERF-14]";
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "red-gate placeholder reason";
        needle = "performance benchmark gate is intentionally pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 perf-bench check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-perf-bench";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies
        ++ lib.optionals (hostParallelism != null) [hostParallelism]
        ++ lib.optionals (fingerprintOffload != null) [fingerprintOffload]
        ++ lib.optionals (deviceWorkOverlap != null) [deviceWorkOverlap];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-perf-bench";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-perf-bench-target" \
              -p crucible-harness \
              --test gate_perf_bench \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:perf-bench
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=complete
            owner=crucible-harness
            phase=phase7
            gate_class=regression
            cost_model=wall_clock=busy/(tcg_ips*P)+amortized_boot+sync_overhead
            metric_tcg_ips=recorded
            metric_idle_compression=flat
            metric_parallelism_P=lookahead-bounded
            metric_sync_overhead_pct=warn-5-fail-10
            metric_per_tb=node-count-independent
            metric_boot_amortization=one-per-vm-per-world
            metric_restore_latency=recorded
            metric_fuzz_throughput=baseline-ratchet
            metric_coverage_on_off=cheap-on-free-off
            metric_fork_cost=delta-bounded
            metric_replay_cost=suffix-bounded
            metric_peak_rss=state-bounded
            fleet_throughput=near-linear-to-saturation
            cumulative_coverage=monotone-non-decreasing
            determinism_neutral=runs-after-determinism-gates
            host_parallelism_admission_register=fail-closed
            host_parallelism_classes=class-a-outside-observable-boundary,class-b-pinned-virtual-time-commit
            admitted_host_parallel_mechanisms=scheduler-host-worker-pool,fingerprint-digest-offload,device-host-work-overlap,translation-prefetch,segment-parallel-replay
            unclassified_host_parallelism_policy=reject
            missing_or_unknown_proving_gate_policy=blocking-failure
            measurement_model=deterministic-cost-model-substrate-no-qemu
            real_process_discharge=checks.fleet.crucible-perf
            real_multi_vm_speedup=checks.fleet.crucible-perf [PERF-3]
            real_restore_latency=checks.fleet.crucible-perf [PERF-12]
            real_throughput_baseline=checks.fleet.crucible-perf [PERF-13]
            real_coverage_ips=checks.crucible.phase0.coverageOverhead [PERF-14]
            real_coverage_observation=checks.crucible.phase6.basicBlockCoverage [PERF-15]
            real_fleet_sweep=checks.fleet.crucible-perf [PERF-27]
            real_guest_boot=checks.fleet.crucible-perf
            host_profile=pinned
            corpus_baseline=content-addressed
            RESULT
            if [ -n "${
              if hostParallelism == null
              then ""
              else builtins.toString hostParallelism
            }" ]; then
              sed -n \
                -e 's/^parallel_realized_parallelism=/metric_parallelism_P_real_qemu=/p' \
                -e 's/^parallel_dispatch_wall_us=/metric_parallel_dispatch_wall_us=/p' \
                -e 's/^serial_dispatch_wall_us=/metric_serial_dispatch_wall_us=/p' \
                -e 's/^serial_evidence_hash=/metric_parallelism_worker_neutral_hash=/p' \
                "${
              if hostParallelism == null
              then "/dev/null"
              else "${hostParallelism}/result"
            }" \
                >> "$out/result"
            fi
            if [ -n "${
              if deviceWorkOverlap == null
              then ""
              else builtins.toString deviceWorkOverlap
            }" ]; then
              sed -n \
                -e 's/^admission_class=/metric_device_work_class=/p' \
                -e 's/^dispatch=/metric_device_work_dispatch=/p' \
                -e 's/^completion_coordinate=/metric_device_work_completion_coordinate=/p' \
                -e 's/^requester_behavior=/metric_device_work_requester_behavior=/p' \
                -e 's/^host_wins_race_proven=/metric_device_work_host_wins=/p' \
                -e 's/^guest_wins_race_proven=/metric_device_work_guest_wins=/p' \
                -e 's/^synchronous_async_canonical_logs_identical=/metric_device_work_log_identity=/p' \
                "${
              if deviceWorkOverlap == null
              then "/dev/null"
              else "${deviceWorkOverlap}/result"
            }" \
                >> "$out/result"
            fi
            if [ -n "${
              if fingerprintOffload == null
              then ""
              else builtins.toString fingerprintOffload
            }" ]; then
              sed -n \
                -e 's/^admission_class=/metric_fingerprint_offload_class=/p' \
                -e 's/^capture=/metric_fingerprint_capture=/p' \
                -e 's/^digest_thread=/metric_fingerprint_digest_thread=/p' \
                -e 's/^synchronous_corpus_identity=/metric_fingerprint_sync_identity=/p' \
                -e 's/^cadence_unchanged=/metric_fingerprint_cadence_unchanged=/p' \
                -e 's/^sample_coordinates_unchanged=/metric_fingerprint_coordinates_unchanged=/p' \
                -e 's/^forced_event_boundaries_unchanged=/metric_fingerprint_forced_boundaries_unchanged=/p' \
                "${
              if fingerprintOffload == null
              then "/dev/null"
              else "${fingerprintOffload}/result"
            }" \
                >> "$out/result"
            fi
            if [ -n "${
              if translationPrefetch == null
              then ""
              else builtins.toString translationPrefetch
            }" ]; then
              sed -n \
                -e 's/^admission_class=/metric_translation_prefetch_class=/p' \
                -e 's/^corpus=/metric_translation_prefetch_corpus=/p' \
                -e 's/^mechanism=/metric_translation_prefetch_mechanism=/p' \
                -e 's/^translation_requests=/metric_translation_prefetch_requests=/p' \
                -e 's/^fingerprints_bit_identical=/metric_translation_prefetch_fingerprint_identity=/p' \
                -e 's/^canonical_logs_bit_identical=/metric_translation_prefetch_log_identity=/p' \
                -e 's/^divergence_policy=/metric_translation_prefetch_divergence_policy=/p' \
                "${
              if translationPrefetch == null
              then "/dev/null"
              else "${translationPrefetch}/result"
            }" \
                >> "$out/result"
            fi
            if [ -n "${
              if segmentReplay == null
              then ""
              else builtins.toString segmentReplay
            }" ]; then
              sed -n \
                -e 's/^admission_class=/metric_segment_replay_class=/p' \
                -e 's/^worker_model=/metric_segment_replay_worker_model=/p' \
                -e 's/^tested_segment_counts=/metric_segment_replay_counts=/p' \
                -e 's/^serial_parallel_final_state_identical=/metric_segment_replay_state_identity=/p' \
                -e 's/^serial_parallel_canonical_log_identical=/metric_segment_replay_log_identity=/p' \
                -e 's/^divergence_coordinate_segment_count_invariant=/metric_segment_replay_divergence_invariant=/p' \
                "${
              if segmentReplay == null
              then "/dev/null"
              else "${segmentReplay}/result"
            }" \
                >> "$out/result"
            fi
          '';
        }
      ];
    }
