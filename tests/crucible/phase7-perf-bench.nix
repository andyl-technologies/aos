{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.perfBench",
  taskIds ? ["T-PERF-26"],
  openTaskIds ? [
    "T-PERF-1" "T-PERF-2" "T-PERF-3" "T-PERF-4" "T-PERF-5" "T-PERF-6"
    "T-PERF-7" "T-PERF-8" "T-PERF-9" "T-PERF-10" "T-PERF-11" "T-PERF-12"
    "T-PERF-13" "T-PERF-14" "T-PERF-15" "T-PERF-16" "T-PERF-17" "T-PERF-18"
    "T-PERF-19" "T-PERF-20" "T-PERF-21" "T-PERF-22" "T-PERF-23" "T-PERF-24"
    "T-PERF-25" "T-PERF-27" "T-PERF-28"
  ],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  # The perf substrate is split across a `perf/` module directory (each file is
  # kept under the engineering-hygiene soft line limit); concatenate the facade
  # and its submodules so the public-surface needles match wherever a symbol
  # lands.
  perfModule = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-harness/src/perf.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/model.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/sweeps.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/report.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/gate.rs)
    (builtins.readFile ../../crates/crucible-harness/src/perf/corpus.rs)
  ];
  perfGate = builtins.readFile ../../crates/crucible-harness/tests/gate_perf_bench.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  libRs = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  perfDoc = builtins.readFile ../../docs/rfcs/0010-crucible/25-performance-targets.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

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

  # The modeled gate remains diagnostic while the live measurements are open.
  perfCheckboxFailures =
    lib.optionals (!(hasInfix "- [x] **T-PERF-26**" perfDoc)) [
      "docs/rfcs/0010-crucible/25-performance-targets.md: T-PERF-26 checklist box must be ticked"
    ]
    ++ lib.concatMap (
      id:
        lib.optionals (!(hasInfix "- [ ] **${id}**" perfDoc)) [
          "docs/rfcs/0010-crucible/25-performance-targets.md: ${id} must remain open while live evidence is absent"
        ]
    )
    openTaskIds;

  failures =
    perfCheckboxFailures
    ++ failuresFor "docs/rfcs/0010-crucible/25-performance-targets.md" perfDoc [
      {
        label = "perf-bench partial-evidence note";
        needle = "Partial modeled evidence is provided by `checks.crucible.phase7.gates.perfBench`";
      }
      {
        label = "cost-model term attribution";
        needle = "wall_clock ≈";
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
        label = "no per-quantum IPC";
        needle = "gate_perf_bench_advance_path_has_no_per_quantum_ipc";
      }
      {
        label = "snapshot latency tracks changed state";
        needle = "gate_perf_bench_snapshot_latency_tracks_changed_state";
      }
      {
        label = "host profile + content-address";
        needle = "gate_perf_bench_pins_host_profile_and_content_addresses_corpus";
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
        needle = "dependencies = [perfBench.rawGate";
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

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ] ++ dependencies;

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
            status=partial
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
            measurement_model=deterministic-cost-model-substrate-no-qemu
            real_process_discharge=checks.fleet.crucible-perf
            real_multi_vm_speedup=checks.fleet.crucible-perf [PERF-3]
            real_restore_latency=checks.fleet.crucible-perf [PERF-12]
            real_throughput_baseline=checks.fleet.crucible-perf [PERF-13]
            real_coverage_ips=pending-real-qemu-exec [PERF-14]
            real_fleet_sweep=deferred-to-gate:fleet-equivalence [PERF-27]
            real_guest_boot=pending-spawn-exec
            host_profile=pinned
            corpus_baseline=content-addressed
            RESULT
          '';
        }
      ];
    }
