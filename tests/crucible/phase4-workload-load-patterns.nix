{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.workloadLoadPatterns",
  taskIds ? ["T-WL-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  workloadDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  engineModel = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  loadPatternTest = builtins.readFile ../../crates/crucible/tests/workload_load_patterns.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  forbiddenOriginationApis = [
    "struct ApplicationTrafficInjector"
    "enum ApplicationTrafficInjector"
    "struct HostTrafficInjector"
    "enum HostTrafficInjector"
    "struct ApplicationLoadGenerator"
    "enum ApplicationLoadGenerator"
    "struct TrafficGenerator"
    "enum TrafficGenerator"
    "struct WorkloadGenerator"
    "enum WorkloadGenerator"
    "fn originate_application_traffic"
    "fn inject_application_traffic"
    "fn generate_application_traffic"
  ];

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" workloadDoc [
      {
        label = "T-WL-4 completion note";
        needle = "Completed by `checks.crucible.phase4.workloadLoadPatterns`";
      }
      {
        label = "load patterns no host-side generator";
        needle = "classic pattern        Crucible mechanism (no host-side generator)";
      }
      {
        label = "StartNode spike mapping documented";
        needle = "StartNode a baked load-node at a chosen virtual time";
      }
      {
        label = "fault campaign mapping documented";
        needle = "correlated partition +";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" engineModel [
      {
        label = "load-pattern scenario parameter";
        needle = "pub const WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER: &str = \"load_pattern\";";
      }
      {
        label = "spike-mode scenario parameter";
        needle = "pub const WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER: &str = \"spike_mode\";";
      }
      {
        label = "black-box suffices invariant";
        needle = "pub const WORKLOAD_LOAD_PATTERN_BLACK_BOX_CONFIG_SUFFICES: bool = true;";
      }
      {
        label = "white-box not required invariant";
        needle = "pub const WORKLOAD_LOAD_PATTERN_REQUIRES_WHITE_BOX: bool = false;";
      }
      {
        label = "load-pattern vocabulary";
        needle = "pub enum GuestWorkloadPattern";
      }
      {
        label = "spike-mode vocabulary";
        needle = "pub enum GuestWorkloadSpikeMode";
      }
      {
        label = "load-pattern fixture type";
        needle = "pub struct GuestWorkloadLoadPatternFixture";
      }
      {
        label = "steady fixture";
        needle = "pub fn steady() -> Result<Self, EngineError>";
      }
      {
        label = "virtual-time spike fixture";
        needle = "pub fn spike_virtual_time_rate() -> Result<Self, EngineError>";
      }
      {
        label = "StartNode spike fixture";
        needle = "pub fn spike_start_node_burst() -> Result<Self, EngineError>";
      }
      {
        label = "cardinality growth fixture";
        needle = "pub fn cardinality_growth() -> Result<Self, EngineError>";
      }
      {
        label = "correlated failure fixture";
        needle = "pub fn correlated_failure_campaign() -> Result<Self, EngineError>";
      }
      {
        label = "StartNode plan primitive";
        needle = "Action::start_node(burst_node)";
      }
      {
        label = "fault-plan campaign primitive";
        needle = "Plan::from_fault_plan_for_world(&world, FaultPlan::from_entries(entries))";
      }
      {
        label = "load-pattern validator";
        needle = "fn validate_world_node_workload_pattern";
      }
      {
        label = "spike-mode validator";
        needle = "fn validate_world_node_workload_spike_mode";
      }
      {
        label = "spike consistency validator";
        needle = "fn validate_world_node_workload_pattern_consistency";
      }
      {
        label = "missing spike mode rejection";
        needle = "WorldNodeWorkloadSpikePatternMissingMode";
      }
      {
        label = "stray spike mode rejection";
        needle = "WorldNodeWorkloadSpikeModeWithoutSpikePattern";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" engineModel (
      builtins.map (needle: {
        label = "host-side workload origination API";
        inherit needle;
      })
      forbiddenOriginationApis
    )
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "load-pattern type re-export";
        needle = "GuestWorkloadPattern";
      }
      {
        label = "spike-mode type re-export";
        needle = "GuestWorkloadSpikeMode";
      }
      {
        label = "load-pattern fixture re-export";
        needle = "GuestWorkloadLoadPatternFixture";
      }
      {
        label = "load-pattern parameter re-export";
        needle = "WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER";
      }
      {
        label = "spike-mode parameter re-export";
        needle = "WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER";
      }
    ]
    ++ failuresFor "crates/crucible/tests/workload_load_patterns.rs" loadPatternTest [
      {
        label = "plain parameter test";
        needle = "load_pattern_mappings_are_plain_cmdline_parameters";
      }
      {
        label = "steady fixture test";
        needle = "steady_fixture_is_guest_loop_plus_rate_parameter";
      }
      {
        label = "virtual-time spike fixture test";
        needle = "spike_fixture_can_be_guest_virtual_time_rate";
      }
      {
        label = "StartNode burst fixture test";
        needle = "spike_fixture_can_be_planned_start_node_burst";
      }
      {
        label = "cardinality fixture test";
        needle = "cardinality_growth_fixture_is_guest_key_policy";
      }
      {
        label = "correlated failure fixture test";
        needle = "correlated_failure_fixture_is_fault_plan_campaign";
      }
      {
        label = "scenario identity fixture test";
        needle = "load_pattern_fixtures_change_scenario_identity_without_global_seed";
      }
      {
        label = "malformed duplicate parameter test";
        needle = "load_pattern_reserved_parameters_reject_unknown_and_duplicate_values";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 workload load patterns import";
        needle = "workloadLoadPatterns = import ./phase4-workload-load-patterns.nix";
      }
      {
        label = "phase4 workload load patterns attr path";
        needle = "checks.crucible.phase4.workloadLoadPatterns";
      }
      {
        label = "phase4 workload load patterns task id";
        needle = "taskIds = [\"T-WL-4\"]";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 workload load-patterns check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-workload-load-patterns";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
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
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-workload-load-patterns";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            require_listed() {
              listed="$1"
              test_name="$2"
              if [ -z "$(sed -n "/$test_name/p" "$listed")" ]; then
                printf 'missing expected test: %s\n' "$test_name" >&2
                exit 1
              fi
            }
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-load-patterns-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_load_patterns \
              -- --list > "$TMPDIR/workload-load-pattern-tests"
            require_listed \
              "$TMPDIR/workload-load-pattern-tests" \
              "load_pattern_mappings_are_plain_cmdline_parameters"
            require_listed \
              "$TMPDIR/workload-load-pattern-tests" \
              "steady_fixture_is_guest_loop_plus_rate_parameter"
            require_listed \
              "$TMPDIR/workload-load-pattern-tests" \
              "spike_fixture_can_be_guest_virtual_time_rate"
            require_listed \
              "$TMPDIR/workload-load-pattern-tests" \
              "spike_fixture_can_be_planned_start_node_burst"
            require_listed \
              "$TMPDIR/workload-load-pattern-tests" \
              "cardinality_growth_fixture_is_guest_key_policy"
            require_listed \
              "$TMPDIR/workload-load-pattern-tests" \
              "correlated_failure_fixture_is_fault_plan_campaign"
            require_listed \
              "$TMPDIR/workload-load-pattern-tests" \
              "load_pattern_fixtures_change_scenario_identity_without_global_seed"
            require_listed \
              "$TMPDIR/workload-load-pattern-tests" \
              "load_pattern_reserved_parameters_reject_unknown_and_duplicate_values"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-load-patterns-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_load_patterns \
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
            tasks=${taskList}
            load_patterns=steady,spike,cardinality_growth,correlated_failure
            spike_modes=virtual_time_rate,start_node_burst
            load_pattern_delivery=black-box-cmdline
            load_generation_subsystem=false
            correlated_failure_plan=FaultPlan
            RESULT
          '';
        }
      ];
    }
