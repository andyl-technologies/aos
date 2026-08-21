{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.workloadVirtualTimeShapes",
  taskIds ? ["T-WL-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  workloadDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  engineModel = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  loadPatternTest = builtins.readFile ../../crates/crucible/tests/workload_load_patterns.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  forbiddenWallClockApis = [
    "std::time::Instant::now"
    "std::time::SystemTime::now"
    "SystemTime::now"
    "Instant::now"
  ];

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" workloadDoc [
      {
        label = "T-WL-5 completion note";
        needle = "Completed by `checks.crucible.phase4.workloadVirtualTimeShapes`";
      }
      {
        label = "WL-8 virtual time requirement";
        needle = "derive its variation from **virtual time**";
      }
      {
        label = "no host wall clock requirement";
        needle = "never from host";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" engineModel [
      {
        label = "time-source scenario parameter";
        needle = "pub const WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER: &str = \"load_time_source\";";
      }
      {
        label = "virtual-time required invariant";
        needle = "pub const WORKLOAD_TIME_VARIATION_REQUIRES_VIRTUAL_TIME: bool = true;";
      }
      {
        label = "host wall clock forbidden invariant";
        needle = "pub const WORKLOAD_HOST_WALL_CLOCK_LOAD_SHAPES_ALLOWED: bool = false;";
      }
      {
        label = "time-source vocabulary";
        needle = "pub enum GuestWorkloadTimeSource";
      }
      {
        label = "only virtual-time value";
        needle = "Self::VirtualTime => \"virtual_time\"";
      }
      {
        label = "time source node-template helper";
        needle = "pub fn guest_workload_time_source(mut self, source: GuestWorkloadTimeSource) -> Self";
      }
      {
        label = "world node time-source parser";
        needle = "pub fn guest_workload_time_source(&self) -> Option<GuestWorkloadTimeSource>";
      }
      {
        label = "time-source validator";
        needle = "fn validate_world_node_workload_time_source";
      }
      {
        label = "time-source consistency validator";
        needle = "fn validate_world_node_workload_time_source_consistency";
      }
      {
        label = "time-varying missing VT rejection";
        needle = "WorldNodeWorkloadTimeVaryingPatternMissingVirtualTimeSource";
      }
      {
        label = "stray time-source rejection";
        needle = "WorldNodeWorkloadTimeSourceWithoutTimeVaryingPattern";
      }
      {
        label = "spike fixture VT source";
        needle = "Some(GuestWorkloadTimeSource::VirtualTime)";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" engineModel (
      builtins.map (needle: {
        label = "host wall-clock API in workload shape model";
        inherit needle;
      })
      forbiddenWallClockApis
    )
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "time-source type re-export";
        needle = "GuestWorkloadTimeSource";
      }
      {
        label = "time-source parameter re-export";
        needle = "WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER";
      }
      {
        label = "virtual-time invariant re-export";
        needle = "WORKLOAD_TIME_VARIATION_REQUIRES_VIRTUAL_TIME";
      }
      {
        label = "host wall clock invariant re-export";
        needle = "WORKLOAD_HOST_WALL_CLOCK_LOAD_SHAPES_ALLOWED";
      }
    ]
    ++ failuresFor "crates/crucible/tests/workload_load_patterns.rs" loadPatternTest [
      {
        label = "time-source parameter test";
        needle = "GuestWorkloadTimeSource::VirtualTime";
      }
      {
        label = "bit-identical reproduction test";
        needle = "time_varying_load_fixtures_reproduce_bit_identically";
      }
      {
        label = "canonical binary first operand";
        needle = "first_form.to_compact_binary()";
      }
      {
        label = "canonical binary second operand";
        needle = "second_form.to_compact_binary()";
      }
      {
        label = "canonical toml first operand";
        needle = "first_form.to_canonical_toml()?";
      }
      {
        label = "canonical toml second operand";
        needle = "second_form.to_canonical_toml()?";
      }
      {
        label = "host wall clock rejection";
        needle = "host_wall_clock";
      }
      {
        label = "missing virtual-time rejection";
        needle = "assert_missing_virtual_time_source";
      }
      {
        label = "stray time-source rejection";
        needle = "assert_stray_time_source";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 workload virtual-time shapes import";
        needle = "workloadVirtualTimeShapes = import ./phase4-workload-virtual-time-shapes.nix";
      }
      {
        label = "phase4 workload virtual-time shapes attr path";
        needle = "checks.crucible.phase4.workloadVirtualTimeShapes";
      }
      {
        label = "phase4 workload virtual-time shapes task id";
        needle = "taskIds = [\"T-WL-5\"]";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 workload virtual-time shapes check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-workload-virtual-time-shapes";
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
          name = "run-workload-virtual-time-shapes";
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
              --target-dir "$TMPDIR/crucible-workload-virtual-time-shapes-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_load_patterns \
              -- --list > "$TMPDIR/workload-virtual-time-shape-tests"
            require_listed \
              "$TMPDIR/workload-virtual-time-shape-tests" \
              "spike_fixture_can_be_guest_virtual_time_rate"
            require_listed \
              "$TMPDIR/workload-virtual-time-shape-tests" \
              "spike_fixture_can_be_planned_start_node_burst"
            require_listed \
              "$TMPDIR/workload-virtual-time-shape-tests" \
              "cardinality_growth_fixture_is_guest_key_policy"
            require_listed \
              "$TMPDIR/workload-virtual-time-shape-tests" \
              "time_varying_load_fixtures_reproduce_bit_identically"
            require_listed \
              "$TMPDIR/workload-virtual-time-shape-tests" \
              "load_pattern_reserved_parameters_reject_unknown_and_duplicate_values"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-virtual-time-shapes-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_load_patterns \
              time_varying_load_fixtures_reproduce_bit_identically \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-virtual-time-shapes-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_load_patterns \
              load_pattern_reserved_parameters_reject_unknown_and_duplicate_values \
              -- --exact --test-threads=1
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
            time_source=virtual_time
            host_wall_clock_load_shapes=false
            spike_reproducible=true
            cardinality_growth_reproducible=true
            RESULT
          '';
        }
      ];
    }
