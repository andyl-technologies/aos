{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.workloadModel",
  taskIds ? ["T-WL-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  workloadDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  engineBackend = builtins.readFile ../../crates/crucible/src/backend.rs;
  engineDevice = builtins.readFile ../../crates/crucible/src/device.rs;
  engineModel = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  workloadTest = builtins.readFile ../../crates/crucible/tests/workload_model.rs;
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
        label = "T-WL-1 completion note";
        needle = "Completed by `checks.crucible.phase4.workloadModel`";
      }
      {
        label = "in-guest workload model documented";
        needle = "closed `GuestWorkloadBinary`";
      }
      {
        label = "no host traffic injector documented";
        needle = "application-traffic origination path exists in the engine";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" engineModel [
      {
        label = "workload scenario parameter";
        needle = "pub const WORKLOAD_SCENARIO_PARAMETER: &str = \"crucible.workload\";";
      }
      {
        label = "in-guest origin invariant";
        needle = "pub const APPLICATION_TRAFFIC_ORIGINATES_IN_GUEST: bool = true;";
      }
      {
        label = "engine workload role";
        needle = "pub const WORKLOAD_ENGINE_ROLE: WorkloadEngineRole = WorkloadEngineRole::ObservationAndSteeringOnly;";
      }
      {
        label = "supported workload enum";
        needle = "pub enum GuestWorkloadBinary";
      }
      {
        label = "httpd workload binary";
        needle = "Httpd";
      }
      {
        label = "client-loop workload binary";
        needle = "ClientLoop";
      }
      {
        label = "benchmark workload binary";
        needle = "Benchmark";
      }
      {
        label = "httpd parameter value";
        needle = "Self::Httpd => \"httpd\"";
      }
      {
        label = "client-loop parameter value";
        needle = "Self::ClientLoop => \"httpget\"";
      }
      {
        label = "benchmark parameter value";
        needle = "Self::Benchmark => \"bench\"";
      }
      {
        label = "node template workload helper";
        needle = "pub fn guest_workload(mut self, workload: GuestWorkloadBinary) -> Self";
      }
      {
        label = "world node workload parser";
        needle = "pub fn guest_workload(&self) -> Option<GuestWorkloadBinary>";
      }
      {
        label = "command-line selection helper";
        needle = "fn cmdline_with_guest_workload";
      }
      {
        label = "unsupported workload error";
        needle = "WorldNodeUnsupportedWorkload";
      }
      {
        label = "duplicate workload error";
        needle = "WorldNodeDuplicateWorkload";
      }
      {
        label = "workload validator";
        needle = "fn validate_world_node_workload";
      }
    ]
    ++ failuresFor "crates/crucible/src/backend.rs" engineBackend [
      {
        label = "backend input not workload generator";
        needle = "not a host-side workload generator";
      }
      {
        label = "backend input cannot originate app traffic";
        needle = "MUST NOT be used to originate application traffic";
      }
      {
        label = "backend input accepts only scheduled model events";
        needle = "already-scheduled model events";
      }
    ]
    ++ failuresFor "crates/crucible/src/device.rs" engineDevice [
      {
        label = "device frame already emitted";
        needle = "already emitted by a modeled guest/device endpoint";
      }
      {
        label = "device frame not workload generator";
        needle = "not a host-side workload";
      }
      {
        label = "device frame cannot originate app traffic";
        needle = "generator and MUST NOT be used to originate application traffic";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "workload enum re-export";
        needle = "GuestWorkloadBinary";
      }
      {
        label = "workload role re-export";
        needle = "WorkloadEngineRole";
      }
      {
        label = "workload parameter re-export";
        needle = "WORKLOAD_SCENARIO_PARAMETER";
      }
    ]
    ++ failuresFor "crates/crucible/tests/workload_model.rs" workloadTest [
      {
        label = "supported binaries test";
        needle = "workload_model_declares_supported_in_guest_binaries";
      }
      {
        label = "cmdline parameter test";
        needle = "workload_selection_is_a_scenario_cmdline_parameter";
      }
      {
        label = "scenario identity test";
        needle = "workload_selection_changes_scenario_identity";
      }
      {
        label = "reserved parameter validation test";
        needle = "workload_reserved_parameter_rejects_unknown_and_duplicate_values";
      }
      {
        label = "serialized form validation test";
        needle = "workload_reserved_parameter_rejects_malformed_toml_and_binary_forms";
      }
      {
        label = "source lint test";
        needle = "engine_source_has_no_application_traffic_origination_path";
      }
      {
        label = "delivery surface documentation test";
        needle = "backend_and_device_delivery_surfaces_are_documented_as_non_originators";
      }
      {
        label = "source lint walks engine crate";
        needle = "env!(\"CARGO_MANIFEST_DIR\")";
      }
      {
        label = "source lint reads engine sources";
        needle = "fs::read_dir";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" engineModel (
      builtins.map (needle: {
        label = "host-side workload origination API";
        inherit needle;
      })
      forbiddenOriginationApis
    )
    ++ forbiddenFor "crates/crucible/src/backend.rs" engineBackend (
      builtins.map (needle: {
        label = "host-side workload origination API";
        inherit needle;
      })
      forbiddenOriginationApis
    )
    ++ forbiddenFor "crates/crucible/src/device.rs" engineDevice (
      builtins.map (needle: {
        label = "host-side workload origination API";
        inherit needle;
      })
      forbiddenOriginationApis
    )
    ++ forbiddenFor "crates/crucible/src/lib.rs" engineLib (
      builtins.map (needle: {
        label = "host-side workload origination API";
        inherit needle;
      })
      forbiddenOriginationApis
    )
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 workload model import";
        needle = "workloadModel = import ./phase4-workload-model.nix";
      }
      {
        label = "phase4 workload model attr path";
        needle = "checks.crucible.phase4.workloadModel";
      }
      {
        label = "phase4 workload model task id";
        needle = "taskIds = [\"T-WL-1\"]";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 workload model check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-workload-model";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-workload-model";
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
              --target-dir "$TMPDIR/crucible-workload-model-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              -- --list > "$TMPDIR/workload-model-tests"
            require_listed \
              "$TMPDIR/workload-model-tests" \
              "workload_model_declares_supported_in_guest_binaries"
            require_listed \
              "$TMPDIR/workload-model-tests" \
              "workload_selection_is_a_scenario_cmdline_parameter"
            require_listed \
              "$TMPDIR/workload-model-tests" \
              "workload_selection_changes_scenario_identity"
            require_listed \
              "$TMPDIR/workload-model-tests" \
              "workload_reserved_parameter_rejects_unknown_and_duplicate_values"
            require_listed \
              "$TMPDIR/workload-model-tests" \
              "workload_reserved_parameter_rejects_malformed_toml_and_binary_forms"
            require_listed \
              "$TMPDIR/workload-model-tests" \
              "engine_source_has_no_application_traffic_origination_path"
            require_listed \
              "$TMPDIR/workload-model-tests" \
              "backend_and_device_delivery_surfaces_are_documented_as_non_originators"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-model-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_model_declares_supported_in_guest_binaries \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-model-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_selection_is_a_scenario_cmdline_parameter \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-model-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_selection_changes_scenario_identity \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-model-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_reserved_parameter_rejects_unknown_and_duplicate_values \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-model-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_reserved_parameter_rejects_malformed_toml_and_binary_forms \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-model-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              engine_source_has_no_application_traffic_origination_path \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-model-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              backend_and_device_delivery_surfaces_are_documented_as_non_originators \
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
            workload_binaries=httpd,httpget,bench
            workload_selection=guest-cmdline-scenario-parameter
            reserved_workload_parameter=validated
            traffic_origination=in-guest-only
            backend_delivery=not-workload-generator
            engine_role=observe-and-steer
            RESULT
          '';
        }
      ];
    }
