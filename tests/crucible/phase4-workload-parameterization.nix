{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.workloadParameterization",
  taskIds ? ["T-WL-6"],
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
  parameterizationTest = builtins.readFile ../../crates/crucible/tests/workload_parameterization.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  forbiddenHostDeliveryNeedles = [
    "HostWorkloadParameterPoke"
    "MutableWorkloadConfigTree"
    "WORKLOAD_PARAMETER_HOST_RUNTIME_POKES_ALLOWED: bool = true"
    "WORKLOAD_CONFIG_TREES_ARE_READ_ONLY: bool = false"
  ];

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" workloadDoc [
      {
        label = "T-WL-6 completion note";
        needle = "Completed by `checks.crucible.phase4.workloadParameterization`";
      }
      {
        label = "WL-10 scenario hash requirement";
        needle = "changing a workload parameter MUST produce a different `ScenarioDef::id`";
      }
      {
        label = "WL-11 read-only requirement";
        needle = "Workload-parameter delivery MUST be **read-only**";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" engineModel [
      {
        label = "config-tree scenario parameter";
        needle = "pub const WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER: &str = \"wcfg\";";
      }
      {
        label = "parameters are scenario config invariant";
        needle = "pub const WORKLOAD_PARAMETERS_ARE_SCENARIO_CONFIG: bool = true;";
      }
      {
        label = "config trees read-only invariant";
        needle = "pub const WORKLOAD_CONFIG_TREES_ARE_READ_ONLY: bool = true;";
      }
      {
        label = "host runtime poke invariant";
        needle = "pub const WORKLOAD_PARAMETER_HOST_RUNTIME_POKES_ALLOWED: bool = false;";
      }
      {
        label = "deterministic qid invariant";
        needle = "pub const WORKLOAD_CONFIG_TREE_DETERMINISTIC_QIDS: bool = true;";
      }
      {
        label = "sorted enumeration invariant";
        needle = "pub const WORKLOAD_CONFIG_TREE_SORTED_ENUMERATION: bool = true;";
      }
      {
        label = "scalar parameter key vocabulary";
        needle = "pub enum GuestWorkloadParameterKey";
      }
      {
        label = "scalar parameter type";
        needle = "pub struct GuestWorkloadScalarParameter";
      }
      {
        label = "config-tree delivery vocabulary";
        needle = "pub enum GuestWorkloadConfigTreeDelivery";
      }
      {
        label = "config-tree ref type";
        needle = "pub struct GuestWorkloadConfigTreeRef";
      }
      {
        label = "world config-tree binding";
        needle = "pub struct WorldWorkloadConfigTree";
      }
      {
        label = "world config-tree accessor";
        needle = "pub fn workload_config_trees(&self) -> Vec<WorldWorkloadConfigTree>";
      }
      {
        label = "node-template scalar helper";
        needle = "pub fn guest_workload_scalar_parameter";
      }
      {
        label = "node-template config helper";
        needle = "pub fn guest_workload_config_tree";
      }
      {
        label = "world-node scalar reader";
        needle = "pub fn guest_workload_scalar_parameters";
      }
      {
        label = "world-node config reader";
        needle = "pub fn guest_workload_config_tree(&self)";
      }
      {
        label = "scalar validator";
        needle = "fn validate_world_node_workload_scalar_parameters";
      }
      {
        label = "config tree validator";
        needle = "fn validate_world_node_workload_config_tree";
      }
      {
        label = "rootfs delivery sets root image";
        needle = "self.root_image = Some(config.export())";
      }
      {
        label = "rootfs missing root image rejection";
        needle = "WorldNodeWorkloadConfigTreeRootfsMissingRootImage";
      }
      {
        label = "rootfs mismatched root image rejection";
        needle = "WorldNodeWorkloadConfigTreeRootfsMismatchedRootImage";
      }
      {
        label = "rootfs export match check";
        needle = "Some(root_image) if root_image == config.export()";
      }
      {
        label = "comma mount rejection";
        needle = "mount.contains(',')";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" engineModel (
      builtins.map (needle: {
        label = "host-side or mutable workload parameter delivery";
        inherit needle;
      })
      forbiddenHostDeliveryNeedles
    )
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "parameter key re-export";
        needle = "GuestWorkloadParameterKey";
      }
      {
        label = "scalar parameter re-export";
        needle = "GuestWorkloadScalarParameter";
      }
      {
        label = "config-tree ref re-export";
        needle = "GuestWorkloadConfigTreeRef";
      }
      {
        label = "world config-tree binding re-export";
        needle = "WorldWorkloadConfigTree";
      }
      {
        label = "config-tree parameter re-export";
        needle = "WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER";
      }
      {
        label = "scenario-config invariant re-export";
        needle = "WORKLOAD_PARAMETERS_ARE_SCENARIO_CONFIG";
      }
      {
        label = "host poke invariant re-export";
        needle = "WORKLOAD_PARAMETER_HOST_RUNTIME_POKES_ALLOWED";
      }
    ]
    ++ failuresFor "crates/crucible/tests/workload_parameterization.rs" parameterizationTest [
      {
        label = "scalar cmdline test";
        needle = "scalar_workload_parameters_are_cmdline_scenario_config";
      }
      {
        label = "scalar identity test";
        needle = "scalar_parameter_change_changes_scenario_id_and_reproduces";
      }
      {
        label = "config read-only test";
        needle = "structured_config_tree_refs_are_read_only_content_addressed";
      }
      {
        label = "config identity test";
        needle = "config_tree_change_changes_scenario_id_and_reproduces";
      }
      {
        label = "world config-tree binding assertion";
        needle = "workload_config_trees()";
      }
      {
        label = "invalid values test";
        needle = "workload_parameterization_rejects_invalid_or_duplicate_values";
      }
      {
        label = "rootfs missing root image test";
        needle = "assert_rootfs_config_missing_root_image";
      }
      {
        label = "rootfs mismatched root image test";
        needle = "assert_rootfs_config_mismatched_root_image";
      }
      {
        label = "comma mount fixture";
        needle = "\"/etc/work,load\"";
      }
      {
        label = "serialized rejection test";
        needle = "workload_parameterization_rejects_malformed_toml_and_binary_forms";
      }
      {
        label = "canonical toml reproduction";
        needle = "ScenarioDefForm::from_canonical_toml";
      }
      {
        label = "compact binary reproduction";
        needle = "ScenarioDefForm::from_compact_binary";
      }
      {
        label = "reproduction artifact capture";
        needle = "ReproductionArtifact::capture";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 workload parameterization import";
        needle = "workloadParameterization = import ./phase4-workload-parameterization.nix";
      }
      {
        label = "phase4 workload parameterization attr path";
        needle = "checks.crucible.phase4.workloadParameterization";
      }
      {
        label = "phase4 workload parameterization task id";
        needle = "taskIds = [\"T-WL-6\"]";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 workload parameterization check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-workload-parameterization";
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
          name = "run-workload-parameterization";
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
              --target-dir "$TMPDIR/crucible-workload-parameterization-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_parameterization \
              -- --list > "$TMPDIR/workload-parameterization-tests"
            require_listed \
              "$TMPDIR/workload-parameterization-tests" \
              "scalar_workload_parameters_are_cmdline_scenario_config"
            require_listed \
              "$TMPDIR/workload-parameterization-tests" \
              "scalar_parameter_change_changes_scenario_id_and_reproduces"
            require_listed \
              "$TMPDIR/workload-parameterization-tests" \
              "structured_config_tree_refs_are_read_only_content_addressed"
            require_listed \
              "$TMPDIR/workload-parameterization-tests" \
              "config_tree_change_changes_scenario_id_and_reproduces"
            require_listed \
              "$TMPDIR/workload-parameterization-tests" \
              "workload_parameterization_rejects_invalid_or_duplicate_values"
            require_listed \
              "$TMPDIR/workload-parameterization-tests" \
              "workload_parameterization_rejects_malformed_toml_and_binary_forms"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-parameterization-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_parameterization \
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
            scalar_params=cmdline
            config_tree=read_only_content_addressed
            host_runtime_pokes=false
            reproduces=true
            RESULT
          '';
        }
      ];
    }
