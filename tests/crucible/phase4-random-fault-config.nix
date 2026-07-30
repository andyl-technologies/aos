{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.randomFaultConfig",
  taskIds ? ["T-FAULT-14"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  randomTest = builtins.readFile ../../crates/crucible/tests/random_fault_config.rs;
  faultPlanTest = builtins.readFile ../../crates/crucible/tests/fault_plan.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-14 pinned failure evidence";
        needle = "The focused gate pins the generated failure as a concrete";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "RandomFaultConfig public type";
        needle = "pub struct RandomFaultConfig";
      }
      {
        label = "FaultWeights public type";
        needle = "pub struct FaultWeights";
      }
      {
        label = "SeverityBounds public type";
        needle = "pub struct SeverityBounds";
      }
      {
        label = "FaultCaps public type";
        needle = "pub struct FaultCaps";
      }
      {
        label = "pure world generator method";
        needle = "pub fn generate_for_world(&self, world: &World) -> Result<FaultPlan, EngineError>";
      }
      {
        label = "single seeded rng fork";
        needle = "self.seed.decision_rng().fork_in_domain";
      }
      {
        label = "weighted kind selection";
        needle = "fn draw_random_fault_kind";
      }
      {
        label = "start draw";
        needle = "fn draw_random_fault_start";
      }
      {
        label = "duration draw";
        needle = "fn draw_random_fault_duration";
      }
      {
        label = "deterministic cap pruning";
        needle = "fn prune_random_fault_candidates";
      }
      {
        label = "basis-point lowering";
        needle = "FaultRateBasisPoints::from_basis_points";
      }
      {
        label = "canonical fault-plan validation";
        needle = "FaultPlan::from_entries_for_world(world, entries)";
      }
      {
        label = "config validation error";
        needle = "RandomFaultConfigInvalid";
      }
      {
        label = "unbiased rejection sampler";
        needle = "fn draw_bounded_u64_from(";
      }
      {
        label = "forced rejection regression";
        needle = "bounded_random_fault_draw_forces_rejection_of_the_biased_prefix";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "live link id compatibility lookup";
        needle = "fn combined_network_faults_for_link";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "RandomFaultConfig crate export";
        needle = "RandomFaultConfig";
      }
      {
        label = "FaultWeights crate export";
        needle = "FaultWeights";
      }
      {
        label = "SeverityBounds crate export";
        needle = "SeverityBounds";
      }
      {
        label = "FaultCaps crate export";
        needle = "FaultCaps";
      }
    ]
    ++ failuresFor "crates/crucible/tests/random_fault_config.rs" randomTest [
      {
        label = "byte-identical generation test";
        needle = "random_fault_config_generates_byte_identical_fault_plan";
      }
      {
        label = "seed sensitivity test";
        needle = "random_fault_config_seed_changes_generated_plan";
      }
      {
        label = "weighted selection and basis-point test";
        needle = "random_fault_config_uses_weighted_kind_selection_and_basis_point_bounds";
      }
      {
        label = "caps pruning test";
        needle = "random_fault_config_prunes_partition_crash_and_concurrency_caps";
      }
      {
        label = "caps common-sequence pruning test";
        needle = "random_fault_caps_prune_common_uncapped_generation_sequence";
      }
      {
        label = "collision-safe link target test";
        needle = "random_fault_config_targets_collision_safe_world_link_ids";
      }
      {
        label = "canonical scenario pinning test";
        needle = "random_fault_config_returns_canonical_plan_and_pinned_scenario";
      }
      {
        label = "device namespace guard test";
        needle = "random_fault_config_rejects_device_only_weights_without_matching_world_devices";
      }
      {
        label = "all weighted device kinds";
        needle = "random_fault_config_generates_every_weighted_device_fault_kind";
      }
      {
        label = "mixed device weight golden plan";
        needle = "mixed_device_weights_and_fixed_draw_order_have_a_golden_plan";
      }
      {
        label = "device family target isolation";
        needle = "device_fault_target_selection_stays_within_the_selected_device_family";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_plan.rs" faultPlanTest [
      {
        label = "canonical fault through legacy live link test";
        needle = "canonical_network_fault_plan_applies_through_legacy_live_link_id";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 random fault config import";
        needle = "randomFaultConfig = import ./phase4-random-fault-config.nix";
      }
      {
        label = "phase4 random fault config attr path";
        needle = "attrPath = \"checks.crucible.phase4.randomFaultConfig\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/random_fault_config.rs" randomTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 random-fault-config check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-random-fault-config";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

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
          name = "run-random-fault-config";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-random-fault-config-target" \
              -p crucible \
              --test random_fault_config \
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
            generator=random-fault-config
            reproducible=true
            RESULT
          '';
        }
      ];
    }
