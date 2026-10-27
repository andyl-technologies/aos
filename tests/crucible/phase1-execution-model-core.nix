{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionModelCore",
  taskIds ? ["T-EXEC-1"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  model = import ./_crucible-model-source.nix {inherit lib;};
  canonical = builtins.readFile ../../crates/crucible/crucible-engine/src/model/canonical.rs;
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible/crucible-engine/src/model.rs" model [
      {
        label = "ScenarioDef type";
        needle = "pub struct ScenarioDef";
      }
      {
        label = "Configuration type";
        needle = "pub struct Configuration";
      }
      {
        label = "Schedule type";
        needle = "pub struct Schedule";
      }
      {
        label = "Decision type";
        needle = "pub enum Decision";
      }
      {
        label = "genesis constructor";
        needle = "pub fn genesis(def: ScenarioDef) -> Self";
      }
      {
        label = "RFC-named configuration id";
        needle = "pub fn id(&self) -> ContentHash";
      }
      {
        label = "content-addressed configuration identity";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/model/canonical.rs" canonical [
      {
        label = "configuration hash function";
        needle = "pub(super) fn configuration_hash(configuration: &Configuration) -> ContentHash";
      }
      {
        label = "scenario id in configuration hash";
        needle = "write_content_hash(&mut hasher, &configuration.def.id());";
      }
      {
        label = "schedule in configuration hash";
        needle = "write_schedule(&mut hasher, &configuration.schedule);";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/lib.rs" crateRoot [
      {
        label = "configuration identity test";
        needle = "configuration_id_is_content_addressed_by_def_and_schedule";
      }
      {
        label = "generated configuration identity property";
        needle = "configuration_id_property_covers_generated_def_schedule_pairs";
      }
      {
        label = "generated property case count";
        needle = "for seed in 0..64";
      }
      {
        label = "generated schedule corpus";
        needle = "generated_schedule(seed, 6)";
      }
      {
        label = "generated changed schedule";
        needle = "generated_decision(seed, 99)";
      }
      {
        label = "same-length changed schedule";
        needle = "same_length_changed_schedule";
      }
      {
        label = "same-length reordered schedule";
        needle = "reordered_schedule";
      }
      {
        label = "same-length schedule assertion";
        needle = "same_length_changed_schedule.schedule.len()";
      }
      {
        label = "schedule order variation helper";
        needle = "fn swap_first_two_decisions(schedule: &Schedule) -> Schedule";
      }
      {
        label = "equal id assertion";
        needle = "assert_eq!(base.id(), same.id());";
      }
      {
        label = "unequal schedule id assertion";
        needle = "assert_ne!(base.id(), changed_schedule.id());";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes execution-model core check";
        needle = "executionModelCore = import ./phase1-execution-model-core.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution-model core check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-execution-model-core";

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-execution-model-core";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-engine \
              --lib \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            types=ScenarioDef,Configuration,Schedule,Decision
            identity=Configuration::id
            rust_test=crucible_engine::configuration_id_is_content_addressed_by_def_and_schedule
            RESULT
          '';
        }
      ];
    }
