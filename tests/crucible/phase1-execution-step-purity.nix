{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionStepPurity",
  taskIds ? ["T-EXEC-3"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  # The pure temporal-graph edge lives in `try_step`, which reports draw-cap
  # validation errors. This pins the pure-edge body: a clone of the scenario def
  # plus the appended decision, with no mutation of `config`.
  pureStepBody = "let next = Configuration {\n        def: config.def.clone(),\n        schedule: config.schedule.appended(decision),\n    };";

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "checked step signature";
        needle = "pub fn try_step(config: &Configuration, decision: Decision) -> Result<Configuration, EngineError>";
      }
      {
        label = "pure step edge body";
        needle = pureStepBody;
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "parent immutability step test";
        needle = "try_step_appends_decision_without_mutating_parent";
      }
      {
        label = "generated step edge-constructor test";
        needle = "try_step_is_pure_temporal_graph_edge_constructor";
      }
      {
        label = "generated step corpus";
        needle = "for seed in 0..64";
      }
      {
        label = "parent unchanged assertion";
        needle = "assert_eq!(parent, original_parent);";
      }
      {
        label = "child keeps scenario def";
        needle = "assert_eq!(child.def, parent.def);";
      }
      {
        label = "child schedule is parent prefix";
        needle = "child.schedule.prefix(parent.schedule.len())";
      }
      {
        label = "child appends decision";
        needle = "assert_eq!(child.schedule.decisions().last(), Some(&decision));";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes execution step-purity check";
        needle = "executionStepPurity = import ./phase1-execution-step-purity.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution step-purity check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-execution-step-purity";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-execution-step-purity";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible \
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
            operation=step
            purity=no-io-no-boot-no-materialization
            edge=parent-schedule-plus-one-decision
            RESULT
          '';
        }
      ];
    }
