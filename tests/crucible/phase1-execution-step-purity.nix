{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionStepPurity",
  taskIds ? ["T-EXEC-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  # The pure temporal-graph edge now lives in `try_step` (step delegates to it and
  # panics on the draw-cap validation error). This pins the pure-edge body — a clone
  # of the scenario def plus the appended decision, with no mutation of `config`.
  pureStepBody = "let next = Configuration {\n        def: config.def.clone(),\n        schedule: config.schedule.appended(decision),\n    };";

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "step signature";
        needle = "pub fn step(config: &Configuration, decision: Decision) -> Configuration";
      }
      {
        label = "pure step edge body";
        needle = pureStepBody;
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "parent immutability step test";
        needle = "step_appends_decision_without_mutating_parent";
      }
      {
        label = "generated step edge-constructor test";
        needle = "step_is_pure_temporal_graph_edge_constructor";
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
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-step-purity";
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
          name = "run-execution-step-purity";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-step-purity-target" \
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
