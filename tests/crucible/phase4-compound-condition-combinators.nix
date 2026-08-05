{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.compoundConditionCombinators",
  taskIds ? ["T-TRIG-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  compoundTest = builtins.readFile ../../crates/crucible/tests/compound_condition_combinators.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-9 completion note";
        needle = "Completed by `checks.crucible.phase4.compoundConditionCombinators`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "all-of predicate variant";
        needle = "AllOf {\n        /// Predicates that must all hold.";
      }
      {
        label = "any-of predicate variant";
        needle = "AnyOf {\n        /// Predicates where at least one must hold.";
      }
      {
        label = "once predicate variant";
        needle = "Once {\n        /// Predicate being latched.";
      }
      {
        label = "not predicate variant";
        needle = "Not {\n        /// Predicate being negated.";
      }
      {
        label = "all-of constructor";
        needle = "pub fn all_of(predicates: Vec<Predicate>) -> Self";
      }
      {
        label = "any-of constructor";
        needle = "pub fn any_of(predicates: Vec<Predicate>) -> Self";
      }
      {
        label = "once constructor";
        needle = "pub fn once(predicate: Predicate) -> Self";
      }
      {
        label = "not constructor";
        needle = "pub fn not(predicate: Predicate) -> Self";
      }
      {
        label = "property empty compound validation";
        needle = "PropertyPredicateEmptyCompound";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "all-of evaluation";
        needle = "Condition::AllOf { predicates }";
      }
      {
        label = "all-of no short-circuit latch traversal";
        needle = "all_true &= evaluate_condition(evaluator, condition);";
      }
      {
        label = "any-of evaluation";
        needle = "Condition::AnyOf { predicates }";
      }
      {
        label = "any-of no short-circuit latch traversal";
        needle = "any_true |= evaluate_condition(evaluator, condition);";
      }
      {
        label = "once latch evaluation";
        needle = "Condition::Once { predicate }";
      }
      {
        label = "once latch hook";
        needle = "fn once_condition_is_latched(&self, condition: &Condition) -> bool;";
      }
      {
        label = "once latch record hook";
        needle = "fn latch_once_condition(&mut self, condition: &Condition);";
      }
      {
        label = "once latch state";
        needle = "once_latches: Vec<Condition>";
      }
      {
        label = "not evaluation";
        needle = "Condition::Not { predicate } => !evaluate_condition(evaluator, predicate)";
      }
      {
        label = "empty compound event graph error";
        needle = "EmptyCompound";
      }
      {
        label = "compound validator";
        needle = "fn validate_compound_condition_references";
      }
    ]
    ++ failuresFor "crates/crucible/tests/compound_condition_combinators.rs" compoundTest [
      {
        label = "nested combinator test";
        needle = "compound_combinators_nest_arbitrarily";
      }
      {
        label = "all-of latch non-short-circuit test";
        needle = "once_latches_after_inner_was_true_even_when_all_of_was_false";
      }
      {
        label = "any-of latch non-short-circuit test";
        needle = "once_inside_any_of_observes_non_short_circuited_branch";
      }
      {
        label = "shared once latch test";
        needle = "equivalent_once_conditions_share_latch_state_across_events";
      }
      {
        label = "empty compound build rejection test";
        needle = "event_graph_rejects_empty_all_of_and_any_of_at_build_time";
      }
      {
        label = "property empty compound rejection test";
        needle = "properties_reject_empty_all_of_and_any_of_at_build_time";
      }
      {
        label = "nested empty any-of rejection";
        needle = "Predicate::not(Predicate::any_of(Vec::new()))";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes compound combinator check";
        needle = "compoundConditionCombinators = import ./phase4-compound-condition-combinators.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/compound_condition_combinators.rs" compoundTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "default non-latching once query";
        needle = "fn once_condition_is_latched(&self, condition: &Condition) -> bool {\n        let _ = condition;\n        false\n    }";
      }
      {
        label = "default no-op once latch";
        needle = "fn latch_once_condition(&mut self, condition: &Condition) {\n        let _ = condition;\n    }";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 compound-condition-combinators check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-compound-condition-combinators";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-compound-condition-combinators";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-compound-condition-combinators-target" \
              -p crucible \
              --test compound_condition_combinators \
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
            component=crucible-trigger
            compound_combinators=all-of,any-of,once,not
            once_latch=event-graph-state
            empty_compounds=rejected-at-build-time
            RESULT
          '';
        }
      ];
    }
