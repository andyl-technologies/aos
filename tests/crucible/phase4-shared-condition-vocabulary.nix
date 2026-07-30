{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.sharedConditionVocabulary",
  taskIds ? ["T-TRIG-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  sharedTest = builtins.readFile ../../crates/crucible/tests/condition_vocabulary_shared.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-2 completion note";
        needle = "Completed by `checks.crucible.phase4.sharedConditionVocabulary`";
      }
      {
        label = "condition has exactly two consumers";
        needle = "exactly two consumers";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "assertion doc references single Condition type";
        needle = "The **predicate** here is not a second vocabulary";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "trigger Condition aliases Predicate";
        needle = "pub type Condition = Predicate";
      }
      {
        label = "shared evaluator trait";
        needle = "pub trait ConditionEvaluator";
      }
      {
        label = "shared evaluator struct";
        needle = "pub struct ConditionEvaluation";
      }
      {
        label = "shared evaluator entrypoint";
        needle = "pub fn evaluate_assertion_condition";
      }
      {
        label = "shared evaluator is non-overridable";
        needle = "Implementors\n/// of [`ConditionEvaluator`] provide leaf truth, deterministic observation";
      }
      {
        label = "event graph uses shared evaluator";
        needle = "evaluate_condition(&mut graph_evaluator, condition)";
      }
      {
        label = "trigger doc names shared vocabulary";
        needle = "Shared predicate vocabulary used by both assertions and event triggers.";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "shared predicate doc";
        needle = "The shared declarative predicate vocabulary used by properties and triggers.";
      }
      {
        label = "single predicate enum";
        needle = "pub enum Predicate";
      }
      {
        label = "named predicate constructor";
        needle = "pub fn named(name: impl Into<String>) -> Self";
      }
      {
        label = "node-qualified predicate constructor";
        needle = "pub fn named_for_nodes(name: impl Into<String>, nodes: Vec<NodeId>) -> Self";
      }
      {
        label = "guest marker constructor";
        needle = "pub fn guest_marker(marker: MarkerId) -> Self";
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
        label = "assertion properties use Predicate";
        needle = "predicate: Predicate";
      }
      {
        label = "eventually trigger uses Predicate";
        needle = "trigger: Predicate";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "Predicate export";
        needle = "Predicate";
      }
      {
        label = "Condition export";
        needle = "Condition";
      }
    ]
    ++ failuresFor "crates/crucible/tests/condition_vocabulary_shared.rs" sharedTest [
      {
        label = "assertion predicate usable as trigger test";
        needle = "predicate_used_by_assertion_is_the_trigger_condition_type";
      }
      {
        label = "identical evaluation function test";
        needle = "trigger_and_assertion_evaluation_use_the_same_predicate_function";
      }
      {
        label = "eventually predicate reuse test";
        needle = "eventually_trigger_and_property_predicates_are_trigger_usable";
      }
      {
        label = "properties accept shared compound condition test";
        needle = "properties_accept_the_same_compound_condition_shape_as_triggers";
      }
      {
        label = "Condition and Predicate same assignment";
        needle = "let condition: Condition = Predicate::all_of";
      }
      {
        label = "trigger receives shared condition";
        needle = "Some(condition.clone())";
      }
      {
        label = "guest-marker trigger uses world-backed graph validation";
        needle = "EventGraph::new_with_assertions_for_world";
      }
      {
        label = "assertion receives shared condition";
        needle = "predicate: condition.clone()";
      }
      {
        label = "assertion and trigger use same evaluator method";
        needle = ".evaluate_assertion_condition(";
      }
      {
        label = "eventually trigger and property extracted";
        needle = "vec![trigger, property]";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes shared condition vocabulary check";
        needle = "sharedConditionVocabulary = import ./phase4-shared-condition-vocabulary.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "separate trigger-only Condition enum";
        needle = "pub enum Condition {";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/condition_vocabulary_shared.rs" sharedTest [
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
      {
        label = "fabricated white-box namespace constructor";
        needle = "new_with_assertions_and_world";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 shared-condition-vocabulary check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-shared-condition-vocabulary";
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
          name = "run-shared-condition-vocabulary";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shared-condition-vocabulary-target" \
              -p crucible \
              --test condition_vocabulary_shared \
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
            shared_type=crucible::Predicate
            trigger_alias=crucible::Condition
            consumers=assertion,trigger
            RESULT
          '';
        }
      ];
    }
