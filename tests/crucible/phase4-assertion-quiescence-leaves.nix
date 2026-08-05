{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionQuiescenceLeaves",
  taskIds ? ["T-TRIG-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  assertionTest = builtins.readFile ../../crates/crucible/tests/assertion_quiescence_leaves.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-7 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionQuiescenceLeaves`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "AssertionPhase type";
        needle = "pub enum AssertionPhase";
      }
      {
        label = "AssertionState predicate";
        needle = "AssertionState {\n        /// Assertion identity whose state transition is observed.";
      }
      {
        label = "Quiescent predicate";
        needle = "Quiescent";
      }
      {
        label = "assertion-state constructor";
        needle = "pub fn assertion_state(name: AssertionId, state: AssertionPhase) -> Self";
      }
      {
        label = "quiescent constructor";
        needle = "pub const fn quiescent() -> Self";
      }
      {
        label = "unknown assertion property error";
        needle = "PropertyPredicateUnknownAssertion";
      }
      {
        label = "assertion-state validates declared assertion";
        needle = "Predicate::AssertionState { name, .. }";
      }
      {
        label = "quiescent property predicate";
        needle = "Predicate::At { .. }\n        | Predicate::NetworkMatch { .. }\n        | Predicate::Quiescent\n        | Predicate::FaultActive { .. } => Ok(())";
      }
      {
        label = "assertion-state TOML";
        needle = "PredicateTomlKind::AssertionState";
      }
      {
        label = "quiescent TOML";
        needle = "PredicateTomlKind::Quiescent";
      }
      {
        label = "assertion phase TOML";
        needle = "enum AssertionPhaseToml";
      }
      {
        label = "assertion-state binary tag";
        needle = "writer.write_u8(15);";
      }
      {
        label = "quiescent binary tag";
        needle = "writer.write_u8(16);";
      }
      {
        label = "assertion-state material";
        needle = "predicate=assertion-state";
      }
      {
        label = "quiescent material";
        needle = "predicate=quiescent";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "assertion observable constructor";
        needle = "pub fn assertion_state_changed";
      }
      {
        label = "assertion observable payload";
        needle = "ObservableEventPayload::AssertionStateChanged";
      }
      {
        label = "scheduler quiescence evidence hook";
        needle = "fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence>";
      }
      {
        label = "scheduler quiescence evaluator builder";
        needle = "pub fn with_scheduler_quiescence";
      }
      {
        label = "AssertionState evaluation";
        needle = "Condition::AssertionState { name, state }";
      }
      {
        label = "assertion state matcher";
        needle = "fn assertion_state_event_matches";
      }
      {
        label = "Quiescent evaluation";
        needle = "Condition::Quiescent => evaluator";
      }
      {
        label = "quiescent sourced from scheduler evidence";
        needle = ".is_some_and(SchedulerQuiescence::is_quiescent)";
      }
      {
        label = "graph assertion declarations";
        needle = "pub fn new_with_assertions";
      }
      {
        label = "graph unknown assertion error";
        needle = "UnknownAssertionReference";
      }
      {
        label = "graph evaluator delegates scheduler evidence";
        needle = "self.inner.scheduler_quiescence()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "AssertionPhase export";
        needle = "AssertionPhase";
      }
      {
        label = "SchedulerQuiescence export";
        needle = "SchedulerQuiescence";
      }
      {
        label = "SchedulerQuiescenceBlocker export";
        needle = "SchedulerQuiescenceBlocker";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_quiescence_leaves.rs" assertionTest [
      {
        label = "current assertion event test";
        needle = "assertion_state_observes_current_causal_entry";
      }
      {
        label = "isolated assertion negative tests";
        needle = "assertion_state_rejects_wrong_state_assertion_and_time_in_isolation";
      }
      {
        label = "assertion event payload test";
        needle = "assertion_state_event_carries_virtual_time_name_and_phase";
      }
      {
        label = "scheduler evidence test";
        needle = "quiescent_uses_scheduler_owned_evidence";
      }
      {
        label = "scheduler-computed quiescence bridge test";
        needle = "quiescent_leaf_consumes_scheduler_computed_quiescence";
      }
      {
        label = "real scheduler quiescence API";
        needle = ".quiescence()";
      }
      {
        label = "assertion-state event graph firing";
        needle = "event_graph_fires_from_assertion_state_with_declared_assertion";
      }
      {
        label = "unknown assertion graph validation";
        needle = "event_graph_rejects_undeclared_assertion_state_reference";
      }
      {
        label = "quiescent event graph firing";
        needle = "event_graph_fires_from_quiescent_scheduler_evidence";
      }
      {
        label = "property assertion validation";
        needle = "properties_validate_assertion_state_references";
      }
      {
        label = "serialization roundtrip";
        needle = "assertion_state_and_quiescent_round_trip_through_properties_serialization";
      }
      {
        label = "content material distinction";
        needle = "assertion_state_material_distinguishes_assertion_name_and_phase";
      }
      {
        label = "no named or guest fallback";
        needle = "assertion-state and quiescence leaves must not require named or guest-marker resolution";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes assertion/quiescence leaf check";
        needle = "assertionQuiescenceLeaves = import ./phase4-assertion-quiescence-leaves.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/assertion_quiescence_leaves.rs" assertionTest [
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
    ];
in
  if failures != []
  then throw "crucible phase4 assertion-quiescence-leaves check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-assertion-quiescence-leaves";
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
          name = "run-assertion-quiescence-leaves";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-assertion-quiescence-leaves-target" \
              -p crucible \
              --test assertion_quiescence_leaves \
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
            assertion_state_source=causal-assertion-state-changed-event
            quiescence_source=scheduler-quiescence-evidence
            RESULT
          '';
        }
      ];
    }
