{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.observableConditionLeaves",
  taskIds ? ["T-TRIG-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  observableTest = builtins.readFile ../../crates/crucible/tests/observable_condition_leaves.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-4 completion note";
        needle = "Completed by `checks.crucible.phase4.observableConditionLeaves`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "NetworkMatch predicate";
        needle = "NetworkMatch {\n        /// Optional link to constrain the delivered frame.";
      }
      {
        label = "ConsoleMatch predicate";
        needle = "ConsoleMatch {\n        /// Node whose console output is observed.";
      }
      {
        label = "IoPattern predicate";
        needle = "IoPattern {\n        /// Node whose deterministic I/O completion is observed.";
      }
      {
        label = "NodeState predicate";
        needle = "NodeState {\n        /// Node whose lifecycle is observed.";
      }
      {
        label = "FramePredicate type";
        needle = "pub enum FramePredicate";
      }
      {
        label = "RegexProgram type";
        needle = "pub struct RegexProgram";
      }
      {
        label = "IoEventKind type";
        needle = "pub enum IoEventKind";
      }
      {
        label = "NodeLifecycle type";
        needle = "pub enum NodeLifecycle";
      }
      {
        label = "network constructor";
        needle = "pub fn network_match(link: Option<LinkId>, predicate: FramePredicate) -> Self";
      }
      {
        label = "console constructor";
        needle = "pub fn console_match(node: NodeId, regex: RegexProgram) -> Self";
      }
      {
        label = "io constructor";
        needle = "pub fn io_pattern(node: NodeId, kind: IoEventKind) -> Self";
      }
      {
        label = "node state constructor";
        needle = "pub fn node_state(node: NodeId, state: NodeLifecycle) -> Self";
      }
      {
        label = "observable TOML network";
        needle = "PredicateTomlKind::NetworkMatch";
      }
      {
        label = "observable binary tag network";
        needle = "writer.write_u8(9);";
      }
      {
        label = "observable binary tag node state";
        needle = "writer.write_u8(12);";
      }
      {
        label = "frame bytes canonical material";
        needle = "frame_predicate_material(predicate)";
      }
      {
        label = "observable properties validate nodes";
        needle = "Predicate::CoveragePoint { node, .. }\n        | Predicate::MemoryPredicate { node, .. }\n        | Predicate::IoPattern { node, .. }\n        | Predicate::NodeState { node, .. }";
      }
      {
        label = "invalid regex property error";
        needle = "PropertyPredicateInvalidRegex";
      }
      {
        label = "property regex validation";
        needle = "fn validate_property_regex";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "observable event type";
        needle = "pub struct ObservableEvent";
      }
      {
        label = "observable event payload";
        needle = "pub enum ObservableEventPayload";
      }
      {
        label = "observable evaluator hook";
        needle = "fn observable_events(&self) -> &[ObservableEvent]";
      }
      {
        label = "checked observable log prefix";
        needle = "pub struct ConditionEventLogPrefix";
      }
      {
        label = "checked scheduler event-log prefix constructor";
        needle = "pub(crate) fn from_scheduler_event_log_entries";
      }
      {
        label = "NetworkMatch evaluation";
        needle = "Condition::NetworkMatch { link, predicate }";
      }
      {
        label = "ConsoleMatch evaluation";
        needle = "Condition::ConsoleMatch { node, regex }";
      }
      {
        label = "IoPattern evaluation";
        needle = "Condition::IoPattern { node, kind }";
      }
      {
        label = "NodeState evaluation";
        needle = "Condition::NodeState { node, state }";
      }
      {
        label = "network payload delivery";
        needle = "ObservableEventPayload::NetworkDelivered";
      }
      {
        label = "regex byte matching";
        needle = "regex::bytes::Regex::new";
      }
      {
        label = "console stream matcher";
        needle = "fn console_stream_matches";
      }
      {
        label = "console stream only fires on current chunk";
        needle = "matched.end() > current_start";
      }
      {
        label = "invalid regex event graph error";
        needle = "InvalidRegex";
      }
      {
        label = "observable events delegated through graph evaluator";
        needle = "self.inner.observable_events()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "FramePredicate export";
        needle = "FramePredicate";
      }
      {
        label = "RegexProgram export";
        needle = "RegexProgram";
      }
      {
        label = "ObservableEvent export";
        needle = "ObservableEvent";
      }
      {
        label = "ObservableEventPayload export";
        needle = "ObservableEventPayload";
      }
    ]
    ++ failuresFor "crates/crucible/tests/observable_condition_leaves.rs" observableTest [
      {
        label = "network delivered frame test";
        needle = "network_match_observes_delivered_frame_payload_at_the_evaluation_point";
      }
      {
        label = "any link network test";
        needle = "network_match_can_observe_any_link";
      }
      {
        label = "console regex test";
        needle = "console_match_uses_host_side_regex_over_captured_console_bytes";
      }
      {
        label = "split console stream test";
        needle = "console_match_spans_chunks_and_fires_when_match_completes_at_point";
      }
      {
        label = "invalid regex rejection test";
        needle = "invalid_console_regex_is_rejected_by_graph_and_properties";
      }
      {
        label = "io pattern test";
        needle = "io_pattern_observes_deterministic_io_completion_kind";
      }
      {
        label = "io any test";
        needle = "io_pattern_any_matches_any_completion_kind_for_the_node";
      }
      {
        label = "node state test";
        needle = "node_state_observes_lifecycle_transition";
      }
      {
        label = "event graph observable firing test";
        needle = "event_graph_fires_from_observable_condition_without_guest_marker_support";
      }
      {
        label = "observable serialization roundtrip";
        needle = "observable_leaves_round_trip_through_properties_serialization";
      }
      {
        label = "observable content material distinction";
        needle = "observable_leaf_material_distinguishes_predicate_payloads";
      }
      {
        label = "observable event prefix construction";
        needle = "support::evaluation_with_observables";
      }
      {
        label = "no guest marker fallback";
        needle = "observable leaves must not require named or guest-marker leaf resolution";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes observable condition leaves check";
        needle = "observableConditionLeaves = import ./phase4-observable-condition-leaves.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/observable_condition_leaves.rs" observableTest [
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
  then throw "crucible phase4 observable-condition-leaves check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-observable-condition-leaves";
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
          name = "run-observable-condition-leaves";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-observable-condition-leaves-target" \
              -p crucible \
              --test observable_condition_leaves \
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
            observable_leaves=network-match,console-match,io-pattern,node-state
            event_source=typed-observable-event-log-prefix
            RESULT
          '';
        }
      ];
    }
