{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestMarkerLeaf",
  taskIds ? ["T-TRIG-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  guestMarkerTest = builtins.readFile ../../crates/crucible/tests/guest_marker_condition_leaf.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-8 completion note";
        needle = "Completed by `checks.crucible.phase4.guestMarkerLeaf`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "MarkerId type";
        needle = "pub struct MarkerId";
      }
      {
        label = "GuestMarker predicate";
        needle = "GuestMarker {\n        /// Stable marker identity.";
      }
      {
        label = "guest marker constructor";
        needle = "pub fn guest_marker(marker: MarkerId) -> Self";
      }
      {
        label = "guest marker TOML";
        needle = "PredicateTomlKind::GuestMarker";
      }
      {
        label = "guest marker binary tag";
        needle = "writer.write_u8(1);";
      }
      {
        label = "guest marker material";
        needle = "predicate=guest-marker";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "guest marker observable constructor";
        needle = "pub fn guest_marker(";
      }
      {
        label = "guest marker event point derived from icount";
        needle = "ticks: retired_icount.retired";
      }
      {
        label = "guest marker observable payload";
        needle = "ObservableEventPayload::GuestMarker";
      }
      {
        label = "guest marker carries retired icount";
        needle = "retired_icount: Icount";
      }
      {
        label = "guest marker carries node";
        needle = "node: NodeId";
      }
      {
        label = "authoritative white-box policy hook";
        needle = "fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy>";
      }
      {
        label = "world white-box policy injection";
        needle = "pub fn with_world_white_box_policies";
      }
      {
        label = "GuestMarker evaluation";
        needle = "Condition::GuestMarker { marker }";
      }
      {
        label = "guest marker matcher";
        needle = "fn guest_marker_event_matches";
      }
      {
        label = "white-box opt-in gate";
        needle = "evaluator.white_box_policy_for_node(node) == Some(WhiteBoxPolicy::Enabled)";
      }
      {
        label = "world-aware event graph constructor";
        needle = "pub fn new_for_world(events: Vec<Event>, world: &World) -> Result<Self, EventGraphError>";
      }
      {
        label = "internal white-box node helper";
        needle = "fn new_with_assertions_and_world";
      }
      {
        label = "guest marker graph validation error";
        needle = "GuestMarkerWithoutWhiteBoxOptIn";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "guest marker property validation error";
        needle = "PropertyPredicateGuestMarkerRequiresWhiteBoxOptIn";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_marker_condition_leaf.rs" guestMarkerTest [
      {
        label = "enabled doorbell marker test";
        needle = "guest_marker_observes_enabled_doorbell_marker_at_retirement_icount";
      }
      {
        label = "isolated negative tests";
        needle = "guest_marker_rejects_wrong_marker_disabled_opt_in_and_wrong_time_in_isolation";
      }
      {
        label = "retirement icount event-point test";
        needle = "guest_marker_event_point_is_doorbell_retirement_icount";
      }
      {
        label = "authoritative node opt-in test";
        needle = "guest_marker_names_are_global_but_emitting_node_must_be_opted_in";
      }
      {
        label = "event graph firing";
        needle = "event_graph_fires_from_guest_marker_without_named_leaf_fallback";
      }
      {
        label = "disabled world graph rejection";
        needle = "event_graph_rejects_guest_marker_without_white_box_world";
      }
      {
        label = "no-world graph rejection";
        needle = "event_graph_rejects_guest_marker_without_world_backed_constructor";
      }
      {
        label = "zero guest marker support";
        needle = "zero_guest_marker_conditions_run_without_guest_marker_support";
      }
      {
        label = "additive guest marker event";
        needle = "zero_guest_marker_conditions_ignore_guest_marker_events";
      }
      {
        label = "serialization roundtrip";
        needle = "guest_marker_round_trips_through_properties_serialization";
      }
      {
        label = "disabled world property rejection";
        needle = "guest_marker_properties_require_a_white_box_enabled_world";
      }
      {
        label = "content material distinction";
        needle = "guest_marker_material_distinguishes_marker_names";
      }
      {
        label = "no fallback panic";
        needle = "guest-marker leaf must be event-backed, not leaf-oracle backed";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes guest marker leaf check";
        needle = "guestMarkerLeaf = import ./phase4-guest-marker-leaf.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "guest marker oracle fallback";
        needle = "evaluator.leaf_is_true(ConditionLeaf::GuestMarker";
      }
      {
        label = "self-attested guest marker payload policy";
        needle = "ObservableEventPayload::GuestMarker {\n                retired_icount,\n                node,\n                marker,\n                white_box,";
      }
      {
        label = "public arbitrary white-box node graph constructor";
        needle = "pub fn new_with_assertions_and_world";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/guest_marker_condition_leaf.rs" guestMarkerTest [
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
  then throw "crucible phase4 guest-marker-leaf check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-marker-leaf";
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
          name = "run-guest-marker-leaf";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-marker-leaf-target" \
              -p crucible \
              --test guest_marker_condition_leaf \
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
            guest_marker_source=white-box-doorbell-observable-event
            zero_guest_marker_conditions=validated
            RESULT
          '';
        }
      ];
    }
