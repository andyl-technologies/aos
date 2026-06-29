{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerGraphValidator",
  taskIds ? ["T-TRIG-15"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  trigger = builtins.readFile ../../crates/crucible/src/trigger.rs;
  validatorTest = builtins.readFile ../../crates/crucible/tests/trigger_graph_validator.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  validatorSources = builtins.concatStringsSep "\n" [
    trigger
    validatorTest
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-15 checked off";
        needle = "- [x] **T-TRIG-15**";
      }
      {
        label = "T-TRIG-15 completion note";
        needle = "Completed by `checks.crucible.phase4.triggerGraphValidator`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "world-required node error";
        needle = "NodeReferenceRequiresWorld";
      }
      {
        label = "world-required link error";
        needle = "LinkReferenceRequiresWorld";
      }
      {
        label = "unknown node error";
        needle = "UnknownNodeReference";
      }
      {
        label = "unknown link error";
        needle = "UnknownLinkReference";
      }
      {
        label = "unknown fault tag error";
        needle = "UnknownFaultTagReference";
      }
      {
        label = "non-repeatable cycle error";
        needle = "NonRepeatableCycle";
      }
      {
        label = "unreachable event error";
        needle = "UnreachableEvent";
      }
      {
        label = "topology helper";
        needle = "EventGraphTopology";
      }
      {
        label = "membership fault reference validator";
        needle = "fn validate_membership_fault_reference";
      }
      {
        label = "canonical link id helper";
        needle = "fn link_id_for_endpoint_pair";
      }
      {
        label = "dependency validator entrypoint";
        needle = "fn validate_event_graph_dependencies";
      }
      {
        label = "non-repeatable cycle validator";
        needle = "fn validate_non_repeatable_cycles";
      }
      {
        label = "cycle DFS visitor";
        needle = "fn visit_non_repeatable_event";
      }
      {
        label = "cycle gray mark";
        needle = "DfsMark::Gray";
      }
      {
        label = "reachability validator";
        needle = "fn validate_event_reachability";
      }
      {
        label = "injected fault tag collection";
        needle = "fn injected_fault_tags";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_graph_validator.rs" validatorTest [
      {
        label = "dangling topology and tag test";
        needle = "validator_rejects_dangling_topology_and_fault_tag_references";
      }
      {
        label = "dangling injected fault topology test";
        needle = "validator_rejects_injected_faults_with_unknown_nodes_or_links";
      }
      {
        label = "empty compound error locality test";
        needle = "validator_rejects_empty_compounds_with_local_event_errors";
      }
      {
        label = "non-repeatable cycle test";
        needle = "validator_rejects_non_repeatable_after_cycles";
      }
      {
        label = "unreachable event test";
        needle = "validator_rejects_unreachable_events_after_cycle_exclusions";
      }
      {
        label = "repeatable feedback acceptance test";
        needle = "validator_accepts_reachable_repeatable_feedback";
      }
      {
        label = "world-aware validation exercised";
        needle = "EventGraph::new_for_world";
      }
      {
        label = "unknown link fixture";
        needle = "db-0--db-2";
      }
      {
        label = "world-required error assertion";
        needle = "EventGraphError::NodeReferenceRequiresWorld";
      }
      {
        label = "world-required link error assertion";
        needle = "EventGraphError::LinkReferenceRequiresWorld";
      }
      {
        label = "missing injected partition link fixture";
        needle = "partition-without-link";
      }
      {
        label = "cycle error assertion";
        needle = "EventGraphError::NonRepeatableCycle";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes trigger graph validator check";
        needle = "triggerGraphValidator = import ./phase4-trigger-graph-validator.nix";
      }
    ]
    ++ forbiddenFor "trigger graph validator sources" validatorSources [
      {
        label = "trigger action decision variant";
        needle = "Decision::Trigger";
      }
      {
        label = "host wall clock";
        needle = "std::time";
      }
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
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
  then throw "crucible phase4 trigger-graph-validator check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-trigger-graph-validator";
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
          name = "run-trigger-graph-validator";
          script = ''
            cargo test \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test trigger_graph_validator \
              -- --test-threads=1
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/nix-support"
            {
              echo "attr=${attrPath}"
              echo "tasks=${taskList}"
              echo "gate=phase4-trigger-graph-validator"
              echo "topology_refs_validate_against_world=true"
              echo "non_repeatable_cycles_reject_before_run=true"
              echo "unreachable_events_reject_before_run=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
