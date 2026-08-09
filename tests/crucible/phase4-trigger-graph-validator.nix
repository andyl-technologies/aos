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
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  validatorTest = builtins.readFile ../../crates/crucible/tests/trigger_graph_validator.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  # Character-exact scrub of Rust comments and string literals. The fold is
  # chunked per source line (each chunk keeps its trailing newline, and the
  # parser state — mode/depth/skip — threads across chunks) with the output
  # string forced after every chunk. A whole-file per-character fold builds a
  # haystack-deep chain of unforced `+` thunks and overflows the evaluator
  # stack on large sources.
  scrubCommentsAndStrings = content: let
    scrubChunk = chunkState: chunk: let
      length = builtins.stringLength chunk;
      charAt = index: builtins.substring index 1 chunk;
      indexes = builtins.genList (index: index) length;
      folded = builtins.foldl' step chunkState indexes;
      step = state: index:
        if state.skip
        then
          state
          // {
            skip = false;
          }
        else let
          ch = charAt index;
          next =
            if (index + 1) < length
            then charAt (index + 1)
            else "";
        in
          if state.mode == "code"
          then
            if ch == "/" && next == "/"
            then
              state
              // {
                out = state.out + "  ";
                mode = "line";
                skip = true;
              }
            else if ch == "/" && next == "*"
            then
              state
              // {
                out = state.out + "  ";
                mode = "block";
                depth = 1;
                skip = true;
              }
            else if ch == "\""
            then
              state
              // {
                out = state.out + " ";
                mode = "string";
              }
            else
              state
              // {
                out = state.out + ch;
              }
          else if state.mode == "line"
          then
            if ch == "\n"
            then
              state
              // {
                out = state.out + "\n";
                mode = "code";
              }
            else
              state
              // {
                out = state.out + " ";
              }
          else if state.mode == "block"
          then
            if ch == "/" && next == "*"
            then
              state
              // {
                out = state.out + "  ";
                depth = state.depth + 1;
                skip = true;
              }
            else if ch == "*" && next == "/"
            then
              state
              // {
                out = state.out + "  ";
                mode =
                  if state.depth == 1
                  then "code"
                  else "block";
                depth =
                  if state.depth == 1
                  then 0
                  else state.depth - 1;
                skip = true;
              }
            else
              state
              // {
                out =
                  state.out
                  + (
                    if ch == "\n"
                    then "\n"
                    else " "
                  );
              }
          else if ch == "\\" && next != ""
          then
            state
            // {
              out =
                state.out
                + " "
                + (
                  if next == "\n"
                  then "\n"
                  else " "
                );
              skip = true;
            }
          else if ch == "\""
          then
            state
            // {
              out = state.out + " ";
              mode = "code";
            }
          else
            state
            // {
              out =
                state.out
                + (
                  if ch == "\n"
                  then "\n"
                  else " "
                );
            };
    in
      # Force the accumulated output flat before the next chunk so thunk
      # depth stays bounded by the longest line, not the whole file.
      builtins.seq (builtins.stringLength folded.out) folded;
    lines = lib.splitString "\n" content;
    lineCount = builtins.length lines;
    chunkAt = index:
      builtins.elemAt lines index
      + (
        if index + 1 < lineCount
        then "\n"
        else ""
      );
    result =
      builtins.foldl'
      (state: index: scrubChunk state (chunkAt index))
      {
        out = "";
        mode = "code";
        depth = 0;
        skip = false;
      }
      (builtins.genList (index: index) lineCount);
  in
    result.out;

  taskList = builtins.concatStringsSep "," taskIds;
  validatorSources = builtins.concatStringsSep "\n" [
    (scrubCommentsAndStrings trigger)
    (scrubCommentsAndStrings validatorTest)
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
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
