{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerPlanLowering",
  taskIds ? ["T-TRIG-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  planLoweringTest = builtins.readFile ../../crates/crucible/tests/trigger_plan_lowering.rs;
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
  planLoweringSources = builtins.concatStringsSep "\n" [
    (scrubCommentsAndStrings trigger)
    (scrubCommentsAndStrings libRs)
    (scrubCommentsAndStrings planLoweringTest)
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-16 completion note";
        needle = "Completed by `checks.crucible.phase4.triggerPlanLowering`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "lowered Plan graph wrapper";
        needle = "pub struct LoweredPlanEventGraph";
      }
      {
        label = "Plan lowering API";
        needle = "pub fn lower_to_event_graph_for_world";
      }
      {
        label = "activation lowering arm";
        needle = "PlanEntry::Activate";
      }
      {
        label = "heal lowering arm";
        needle = "PlanEntry::Heal";
      }
      {
        label = "pure At trigger lowering";
        needle = "Condition::At { at: *at }";
      }
      {
        label = "source Plan hash identity";
        needle = "content_hash: self.content_hash()";
      }
      {
        label = "source Plan canonical bytes identity";
        needle = "canonical_bytes: self.canonical_bytes()";
      }
      {
        label = "evaluation time collection";
        needle = "fn plan_evaluation_times";
      }
      {
        label = "world-validated lowered graph";
        needle = "EventGraph::new_for_world(events, world)";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "lowering wrapper exported";
        needle = "LoweredPlanEventGraph";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_plan_lowering.rs" planLoweringTest [
      {
        label = "identity-preserving lowering test";
        needle = "plan_lowers_to_identity_preserving_at_triggered_fault_events";
      }
      {
        label = "scheduler reduction equivalence test";
        needle = "lowered_plan_graph_reduces_to_the_same_fault_state_as_plan_entries";
      }
      {
        label = "same-time canonical firing order";
        needle = "same-time Plan entries must fire in canonical lowered order";
      }
      {
        label = "same-time canonical activation before heal";
        needle = "plan:0000000000000002:activate:crash-db-1";
      }
      {
        label = "lowering API exercised";
        needle = "lower_to_event_graph_for_world";
      }
      {
        label = "content hash identity asserted";
        needle = "lowered.content_hash(), plan.content_hash()";
      }
      {
        label = "canonical byte identity asserted";
        needle = "lowered.canonical_bytes(), plan.canonical_bytes()";
      }
      {
        label = "observation event composition";
        needle = "observe-ready";
      }
      {
        label = "scheduler evaluation boundaries";
        needle = "append_evaluation_boundary";
      }
      {
        label = "scheduler trigger action application";
        needle = "apply_trigger_firings";
      }
      {
        label = "Plan-state oracle";
        needle = "plan_active_faults_at";
      }
      {
        label = "black-box observation composition";
        needle = "Predicate::console_match";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes trigger Plan lowering check";
        needle = "triggerPlanLowering = import ./phase4-trigger-plan-lowering.nix";
      }
    ]
    ++ forbiddenFor "trigger Plan lowering sources" planLoweringSources [
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
  then throw "crucible phase4 trigger-Plan-lowering check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-trigger-plan-lowering";
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
          name = "run-trigger-plan-lowering";
          script = ''
            cargo test \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test trigger_plan_lowering \
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
              echo "gate=phase4-trigger-plan-lowering"
              echo "plan_hash_identity_preserved=true"
              echo "pure_at_plan_reduces_as_event_graph=true"
              echo "observation_event_preserves_lowered_plan_prefix=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
