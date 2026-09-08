{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.observedStateMaterialization",
  taskIds ? ["T-ASRT-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  crateRoot = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  observedStateTest = builtins.readFile ../../crates/crucible/tests/observed_state_materialization.rs;
  deterministicConditionTest = builtins.readFile ../../crates/crucible/tests/deterministic_condition_evaluation.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
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
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-4 completion note";
        needle = "Completed by `checks.crucible.phase4.observedStateMaterialization`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "observed state view";
        needle = "pub struct ObservedState<'log>";
      }
      {
        label = "observed state from checked prefix";
        needle = "pub fn observed_state(&self) -> ObservedState<'_>";
      }
      {
        label = "observable events view";
        needle = "pub fn observable_events(self) -> &'log [ObservableEvent]";
      }
      {
        label = "ordering facts view";
        needle = "pub fn ordering_facts(self) -> &'log [ObservedOrderingFact]";
      }
      {
        label = "fault facts view";
        needle = "pub fn fault_facts(self) -> &'log [ObservedFaultFact]";
      }
      {
        label = "ordering fact enum";
        needle = "pub enum ObservedOrderingFact";
      }
      {
        label = "fault fact enum";
        needle = "pub enum ObservedFaultFact";
      }
      {
        label = "checked prefix constructor";
        needle = "fn from_scheduler_event_log_entries";
      }
      {
        label = "dense prefix validation";
        needle = "ConditionEvaluationError::NonPrefixEventLogSequence";
      }
      {
        label = "entry hash validation";
        needle = "ConditionEvaluationError::InvalidEventLogEntryHash";
      }
      {
        label = "future entry rejection";
        needle = "ConditionEvaluationError::FutureEventLogEntry";
      }
      {
        label = "observed-state fold helper";
        needle = "fn push_observed_state_facts";
      }
      {
        label = "black-box observable payload fold";
        needle = "SchedulerEventLogPayload::Observable(payload)";
      }
      {
        label = "resolved ordering fold";
        needle = "SchedulerEventLogPayload::ResolvedHappening(event)";
      }
      {
        label = "delivery-order fold";
        needle = "Decision::DeliveryOrder(order)";
      }
      {
        label = "trigger fault fold";
        needle = "SchedulerEventLogPayload::TriggerActionApplied(application)";
      }
      {
        label = "ignored nondeterministic decisions";
        needle = "Decision::RngDraw(_)";
      }
      {
        label = "ignored host/preemption decision";
        needle = "Decision::Preemption(_)";
      }
      {
        label = "ignored app-random decision";
        needle = "Decision::AppRandom(_)";
      }
      {
        label = "evaluation pass exposes observed state";
        needle = "pub fn observed_state(&self) -> ObservedState<'_>";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "test-only typed event-log constructor";
        needle = "pub(crate) fn with_payload_for_test";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "observed state export";
        needle = "ObservedState";
      }
      {
        label = "observed ordering fact export";
        needle = "ObservedOrderingFact";
      }
      {
        label = "observed fault fact export";
        needle = "ObservedFaultFact";
      }
      {
        label = "test typed payload constructor";
        needle = "condition_payload_entry_for_test";
      }
    ]
    ++ failuresFor "crates/crucible/tests/observed_state_materialization.rs" observedStateTest [
      {
        label = "checked prefix materialization test";
        needle = "observed_state_materializes_only_checked_event_log_prefix";
      }
      {
        label = "invalid prefix rejection test";
        needle = "observed_state_rejects_future_invalid_or_non_dense_prefixes";
      }
      {
        label = "host time unordered map static test";
        needle = "observed_state_implementation_avoids_host_time_and_unordered_maps";
      }
      {
        label = "raw RNG draw ignored by observed state";
        needle = "Decision::RngDraw";
      }
      {
        label = "raw override ignored by observed state";
        needle = "Decision::Override";
      }
      {
        label = "preemption ignored by observed state";
        needle = "Decision::Preemption";
      }
      {
        label = "app random ignored by observed state";
        needle = "Decision::AppRandom";
      }
      {
        label = "checked future rejection";
        needle = "ConditionEvaluationError::FutureEventLogEntry";
      }
    ]
    ++ failuresFor "crates/crucible/tests/deterministic_condition_evaluation.rs" deterministicConditionTest [
      {
        label = "existing prefix-event-only regression";
        needle = "condition_evaluation_uses_checked_prefix_events_only";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 observed state check import";
        needle = "observedStateMaterialization = import ./phase4-observed-state-materialization.nix";
      }
      {
        label = "phase4 observed state attr path";
        needle = "attrPath = \"checks.crucible.phase4.observedStateMaterialization\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" (scrubCommentsAndStrings trigger) [
      {
        label = "host wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "host instant dependency";
        needle = "time::Instant";
      }
      {
        label = "std time dependency";
        needle = "std::time";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
      {
        label = "unordered hash set";
        needle = "HashSet";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/observed_state_materialization.rs" observedStateTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
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
  then throw "crucible phase4 observed-state-materialization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-observed-state-materialization";
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
          name = "run-observed-state-materialization";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-observed-state-materialization-target" \
              -p crucible \
              --test observed_state_materialization \
              --test deterministic_condition_evaluation \
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
            observed_state_materialized_from_prefix=true
            RESULT
          '';
        }
      ];
    }
