{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerRelativeTimers",
  taskIds ? ["T-TRIG-14"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  relativeTimerTest = builtins.readFile ../../crates/crucible/tests/trigger_relative_timers.rs;
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
              out = state.out + (
                if ch == "\n"
                then "\n"
                else " "
              );
            }
        else if ch == "\\" && next != ""
        then
          state
          // {
            out = state.out + " " + (
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
            out = state.out + (
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
  relativeTimerSources = builtins.concatStringsSep "\n" [
    (scrubCommentsAndStrings scheduler)
    (scrubCommentsAndStrings trigger)
    (scrubCommentsAndStrings relativeTimerTest)
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-14 checked off";
        needle = "- [x] **T-TRIG-14**";
      }
      {
        label = "T-TRIG-14 completion note";
        needle = "Completed by `checks.crucible.phase4.triggerRelativeTimers`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "observable event append API";
        needle = "pub fn append_observable_events";
      }
      {
        label = "observable payloads append through event log";
        needle = "SchedulerEventLogPayload::Observable(event.payload().clone())";
      }
      {
        label = "evaluation boundary append API";
        needle = "pub fn append_evaluation_boundary";
      }
      {
        label = "evaluation boundary payload append";
        needle = "SchedulerEventLogPayload::EvaluationBoundary(kind)";
      }
      {
        label = "scheduler event graph evaluation API";
        needle = "pub fn evaluate_event_graph";
      }
      {
        label = "trigger timers feed Timer leaves";
        needle = ".with_timer_fires(self.trigger_actions.armed_timers.clone())";
      }
      {
        label = "scheduler rejects mismatched timer witnesses";
        needle = "firings.timer_fires() != &self.trigger_actions.armed_timers";
      }
      {
        label = "arm timer uses firing virtual time";
        needle = ".at\n                .ticks\n                .checked_add(after.nanos)";
      }
      {
        label = "cancel timer removes armed timer";
        needle = "state.armed_timers.remove(name)";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "Timer leaf uses evaluator timer fires";
        needle = "Condition::Timer { name } => evaluator";
      }
      {
        label = "Timer fire time trait method";
        needle = "fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime>";
      }
      {
        label = "EventFirings carries timer witness";
        needle = "timer_fires: BTreeMap<TimerId, VirtualTime>";
      }
      {
        label = "EventFirings exposes timer witness";
        needle = "pub fn timer_fires(&self) -> &BTreeMap<TimerId, VirtualTime>";
      }
      {
        label = "After leaf uses last firing history";
        needle = ".last_event_firing(of)";
      }
      {
        label = "After uses checked relative addition";
        needle = ".and_then(|fired_at| fired_at.ticks.checked_add(duration.nanos))";
      }
      {
        label = "grouped arm timer validation";
        needle = "fn collect_timer_names(action: &Action, timers: &mut BTreeSet<TimerId>)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_relative_timers.rs" relativeTimerTest [
      {
        label = "timer recovery replay test";
        needle = "arm_timer_timer_leaf_heals_at_relative_virtual_time_and_replays_identically";
      }
      {
        label = "After sugar recovery test";
        needle = "after_sugar_heals_at_the_same_relative_virtual_time";
      }
      {
        label = "cancelled timer test";
        needle = "cancelled_timer_does_not_fire_at_its_former_deadline";
      }
      {
        label = "raw timer evaluation bypass rejection test";
        needle = "scheduler_rejects_timer_firings_evaluated_without_scheduler_timer_state";
      }
      {
        label = "black-box console readiness";
        needle = "Predicate::console_match";
      }
      {
        label = "black-box coverage gate";
        needle = "Predicate::coverage_point";
      }
      {
        label = "timer trigger leaf";
        needle = "Predicate::timer";
      }
      {
        label = "after trigger leaf";
        needle = "Predicate::after";
      }
      {
        label = "observable append exercised";
        needle = ".append_observable_events(recovery_observations())";
      }
      {
        label = "evaluation boundary exercised";
        needle = ".append_evaluation_boundary(time(ticks), SchedulerEvaluationBoundaryKind::Quantum)";
      }
      {
        label = "no guest marker fallback";
        needle = "relative timer scenario should use only black-box observable leaves";
      }
      {
        label = "replay byte comparison";
        needle = "assert_eq!(left, right);";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes trigger relative timers check";
        needle = "triggerRelativeTimers = import ./phase4-trigger-relative-timers.nix";
      }
    ]
    ++ forbiddenFor "trigger relative timer sources" relativeTimerSources [
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
    ];
in
  if failures != []
  then throw "crucible phase4 trigger-relative-timers check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-trigger-relative-timers";
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
          name = "run-trigger-relative-timers";
          script = ''
            cargo test \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test trigger_relative_timers \
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
              echo "gate=phase4-trigger-relative-timers"
              echo "timer_leaf_uses_armed_trigger_timers=true"
              echo "after_sugar_uses_event_firing_history=true"
              echo "black_box_recovery_scenario_replays_identically=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
