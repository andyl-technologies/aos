{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.debugTimeTravel",
  taskIds ? ["T-DBG-4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  debugDoc = builtins.readFile ../../docs/rfcs/0010-crucible/36-time-travel-debugging.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  timeTravelTest = builtins.readFile ../../crates/crucible/tests/gate_debug_time_travel.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/36-time-travel-debugging.md" debugDoc [
      {
        label = "T-DBG-4 checked off";
        needle = "- [x] **T-DBG-4**";
      }
      {
        label = "T-DBG-4 completion note";
        needle = "Completed by `checks.crucible.phase6.debugTimeTravel`";
      }
      {
        label = "restore nearest wording";
        needle = "restore-nearest-checkpoint";
      }
      {
        label = "reverse continue wording";
        needle = "latest-log-coordinate";
      }
      {
        label = "bisection wording";
        needle = "localizing any divergence by bisection";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-DBG-4 plan summary";
        needle = "`T-DBG-4` is green through `checks.crucible.phase6.debugTimeTravel`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "debug goto API";
        needle = "pub fn debug_goto";
      }
      {
        label = "coordinate resolver";
        needle = "fn debug_resolve_coordinate";
      }
      {
        label = "restore selector";
        needle = "fn debug_restore_configuration";
      }
      {
        label = "virtual-time resolver";
        needle = "debug_latest_checkpoint_at_or_before_time";
      }
      {
        label = "node-icount resolver";
        needle = "debug_latest_checkpoint_at_or_before_icount";
      }
      {
        label = "ancestry filter";
        needle = "debug_configuration_is_ancestor_or_self";
      }
      {
        label = "thin checkpoint icounts";
        needle = "thin_checkpoint_node_icounts";
      }
      {
        label = "goto request type";
        needle = "pub struct DebugGotoRequest";
      }
      {
        label = "debug coordinate type";
        needle = "pub enum DebugCoordinate";
      }
      {
        label = "goto report type";
        needle = "pub struct DebugGotoReport";
      }
      {
        label = "restore-plus-replay proof helper";
        needle = "used_restore_then_replay";
      }
      {
        label = "replay suffix count";
        needle = "replay_suffix_decisions";
      }
      {
        label = "reverse step API";
        needle = "pub fn debug_reverse_step";
      }
      {
        label = "reverse step grain";
        needle = "pub enum DebugReverseStepGrain";
      }
      {
        label = "reverse step closed set";
        needle = "pub const ALL: [Self; 5]";
      }
      {
        label = "reverse continue API";
        needle = "pub fn debug_reverse_continue";
      }
      {
        label = "reverse continue condition pass";
        needle = "ConditionEvaluationPass::from_log_prefix";
      }
      {
        label = "reverse continue prefix validation";
        needle = "ConditionEventLogPrefix::from_scheduler_event_log_entries";
      }
      {
        label = "replay oracle mismatch";
        needle = "DebugGotoReplayOracleMismatch";
      }
      {
        label = "debug bisection request";
        needle = "pub struct DebugReplayOracleBisectionRequest";
      }
      {
        label = "debug bisection helper";
        needle = "fn debug_replay_oracle_bisection";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "debug coordinate export";
        needle = "DebugCoordinate";
      }
      {
        label = "debug goto request export";
        needle = "DebugGotoRequest";
      }
      {
        label = "debug goto report export";
        needle = "DebugGotoReport";
      }
      {
        label = "debug bisection export";
        needle = "DebugReplayOracleBisectionRequest";
      }
      {
        label = "reverse step grain export";
        needle = "DebugReverseStepGrain";
      }
      {
        label = "reverse continue export";
        needle = "DebugReverseContinueRequest";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "duration step mode";
        needle = "Duration(SimDuration)";
      }
      {
        label = "event step mode";
        needle = "Event,";
      }
      {
        label = "assertion step mode";
        needle = "Assertion,";
      }
      {
        label = "timer step mode";
        needle = "Timer,";
      }
      {
        label = "forward step closed set";
        needle = "pub const ALL: [Self; 5]";
      }
      {
        label = "reverse grain mirror";
        needle = "pub const fn reverse_grain";
      }
      {
        label = "step-mode mirror test";
        needle = "step_modes_cover_forward_vocabulary_and_reverse_grains";
      }
      {
        label = "forward-only duration step";
        needle = "Duration(SimDuration { nanos: 10 }).reverse_grain()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_debug_time_travel.rs" timeTravelTest [
      {
        label = "nearest checkpoint gate";
        needle = "debug_goto_uses_nearest_checkpoint_then_replay_to_exact_coordinate";
      }
      {
        label = "ancestry-safe coordinate gate";
        needle = "debug_goto_coordinate_resolution_stays_on_current_ancestry";
      }
      {
        label = "reverse step/continue gate";
        needle = "debug_reverse_step_and_continue_are_realized_by_goto";
      }
      {
        label = "bisection gate";
        needle = "debug_goto_replay_oracle_mismatch_carries_bisection_coordinate";
      }
      {
        label = "virtual time coordinate assertion";
        needle = "DebugCoordinate::virtual_time";
      }
      {
        label = "node icount coordinate assertion";
        needle = "DebugCoordinate::node_icount";
      }
      {
        label = "restore checkpoint assertion";
        needle = "assert_eq!(by_time.restore_checkpoint, cached_first.id)";
      }
      {
        label = "reverse instruction assertion";
        needle = "DebugReverseStepGrain::Instruction";
      }
      {
        label = "reverse quantum assertion";
        needle = "DebugReverseStepGrain::Quantum";
      }
      {
        label = "condition scan assertion";
        needle = "Predicate::node_state";
      }
      {
        label = "inclusive reverse-continue assertion";
        needle = "current event sequence is an inclusive reverse-continue candidate";
      }
      {
        label = "oracle mismatch assertion";
        needle = "DebugGotoReplayOracleMismatch";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green debug time-travel gate";
        needle = "debugTimeTravel = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-DBG-4\"]";
      }
      {
        label = "canonical breakpoint raw dependency";
        needle = "phase6.canonicalDebugBreakpoint.rawGate";
      }
      {
        label = "canonical breakpoint green dependency";
        needle = "phase6.canonicalDebugBreakpoint";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_debug_time_travel.rs" timeTravelTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 debug-time-travel check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-debug-time-travel";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            set -eu
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-debug-time-travel";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-time-travel-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_debug_time_travel \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-time-travel-session-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-session \
              step_modes \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:debug-time-travel
            goto=restore-nearest-checkpoint-then-replay
            reverse_step=mirrors-forward-step-modes
            reverse_continue=latest-condition-prefix
            oracle=content-addressed-bisection
            RESULT
          '';
        }
      ];
    }
