{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionLifecycle",
  taskIds ? ["T-SESS-3"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
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

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-3 checked off";
        needle = "- [x] **T-SESS-3**";
      }
      {
        label = "T-SESS-3 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionLifecycle`";
      }
      {
        label = "section4 command-kind scope";
        needle = "command-kind lifecycle model";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 lifecycle status note";
        needle = "`T-SESS-3` is green through `checks.crucible.phase5.sessionLifecycle`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "closed lifecycle state kind";
        needle = "pub enum LifecycleStateKind";
      }
      {
        label = "closed lifecycle state set";
        needle = "pub const ALL: [Self; 4] = [Self::Loaded, Self::Running, Self::Paused, Self::Stopped]";
      }
      {
        label = "engine state kind conversion";
        needle = "impl From<&EngineState> for LifecycleStateKind";
      }
      {
        label = "closed pause reason kind";
        needle = "pub enum PauseReasonKind";
      }
      {
        label = "pause reason kind conversion";
        needle = "impl From<&PauseReason> for PauseReasonKind";
      }
      {
        label = "closed outcome kind";
        needle = "pub enum OutcomeKind";
      }
      {
        label = "outcome kind conversion";
        needle = "impl From<&Outcome> for OutcomeKind";
      }
      {
        label = "closed command kind";
        needle = "pub enum SessionCommandKind";
      }
      {
        label = "set breakpoint lifecycle kind";
        needle = "SetBreakpoint";
      }
      {
        label = "remove breakpoint lifecycle kind";
        needle = "RemoveBreakpoint";
      }
      {
        label = "create savepoint lifecycle kind";
        needle = "CreateSavepoint";
      }
      {
        label = "command representative mapping";
        needle = "pub fn representative_command(self) -> Option<SessionCommand>";
      }
      {
        label = "command kind conversion";
        needle = "impl From<&SessionCommand> for SessionCommandKind";
      }
      {
        label = "lifecycle transition result";
        needle = "pub enum LifecycleTransition";
      }
      {
        label = "total transition function";
        needle = "pub const fn lifecycle_transition";
      }
      {
        label = "event step lifecycle kind";
        needle = "StepEvent";
      }
      {
        label = "assertion step lifecycle kind";
        needle = "StepAssertion";
      }
      {
        label = "timer step lifecycle kind";
        needle = "StepTimer";
      }
      {
        label = "duration step lifecycle kind";
        needle = "StepDuration";
      }
      {
        label = "closed state/reason/outcome/command test";
        needle = "lifecycle_state_reason_outcome_and_command_sets_are_closed";
      }
      {
        label = "total transition table test";
        needle = "lifecycle_transition_model_is_total_for_representative_commands";
      }
      {
        label = "rfc table cell test";
        needle = "lifecycle_transition_model_matches_rfc_section_table_cells";
      }
      {
        label = "no wedge command sequence test";
        needle = "lifecycle_transition_model_command_sequences_never_wedge";
      }
      {
        label = "generated command stream test";
        needle = "scheduler_liveness_generated_command_streams_exercise_lifecycle_table";
      }
      {
        label = "engine/model agreement test";
        needle = "engine_transition_table_matches_lifecycle_model_for_current_commands";
      }
      {
        label = "all current command kinds exercised";
        needle = "for command_kind in SessionCommandKind::ALL";
      }
      {
        label = "side-effect-free rejection helper";
        needle = "assert_rejection_names_state_and_command";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session lifecycle check";
        needle = "sessionLifecycle = import ./phase5-session-lifecycle.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session lifecycle check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-lifecycle";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

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
          name = "run-session-lifecycle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-lifecycle-target" \
              -p crucible-session \
              --lib \
              lifecycle \
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
            component=crucible-session
            state_machine=lifecycle
            transition_table=total
            command_scope=section4-plus-current-shims
            scheduler_liveness=phase3-gate-dependency
            RESULT
          '';
        }
      ];
    }
