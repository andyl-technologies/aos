{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionStepModes",
  taskIds ? ["T-SESS-5"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-5 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionStepModes`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 step modes status note";
        needle = "`T-SESS-5` is green through `checks.crucible.phase5.sessionStepModes`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "duration step mode";
        needle = "Duration(SimDuration)";
      }
      {
        label = "active step state";
        needle = "active_step: Option<ActiveStep>";
      }
      {
        label = "duration target frontier";
        needle = "target_frontier";
      }
      {
        label = "event step predicate";
        needle = "entry_is_resolved_external_event";
      }
      {
        label = "assertion step predicate";
        needle = "entry_is_assertion_state_change";
      }
      {
        label = "timer step predicate";
        needle = "condition_summary_is_timer_fire";
      }
      {
        label = "step command starts bounded execution";
        needle = "self.active_step = Some(ActiveStep::new(*mode, self.frontier));";
      }
      {
        label = "step completion pause reason";
        needle = "PauseReason::StepComplete { mode }";
      }
      {
        label = "boundary stop test";
        needle = "session_actor_step_modes_stop_on_deterministic_boundaries";
      }
      {
        label = "interruptibility test";
        needle = "session_actor_step_modes_are_interruptible_by_pause_and_stop";
      }
      {
        label = "timer action negative test";
        needle = "timer_step_ignores_timer_actions_without_timer_predicate_fire";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session step modes check";
        needle = "sessionStepModes = import ./phase5-session-step-modes.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session-step-modes check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-step-modes";
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
          name = "run-session-step-modes";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-step-modes-target" \
              -p crucible-session \
              --lib \
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
            step_modes=quantum-event-assertion-timer-duration
            interruptible=pause-stop
            RESULT
          '';
        }
      ];
    }
