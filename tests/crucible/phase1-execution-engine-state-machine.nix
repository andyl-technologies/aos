{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionEngineStateMachine",
  taskIds ? ["T-EXEC-14" "T-SESS-2" "T-PAT-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  session = import ./_crucible-session-source.nix {inherit lib;};
  sessionManifest = builtins.readFile ../../crates/crucible-session/Cargo.toml;
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
  sessionControlPlane = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "closed engine state enum";
        needle = "pub enum EngineState";
      }
      {
        label = "loaded run state";
        needle = "Loaded,";
      }
      {
        label = "running run state";
        needle = "Running,";
      }
      {
        label = "paused run state";
        needle = "Paused {";
      }
      {
        label = "stopped run state";
        needle = "Stopped {";
      }
      {
        label = "pause reasons";
        needle = "pub enum PauseReason";
      }
      {
        label = "terminal outcomes";
        needle = "pub enum Outcome";
      }
      {
        label = "engine owner";
        needle = "pub struct Engine";
      }
      {
        label = "configuration source of truth";
        needle = "configuration: Configuration";
      }
      {
        label = "runtime cache";
        needle = "runtime: Option<RuntimeState>";
      }
      {
        label = "temporal graph handle";
        needle = "graph: TemporalGraph";
      }
      {
        label = "session actor";
        needle = "pub struct SessionActor";
      }
      {
        label = "actor mailbox";
        needle = "mailbox: mpsc::Receiver<SessionCommand>";
      }
      {
        label = "async actor run loop";
        needle = "pub async fn run";
      }
      {
        label = "instantiate state guard";
        needle = "return Err(self.invalid_engine_state(\"instantiate_runtime\"));";
      }
      {
        label = "running-state mailbox poll";
        needle = "self.mailbox.try_recv()";
      }
      {
        label = "bounded quantum step";
        needle = "let _outcome = match self.engine.step_quantum()";
      }
      {
        label = "cooperative inter-quantum yield";
        needle = "tokio::task::yield_now().await;";
      }
      {
        label = "command path cooperative yield";
        needle = "self.commands_applied = self.commands_applied.saturating_add(1);\n        tokio::task::yield_now().await;";
      }
      {
        label = "scheduler quantum boundary";
        needle = "drive_quantum(QuantumRequest";
      }
      {
        label = "start instantiate test";
        needle = "engine_start_instantiates_runtime_and_pauses";
      }
      {
        label = "invalid transition test";
        needle = "engine_rejects_invalid_transition_without_changing_state";
      }
      {
        label = "direct instantiate guard test";
        needle = "engine_instantiate_runtime_cannot_bypass_state_transitions";
      }
      {
        label = "command-before-quantum actor test";
        needle = "session_actor_services_pending_command_before_quantum";
      }
      {
        label = "yield-after-quantum actor test";
        needle = "session_actor_steps_one_quantum_then_yields";
      }
      {
        label = "command-driven step yield test";
        needle = "session_actor_yields_after_command_driven_step";
      }
    ]
    ++ failuresFor "crates/crucible-session/Cargo.toml" sessionManifest [
      {
        label = "tokio actor dependency";
        needle = "tokio = { workspace = true }";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes execution engine state-machine check";
        needle = "executionEngineStateMachine = import ./phase1-execution-engine-state-machine.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-14 completion note";
        needle = "Completed by `crates/crucible-session/src/lib.rs`: `Engine` now owns";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionControlPlane [
      {
        label = "T-SESS-2 completion names run_once";
        needle = "`SessionActor::run`";
      }
      {
        label = "T-SESS-2 completion names live snapshot publication";
        needle = "`LiveSnapshot` mirror";
      }
      {
        label = "T-SESS-2 completion names command yield";
        needle = "`tokio::task::yield_now` after every applied command or scheduler quantum";
      }
      {
        label = "T-SESS-2 completion names engine state-machine gate";
        needle = "`checks.crucible.phase1.executionEngineStateMachine`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-1 completion names closed run states";
        needle = "`EngineState` is the\n    closed Loaded/Running/Paused/Stopped run-state enum";
      }
      {
        label = "T-PAT-1 completion names bounded run_once loop";
        needle = "`SessionActor::run`\n    delegates to bounded `run_once` iterations";
      }
      {
        label = "T-PAT-1 completion names engine state-machine gate";
        needle = "`checks.crucible.phase1.executionEngineStateMachine`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution engine state-machine check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-engine-state-machine";
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
          name = "run-execution-engine-state-machine";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-engine-state-machine-target" \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            states=loaded,running,paused,stopped
            loop=poll-then-step
            quantum=bounded-single-scheduler-step
            yield=inter-quantum-cooperative
            command_yield=post-command-cooperative
            session_actor_loop=poll-command-or-step-one-quantum-publish-yield
            pattern_PAT_1=enum-states-bounded-actor-loop
            RESULT
          '';
        }
      ];
    }
