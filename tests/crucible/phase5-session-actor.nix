{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionActor",
  taskIds ? ["T-SESS-1"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-1 checked off";
        needle = "- [x] **T-SESS-1**";
      }
      {
        label = "T-SESS-1 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionActor`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 session actor status note";
        needle = "`T-SESS-1` is green through `checks.crucible.phase5.sessionActor`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "engine type";
        needle = "pub struct Engine";
      }
      {
        label = "runtime state cache";
        needle = "runtime: Option<RuntimeState>";
      }
      {
        label = "temporal graph handle";
        needle = "graph: TemporalGraph";
      }
      {
        label = "actor-owned breakpoint set";
        needle = "breakpoints: BreakpointSet";
      }
      {
        label = "scheduler boundary";
        needle = "quantum_loop: L";
      }
      {
        label = "session actor type";
        needle = "pub struct SessionActor";
      }
      {
        label = "engine owned by value";
        needle = "engine: Engine<L>";
      }
      {
        label = "actor mailbox";
        needle = "mailbox: mpsc::Receiver<SessionCommand>";
      }
      {
        label = "actor event-log writer";
        needle = "event_log: SessionEventLog";
      }
      {
        label = "message-only command type";
        needle = "pub enum SessionCommand";
      }
      {
        label = "async actor run loop";
        needle = "pub async fn run";
      }
      {
        label = "running mailbox poll";
        needle = "self.mailbox.try_recv()";
      }
      {
        label = "single bounded quantum";
        needle = "let _outcome = self.engine.step_quantum()?;";
      }
      {
        label = "breakpoint ownership test";
        needle = "session_actor_owns_breakpoint_set_with_runtime_state";
      }
      {
        label = "no locked engine source test";
        needle = "session_actor_source_does_not_lock_engine_across_run";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "engine behind Arc";
        needle = "engine: Arc<";
      }
      {
        label = "engine behind Mutex";
        needle = "engine: Mutex<";
      }
      {
        label = "engine behind RwLock";
        needle = "engine: RwLock<";
      }
      {
        label = "Arc Mutex Engine";
        needle = "Arc<Mutex<Engine";
      }
      {
        label = "Arc std Mutex Engine";
        needle = "Arc<std::sync::Mutex<Engine";
      }
      {
        label = "Arc RwLock Engine";
        needle = "Arc<RwLock<Engine";
      }
      {
        label = "Arc std RwLock Engine";
        needle = "Arc<std::sync::RwLock<Engine";
      }
      {
        label = "tokio mutex in session actor source";
        needle = "tokio::sync::Mutex";
      }
      {
        label = "tokio rwlock in session actor source";
        needle = "tokio::sync::RwLock";
      }
      {
        label = "parking_lot mutex in session actor source";
        needle = "parking_lot::Mutex";
      }
      {
        label = "parking_lot rwlock in session actor source";
        needle = "parking_lot::RwLock";
      }
      {
        label = "public direct boundary command hook";
        needle = "pub fn defer_boundary_command";
      }
      {
        label = "public mutable engine accessor";
        needle = "pub fn engine_mut";
      }
      {
        label = "public actor run_once hook";
        needle = "pub fn run_once";
      }
      {
        label = "public actor boundary command hook";
        needle = "pub fn next_boundary_command";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session actor check";
        needle = "sessionActor = import ./phase5-session-actor.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session actor check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-actor";
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
          name = "run-session-actor";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-actor-target" \
              -p crucible-session \
              --lib \
              session_actor \
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
            actor=single-owner
            engine=owned-by-value
            mailbox=message-only
            no_engine_lock=source-and-test
            RESULT
          '';
        }
      ];
    }
