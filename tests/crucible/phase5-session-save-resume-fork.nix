{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionSaveResumeFork",
  taskIds ? ["T-SESS-8"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  modelLib = import ./_crucible-model-source.nix {inherit lib;};
  crucibleLib =
    builtins.readFile ../../crates/crucible/src/lib.rs
    + builtins.readFile ../../crates/crucible/src/tests/model_core.rs;
  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  forkGateTest = builtins.readFile ../../crates/crucible-session/tests/gate_exploration_fork.rs;
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-8 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionSaveResumeFork`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 save-resume-fork status note";
        needle = "`T-SESS-8` is green through `checks.crucible.phase5.sessionSaveResumeFork`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" modelLib [
      {
        label = "checkpoint configuration lookup";
        needle = "pub fn checkpoint_configuration";
      }
      {
        label = "checkpoint record lookup";
        needle = "pub fn checkpoint_record";
      }
      {
        label = "checkpoint-addressed resume";
        needle = "pub fn resume_checkpoint";
      }
      {
        label = "checkpoint resume delegates to ordinary resume";
        needle = "self.resume(&configuration)";
      }
      {
        label = "checkpoint lookup covers cached snapshots";
        needle = "or_else(|| self.cached_snapshots.get(&checkpoint))";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crucibleLib [
      {
        label = "cached snapshot checkpoint resume test";
        needle = "temporal_graph_checkpoint_resume_resolves_cached_snapshot_without_thin_node";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "fork handle configuration identity";
        needle = "pub configuration: ContentHash";
      }
      {
        label = "fork handle child transport";
        needle = "pub struct SessionChildHandle";
      }
      {
        label = "fork request factory input";
        needle = "pub struct SessionForkRequest";
      }
      {
        label = "savepoint materializes through graph";
        needle = "self.graph.save_checkpoint(&self.configuration)?";
      }
      {
        label = "session runtime uses temporal graph resume";
        needle = "self.graph.resume(&self.configuration)?.runtime";
      }
      {
        label = "resumed session result";
        needle = "pub struct SessionResume";
      }
      {
        label = "realized checkpoint engine constructor";
        needle = "fn from_realized_checkpoint";
      }
      {
        label = "resumed actor lands paused";
        needle = "reason: PauseReason::Instantiated";
      }
      {
        label = "checkpoint resume API";
        needle = "pub fn resume_session_from_checkpoint";
      }
      {
        label = "checkpoint resume graph delegation";
        needle = "self.graph.resume_checkpoint(checkpoint)?";
      }
      {
        label = "checkpoint resume accepts cached records";
        needle = "checkpoint_record(checkpoint)";
      }
      {
        label = "checkpoint fork API";
        needle = "pub fn fork_child_from_checkpoint";
      }
      {
        label = "actor fork factory constructor";
        needle = "pub fn new_with_fork_loop_factory";
      }
      {
        label = "actor fork command interception";
        needle = "fn apply_spawned_fork_command";
      }
      {
        label = "actor fork command spawns child";
        needle = "tokio::spawn(async move";
      }
      {
        label = "shared checkpoint child builder";
        needle = "fn build_checkpoint_child";
      }
      {
        label = "checkpoint fork graph delegation";
        needle = "self.graph.fork(&base, std::iter::empty::<Decision>())?";
      }
      {
        label = "direct checkpoint fork state rejection";
        needle = ''operation: "fork_child_from_checkpoint"'';
      }
      {
        label = "fork command handle configuration";
        needle = "configuration: checkpoint.configuration";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_exploration_fork.rs" forkGateTest [
      {
        label = "command-path fork child test";
        needle = "actor_fork_command_spawns_independent_child_handle";
      }
      {
        label = "command-path fork error reply test";
        needle = "actor_fork_command_completes_reply_on_missing_checkpoint";
      }
      {
        label = "command-path fork factory";
        needle = "SessionActor::new_with_fork_loop_factory";
      }
      {
        label = "command-path child sender assertion";
        needle = "fork command should return a child sender";
      }
      {
        label = "savepoint resume test";
        needle = "resume_session_from_savepoint_uses_graph_checkpoint_and_independent_actor";
      }
      {
        label = "cached snapshot resume test";
        needle = "resume_session_from_cached_snapshot_without_thin_node";
      }
      {
        label = "checkpoint-prefix fork test";
        needle = "fork_child_from_checkpoint_instantiates_prefix_child_without_parent_mutation";
      }
      {
        label = "checkpoint fork rejection test";
        needle = "fork_child_from_checkpoint_rejects_loaded_and_running_parent_without_pause";
      }
      {
        label = "resume parent immutability";
        needle = "assert_eq!(parent.snapshot(), parent_before_resume)";
      }
      {
        label = "fork parent immutability";
        needle = "assert_eq!(parent.snapshot(), parent_before_fork)";
      }
      {
        label = "child actor mutates independently";
        needle = "send_command(&child_sender, SessionCommand::Continue).await";
      }
      {
        label = "resumed actor mutates independently";
        needle = "send_command(&resumed_sender, SessionCommand::Continue).await";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session save/resume/fork check";
        needle = "sessionSaveResumeFork = import ./phase5-session-save-resume-fork.nix";
      }
      {
        label = "phase5 save/resume/fork attr path";
        needle = ''attrPath = "checks.crucible.phase5.sessionSaveResumeFork"'';
      }
      {
        label = "phase5 save/resume/fork task id";
        needle = ''taskIds = ["T-SESS-8"]'';
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session-save-resume-fork check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-save-resume-fork";
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
          name = "run-session-save-resume-fork";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-save-resume-fork-target" \
              -p crucible-session \
              --test gate_exploration_fork \
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
            graph_ops=save-checkpoint,resume-checkpoint,fork-empty-delta
            child_actor=independent-paused
            RESULT
          '';
        }
      ];
    }
