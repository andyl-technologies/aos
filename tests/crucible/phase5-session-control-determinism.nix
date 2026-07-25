{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionControlDeterminism",
  taskIds ? ["T-SESS-9"],
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
        label = "T-SESS-9 checked off";
        needle = "- [x] **T-SESS-9**";
      }
      {
        label = "T-SESS-9 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionControlDeterminism`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 control determinism status note";
        needle = "`T-SESS-9` is green through `checks.crucible.phase5.sessionControlDeterminism`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "control replay artifact type";
        needle = "pub struct SessionControlReplayArtifact";
      }
      {
        label = "control replay artifact capture";
        needle = "pub fn control_replay_artifact";
      }
      {
        label = "control replay entrypoint";
        needle = "pub fn replay_control_replay_artifact";
      }
      {
        label = "control replay boundary guard";
        needle = "ControlReplayBoundaryMismatch";
      }
      {
        label = "control replay frontier guard";
        needle = "ControlReplayFrontierMismatch";
      }
      {
        label = "control replay batch guard";
        needle = "ControlReplayBatchMismatch";
      }
      {
        label = "control replay final snapshot guard";
        needle = "ControlReplayFinalSnapshotMismatch";
      }
      {
        label = "deterministic scheduler batch field";
        needle = "pub scheduler_batch: u64";
      }
      {
        label = "running and paused inject applies immediate scheduler control";
        needle = "self.apply_control_operation_at_boundary(control.clone())?";
      }
      {
        label = "running and paused inject records scheduler control";
        needle = "self.record_boundary_control_at(\n                        &command,\n                        Some(control),";
      }
      {
        label = "paused mutator regression test";
        needle = "paused_boundary_mutators_apply_and_record_control_log";
      }
      {
        label = "control replay reproduction test";
        needle = "control_replay_artifact_reproduces_interactive_scheduler_state";
      }
      {
        label = "control replay mismatch test";
        needle = "control_replay_artifact_rejects_wrong_boundary_frontier";
      }
      {
        label = "control replay final mismatch test";
        needle = "control_replay_artifact_rejects_final_snapshot_mismatch";
      }
      {
        label = "grouped breakpoint replay batch test";
        needle = "control_replay_artifact_replays_grouped_breakpoint_actions_as_one_batch";
      }
      {
        label = "control-sensitive replay loop";
        needle = "struct ControlSensitiveLoop";
      }
      {
        label = "batch-sensitive replay seed";
        needle = "self.control_batches.saturating_mul(100_000)";
      }
      {
        label = "breakpoint action boundary control coverage";
        needle = "breakpoint_action_applies_scheduler_control_at_boundary";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session control determinism check";
        needle = "sessionControlDeterminism = import ./phase5-session-control-determinism.nix";
      }
      {
        label = "phase5 control determinism attr path";
        needle = ''attrPath = "checks.crucible.phase5.sessionControlDeterminism"'';
      }
      {
        label = "phase5 control determinism task id";
        needle = ''taskIds = ["T-SESS-9"]'';
      }
      {
        label = "phase5 control determinism depends on save/resume/fork";
        needle = "dependencies = [phase5.sessionSaveResumeFork]";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session-control-determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-control-determinism";
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
          name = "run-session-control-determinism";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-control-determinism-target" \
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
            artifact=session-control-replay
            boundary_key=virtual-time-quanta
            wall_clock_input=false
            RESULT
          '';
        }
      ];
    }
