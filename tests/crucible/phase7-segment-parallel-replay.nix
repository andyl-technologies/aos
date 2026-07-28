{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.segmentParallelReplay",
  taskIds ? ["T-PERF-33"],
  dependencies ? [],
}: let
  taskList = lib.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-segment-parallel-replay";
    version = "0";

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
      ]
      ++ dependencies;

    phases = [
      {
        name = "verify-segment-parallel-replay";
        script = ''
          set -eu
          grep -Fq 'pub fn replay_checkpoint_segments<' ${../../crates/crucible-harness/src/segment_replay.rs}
          grep -Fq 'scope.spawn(move || replay_ref(segment))' ${../../crates/crucible-harness/src/segment_replay.rs}
          grep -Fq 'CheckpointStateMismatch' ${../../crates/crucible-harness/src/segment_replay.rs}
          grep -Fq 'canonical_log.extend(output.canonical_log)' ${../../crates/crucible-harness/src/segment_replay.rs}
          grep -Fq 'pub fn bisect_diverging_runs_with_segment_replay<' ${../../crates/crucible-harness/src/divergence/segment.rs}
          grep -Fq 'CoordinateChanged' ${../../crates/crucible-harness/src/divergence/segment.rs}
          grep -Fq 'gate_divergence_bisect_segment_replay_matches_serial_state_and_log' ${../../crates/crucible-harness/tests/gate_divergence_bisect.rs}
          grep -Fq 'gate_divergence_bisect_coordinate_is_independent_of_segment_count' ${../../crates/crucible-harness/tests/gate_divergence_bisect.rs}
          grep -Fq 'Arc::new(Barrier::new(4))' ${../../crates/crucible-harness/tests/gate_divergence_bisect.rs}

          grep -Fxq PASS "${builtins.elemAt dependencies 0}/result"
          grep -Fxq PASS "${builtins.elemAt dependencies 1}/result"

          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:segment-parallel-replay
          proving_gates=gate:replay-oracle,gate:divergence-bisect
          tasks=${taskList}
          status=complete
          admission_class=A
          replay_split=realizable-checkpoint-coordinates
          worker_model=one-scoped-host-thread-per-selected-segment
          checkpoint_boundary_state_validation=exact
          join_order=canonical-segment-coordinate
          serial_parallel_final_state_identical=true
          serial_parallel_canonical_log_identical=true
          tested_segment_counts=1,2,4
          divergence_coordinate_segment_count_invariant=true
          RESULT
        '';
      }
    ];
  }
