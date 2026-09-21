{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.segmentParallelReplay",
  taskIds ? ["T-PERF-33"],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  taskList = lib.concatStringsSep "," taskIds;
  segmentReplaySource = builtins.path {
    path = ../../crates/crucible-harness/src/segment_replay.rs;
    name = "crucible-segment-replay.rs";
  };
  segmentDivergenceSource = builtins.path {
    path = ../../crates/crucible-harness/src/divergence/segment.rs;
    name = "crucible-segment-divergence.rs";
  };
  divergenceGateSource = builtins.path {
    path = ../../crates/crucible-harness/tests/gate_divergence_bisect.rs;
    name = "crucible-gate-divergence-bisect.rs";
  };
  dependencyResult = dependency:
    if campaignComposition == null
    then "${dependency}/result"
    else "${dependency}/raw-result";
  divergenceResult = dependencyResult (builtins.elemAt dependencies 0);
  replayResult = dependencyResult (builtins.elemAt dependencies 1);
  modeDependencyAuthentication = lib.optionalString (campaignComposition != null) ''
    for binding in \
      ${lib.escapeShellArg "campaign_mode=${campaignComposition.mode}"} \
      ${lib.escapeShellArg "campaign_configuration_identity=${campaignComposition.system.config.aos.services.crucibleCampaign._runtimeIdentity}"} \
      ${lib.escapeShellArg "campaign_toplevel=${campaignComposition.system.config.system.build.toplevel}"}; do
      grep -Fxq "$binding" ${divergenceResult}
      grep -Fxq "$binding" ${replayResult}
    done
    grep -Fxq 'gate=gate:divergence-bisect' ${divergenceResult}
    grep -Fxq 'gate=gate:replay-oracle' ${replayResult}
  '';
  verifyScript = ''
    set -eu
    ${modeDependencyAuthentication}
    grep -Fq 'pub fn replay_checkpoint_segments<' ${segmentReplaySource}
    grep -Fq 'scope.spawn(move || replay_ref(segment))' ${segmentReplaySource}
    grep -Fq 'CheckpointStateMismatch' ${segmentReplaySource}
    grep -Fq 'canonical_log.extend(output.canonical_log)' ${segmentReplaySource}
    grep -Fq 'pub fn bisect_diverging_runs_with_segment_replay<' ${segmentDivergenceSource}
    grep -Fq 'CoordinateChanged' ${segmentDivergenceSource}
    grep -Fq 'gate_divergence_bisect_segment_replay_matches_serial_state_and_log' ${divergenceGateSource}
    grep -Fq 'gate_divergence_bisect_coordinate_is_independent_of_segment_count' ${divergenceGateSource}
    grep -Fq 'Arc::new(Barrier::new(4))' ${divergenceGateSource}

    grep -Fxq PASS ${divergenceResult}
    grep -Fxq PASS ${replayResult}

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
  authoritativeGate = pkgs.mkDerivation {
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
        script = verifyScript;
      }
    ];
  };
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      gateName = "gate:segment-parallel-replay";
      authoritativeAttr = attrPath;
      executionFamily = "native-runtime";
      name = "segment-parallel-replay";
      runtimeInputs = [pkgs.coreutils pkgs.grep] ++ dependencies;
      runtimeClosures = [
        segmentReplaySource
        segmentDivergenceSource
        divergenceGateSource
      ];
      runtimeScript = verifyScript;
      timeout = 900;
    }
  else authoritativeGate
