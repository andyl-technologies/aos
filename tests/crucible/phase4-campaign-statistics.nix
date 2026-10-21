{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.campaignStatistics",
  taskIds ? ["T-CAM-3.4" "T-CAM-4.1" "T-CAM-4.2" "T-CAM-4.3"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase4-campaign-statistics";

    buildDeps = [pkgs.coreutils];
    ATTR_PATH = attrPath;
    TASK_IDS = builtins.concatStringsSep "," taskIds;
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "run-campaign-statistics";
        script = ''
          set -eu
          : "$DEPENDENCY_PATHS"

          crucible-cargo test \
            -p crucible-campaign --lib \
            finite_distribution_rejects_incomplete_or_nonpositive_mass_contracts \
            -- --test-threads=1
          crucible-cargo test \
            -p crucible-campaign --lib \
            statistical_design_requires_static_exhaustive_policy_and_unconfigured_reports_fail_closed \
            -- --test-threads=1
          crucible-cargo test \
            -p crucible-campaign --lib \
            two_edge_statistical_flight_reports_the_full_unequal_probability_product \
            -- --test-threads=1
          crucible-cargo test \
            -p crucible-campaign --lib \
            duplicate_draws_reuse_one_observation_without_losing_sampling_multiplicity \
            -- --test-threads=1
          crucible-cargo test \
            -p crucible-campaign --lib \
            repository::tests::statistics::smc \
            -- --test-threads=1
          crucible-cargo test \
            -p crucible-campaign \
            --test gate_campaign_statistics -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'gate=gate:campaign-statistics\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'scope=finite-static-p-q,bounded-smc,importance-weighting,systematic-resampling,genealogy,support,intervention-exclusion,stage-barriers,restart\n'
            printf 'open_scope=checked-statistical-service,operator-porcelain\n'
          } > "$out/result"
        '';
      }
    ];
  }
