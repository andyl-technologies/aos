{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.campaignModel",
  taskIds ? ["T-CAM-1.1" "T-CAM-1.2" "T-CAM-1.3" "T-CAM-1.4" "T-CAM-1.5" "T-CAM-1.6" "T-CAM-1.7" "T-CAM-3.1"],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-campaign-model.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
    }
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-campaign-model";
      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "run-campaign-model";
          script = ''
            set -euo pipefail
            : "$DEPENDENCY_PATHS"

            # The suites run on libtest's thread pool: crucible-campaign's
            # tests share no process-global state (environment, working
            # directory, or statics), and one serial run of the library
            # suite was most of this gate's time. The individually required
            # tests run in one exact invocation per test executable.
            crucible-cargo test -p crucible-campaign --lib
            crucible-cargo test -p crucible-campaign --test gate_campaign_model
            crucible-exact-tests -p crucible --lib -- \
              model::measurement::runtime::tests::model_sources_project_exact_replay_samples
            crucible-exact-tests -p crucible-daemon --lib -- \
              crucible_measurement::evidence::tests::v3_publication_round_trips_and_rederives_guest_and_model_samples \
              crucible_measurement::tests::verified_crucible_aggregate_drives_exact_campaign_objective
          '';
        }
        {
          name = "write-result";
          script = ''
            mkdir -p "$out"
            {
              printf 'PASS\n'
              printf 'gate=gate:campaign-model\n'
              printf 'attr_path=%s\n' "$ATTR_PATH"
              printf 'task_ids=%s\n' "$TASK_IDS"
              printf 'scope=canonical-identities,linear-owner,derivation,restart-projection,model-owned-measurements,raw-replay-evidence\n'
            } > "$out/result"
          '';
        }
      ];
    }
