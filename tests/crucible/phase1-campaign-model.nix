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

            run_exact_lib_test() {
              gate_package=$1
              gate_test=$2
              gate_list_log="$TMPDIR/campaign-model-list.log"
              gate_test_log="$TMPDIR/campaign-model-test.log"

              printf 'listing library tests for %s\n' "$gate_package"
              if crucible-cargo test \
                -p "$gate_package" --lib -- --list 2>&1 \
                | "${pkgs.coreutils}/bin/tee" "$gate_list_log"; then
                :
              else
                status="''${PIPESTATUS[0]}"
                [ "$status" -ne 0 ] || status=1
                exit "$status"
              fi
              match_count=$(grep -Fxc "$gate_test: test" "$gate_list_log" || true)
              if [ "$match_count" -ne 1 ]; then
                printf 'expected exactly one listed test named %s; found %s\n' \
                  "$gate_test" "$match_count" >&2
                exit 1
              fi

              printf 'running exact test %s::%s\n' "$gate_package" "$gate_test"
              if crucible-cargo test \
                -p "$gate_package" --lib -- --exact "$gate_test" --test-threads=1 2>&1 \
                | "${pkgs.coreutils}/bin/tee" "$gate_test_log"; then
                :
              else
                status="''${PIPESTATUS[0]}"
                [ "$status" -ne 0 ] || status=1
                exit "$status"
              fi
              if ! grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$gate_test_log"; then
                printf 'required test did not produce the exact pass count: %s\n' \
                  "$gate_test" >&2
                exit 1
              fi
            }

            crucible-cargo test -p crucible-campaign --lib -- --test-threads=1
            crucible-cargo test -p crucible-campaign --test gate_campaign_model -- --test-threads=1
            run_exact_lib_test \
              crucible \
              model::measurement::runtime::tests::model_sources_project_exact_replay_samples
            run_exact_lib_test \
              crucible-daemon \
              crucible_measurement::evidence::tests::v3_publication_round_trips_and_rederives_guest_and_model_samples
            run_exact_lib_test \
              crucible-daemon \
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
