{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase9.gates.campaignFindingPortability",
  taskIds ? ["T-CAM-9.4"],
  packagedReplay,
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase9-campaign-finding-portability";

    buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed packagedReplay] ++ dependencies;

    phases = [
      {
        name = "run-self-contained-finding-replay";
        script = ''
          set -eu

          run_exact_test() {
            package=$1
            target_kind=$2
            test_target=$3
            selector=$4
            listing=$(crucible-cargo test \
              -p "$package" \
              "$target_kind" "$test_target" \
              "$selector" \
              -- --exact --list)
            printf '%s\n' "$listing" | grep -Fqx "$selector: test"

            output=$(crucible-cargo test \
              -p "$package" \
              "$target_kind" "$test_target" \
              "$selector" \
              -- --exact --test-threads=1 2>&1)
            printf '%s\n' "$output"
            printf '%s\n' "$output" \
              | grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;'
          }

          run_exact_test \
            crucible-campaign \
            --test \
            gate_campaign_replay \
            strict_campaign_planner_reproduces_every_accepted_step
          run_exact_test \
            crucible \
            --test \
            gate_campaign_replay \
            offline_rich_finding_replays_without_campaign_store
          run_exact_test \
            crucible-cli \
            --bin \
            crucible \
            tests::verify_dispatch::finding_export::campaign_findings_round_trip_authenticates_occurrence_objects_and_tampering

          grep -Fqx \
            'crucible.campaign.finding-bundle	2	crucible-cli::cli_campaign::finding_bundle	export-directory	gate:campaign-replay,gate:campaign-store-composition' \
            docs/rfcs/0020-crucible-campaigns/schema-registry.tsv

          test "$(sed -n '1p' ${packagedReplay}/result)" = PASS
          test "$(grep -Fxc 'gate=gate:campaign-replay' ${packagedReplay}/result || true)" -eq 1
          grep -Fqx 'scope=portable-model,strict,production-qemu,native' \
            ${packagedReplay}/result
          grep -Fqx 'tier=automated' ${packagedReplay}/result
          grep -Fqx \
            'evidence=campaign_production_qemu_exact_checkpoint_replay=true,interactive_packaged_capture_replay=true' \
            ${packagedReplay}/result

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:campaign-replay
          tasks=${builtins.concatStringsSep "," taskIds}
          portable_model_replay=true
          no_campaign_daemon=true
          no_shared_store=true
          production_qemu_capture_replay=${packagedReplay}
          finding_native_evidence_self_contained=true
          fresh_process_bundle_model_verification=true
          fresh_process_bundle_archive_rejection=true
          RESULT
        '';
      }
    ];
  }
