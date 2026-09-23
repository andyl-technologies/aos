{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase9.gates.campaignFindingPortability",
  taskIds ? ["T-CAM-9.4"],
  packagedReplay,
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-finding-portability";
    version = "0";
    src = crucibleSrc;

    buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed packagedReplay] ++ dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "run-self-contained-finding-replay";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/crucible-campaign-finding-portability-target"
          run_exact_test() {
            package=$1
            target_kind=$2
            test_target=$3
            selector=$4
            listing=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              "$target_kind" "$test_target" \
              "$selector" \
              -- --exact --list)
            printf '%s\n' "$listing" | grep -Fqx "$selector: test"

            output=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
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
          fresh_process_bundle_verification=true
          RESULT
        '';
      }
    ];
  }
