{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.campaignModel",
  taskIds ? ["T-CAM-1.1" "T-CAM-1.2" "T-CAM-1.3" "T-CAM-1.4" "T-CAM-1.5" "T-CAM-1.6" "T-CAM-3.1"],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-campaign-model.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
    }
  else
    pkgs.mkDerivation {
    pname = "crucible-phase1-campaign-model";
    version = "0";
    src = crucibleSrc;

    buildDeps = [pkgs.coreutils pkgs.rust];
    ATTR_PATH = attrPath;
    TASK_IDS = builtins.concatStringsSep "," taskIds;
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

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
        name = "run-campaign-model";
        script = ''
          set -eu
          : "$DEPENDENCY_PATHS"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          run_exact_lib_test() {
            gate_package=$1
            gate_test=$2

            if output=$(cargo test --frozen --offline \
              --manifest-path crates/Cargo.toml \
              --target-dir "$TMPDIR/campaign-model-target" \
              -p "$gate_package" --lib -- --list 2>&1); then
              :
            else
              status=$?
              printf '%s\n' "$output" >&2
              exit "$status"
            fi
            printf '%s\n' "$output"
            match_count=$(printf '%s\n' "$output" | grep -Fxc "$gate_test: test" || true)
            if [ "$match_count" -ne 1 ]; then
              printf 'expected exactly one listed test named %s; found %s\n' \
                "$gate_test" "$match_count" >&2
              exit 1
            fi

            if output=$(cargo test --frozen --offline \
              --manifest-path crates/Cargo.toml \
              --target-dir "$TMPDIR/campaign-model-target" \
              -p "$gate_package" --lib -- --exact "$gate_test" --test-threads=1 2>&1); then
              :
            else
              status=$?
              printf '%s\n' "$output" >&2
              exit "$status"
            fi
            printf '%s\n' "$output"
            if ! printf '%s\n' "$output" \
              | grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;'; then
              printf 'required test did not produce the exact pass count: %s\n' \
                "$gate_test" >&2
              exit 1
            fi
          }

          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/campaign-model-target" \
            -p crucible-campaign --lib -- --test-threads=1
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/campaign-model-target" \
            -p crucible-campaign --test gate_campaign_model -- --test-threads=1
          run_exact_lib_test \
            crucible \
            model::measurement::runtime::tests::model_sources_project_exact_replay_samples
          run_exact_lib_test \
            crucible-daemon \
            crucible_measurement::evidence::tests::v2_publication_round_trips_and_rederives_guest_and_model_samples
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
