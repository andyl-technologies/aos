{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.campaignReplay.rawGate",
  taskIds ? ["T-CAM-3.5" "T-CAM-4.10" "T-CAM-8.4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase4-campaign-replay";
    version = "0";
    src = crucibleSrc;

    buildDeps = [pkgs.coreutils pkgs.rust] ++ dependencies;

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
        name = "run-campaign-replay";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          run_gate_test() {
            gate_package=$1
            gate_test=$2

            if output=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/campaign-replay-target" \
              --manifest-path crates/Cargo.toml \
              -p "$gate_package" \
              --test gate_campaign_replay \
              -- --list 2>&1); then
              :
            else
              status=$?
              printf '%s\n' "$output" >&2
              exit "$status"
            fi
            printf '%s\n' "$output"
            if match_count=$(printf '%s\n' "$output" | grep -Fxc "$gate_test: test"); then
              :
            else
              match_count=0
            fi
            if [ "$match_count" -ne 1 ]; then
              printf 'expected exactly one listed test named %s; found %s\n' \
                "$gate_test" "$match_count" >&2
              exit 1
            fi

            if output=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/campaign-replay-target" \
              --manifest-path crates/Cargo.toml \
              -p "$gate_package" \
              --test gate_campaign_replay \
              -- --exact "$gate_test" --test-threads=1 2>&1); then
              :
            else
              status=$?
              printf '%s\n' "$output" >&2
              exit "$status"
            fi
            printf '%s\n' "$output"
            if ! printf '%s\n' "$output" | grep -Fqx "test $gate_test ... ok"; then
              printf 'required test did not report success: %s\n' "$gate_test" >&2
              exit 1
            fi
            if ! printf '%s\n' "$output" \
              | grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;'; then
              printf 'required test did not produce the exact pass count: %s\n' "$gate_test" >&2
              exit 1
            fi
          }

          run_gate_test \
            crucible-campaign \
            strict_campaign_planner_reproduces_every_accepted_step
          run_gate_test \
            crucible \
            offline_rich_finding_replays_without_campaign_store

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-replay
          scope=portable-model,strict
          tier=component
          open=production-qemu,native
          RESULT
        '';
      }
    ];
  }
