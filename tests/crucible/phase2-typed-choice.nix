{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.typedChoice",
  taskIds ? ["T-CAM-2.1" "T-CAM-2.2" "T-CAM-2.3" "T-CAM-2.4" "T-CAM-2.5" "T-CAM-2.7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-typed-choice";
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
        name = "run-typed-choice";
        script = ''
          set -eu
          : "$DEPENDENCY_PATHS"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible-campaign --lib -- --test-threads=1
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible-campaign --test gate_typed_choice -- --test-threads=1
          exact_selection_test=tests::model_core::campaign_selection_decision_is_strict_and_changes_schedule_identity
          selection_listing=$(cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible --lib "$exact_selection_test" -- --exact --list 2>&1)
          printf '%s\n' "$selection_listing"
          selection_match_count=$(printf '%s\n' "$selection_listing" \
            | grep -Fxc "$exact_selection_test: test" || true)
          if [ "$selection_match_count" -ne 1 ]; then
            printf 'expected exactly one listed test named %s; found %s\n' \
              "$exact_selection_test" "$selection_match_count" >&2
            exit 1
          fi

          selection_output=$(cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible --lib "$exact_selection_test" -- --exact --test-threads=1 2>&1)
          printf '%s\n' "$selection_output"
          if ! printf '%s\n' "$selection_output" \
            | grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;'; then
            printf 'required test did not produce the exact pass count: %s\n' \
              "$exact_selection_test" >&2
            exit 1
          fi
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible --test backend_node_routing live_world_network_ -- --test-threads=1
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible --test gate_guided_adaptive_exploration gate_preemption_branching_ \
            -- --test-threads=1
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible-protocol --lib selectable -- --test-threads=1
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/typed-choice-target" \
            -p crucible-guest --lib selectable -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'gate=gate:typed-choice\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'scope=typed-domain,selection-replay,live-network-selection,preemption-selection,guest-selectable-codec\n'
          } > "$out/result"
        '';
      }
    ];
  }
