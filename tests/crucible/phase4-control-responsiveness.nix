{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.controlResponsiveness",
  taskIds ? ["T-CAM-4.5" "T-CAM-4.6" "T-CAM-4.9" "T-CAM-8.1" "T-CAM-8.2"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase4-control-responsiveness";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
      ]
      ++ dependencies;
    ATTR_PATH = attrPath;
    TASK_IDS = builtins.concatStringsSep "," taskIds;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);

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
        name = "run-control-responsiveness";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/control-responsiveness-target"
          exact_test="executor_pool::tests::campaign_controls_remain_responsive_while_every_executor_slot_is_busy"
          if list_output=$(cargo test --frozen --offline \
            --manifest-path crates/Cargo.toml --target-dir "$target" \
            -p crucible-daemon --lib "$exact_test" -- --exact --list 2>&1); then
            :
          else
            cargo_status=$?
            printf '%s\n' "$list_output" >&2
            exit "$cargo_status"
          fi
          exact_count=$(printf '%s\n' "$list_output" | grep -Fxc "$exact_test: test" || true)
          if [ "$exact_count" -ne 1 ]; then
            printf '%s\n' "$list_output" >&2
            echo "expected exactly one test named $exact_test, found $exact_count" >&2
            exit 1
          fi

          if test_output=$(cargo test --frozen --offline \
            --manifest-path crates/Cargo.toml --target-dir "$target" \
            -p crucible-daemon --lib "$exact_test" -- \
            --exact --test-threads=1 2>&1); then
            :
          else
            cargo_status=$?
            printf '%s\n' "$test_output" >&2
            exit "$cargo_status"
          fi
          printf '%s\n' "$test_output"
          if ! printf '%s\n' "$test_output" \
            | grep -F "test result: ok. 1 passed;" >/dev/null; then
            echo "exact test $exact_test did not report one passed test" >&2
            exit 1
          fi
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'gate=gate:control-responsiveness\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'dependency_count=%s\n' "$DEPENDENCY_COUNT"
            printf 'tier=model\n'
            printf 'controls=campaign-pause,campaign-status,campaign-pin,executor-shutdown\n'
            printf 'saturation=fixed-workers-busy-with-accepted-queue\n'
            printf 'control_latency_bound_ms=250\n'
            printf 'shutdown=sticky-cancel-drain-join\n'
            printf 'cancellation=all-executing-signaled,queued-drained-without-execution,admission-closed\n'
            printf 'reservation_release=after-physical-worker-exit-acknowledgement\n'
            printf 'open_scope=\n'
          } > "$out/result"
        '';
      }
    ];
  }
