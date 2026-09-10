{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.lazyFrontier",
  taskIds ? ["T-CAM-4.1" "T-CAM-4.2" "T-CAM-4.3" "T-CAM-4.4" "T-CAM-4.5" "T-CAM-4.6"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase4-lazy-frontier";
    version = "0";
    src = crucibleSrc;

    buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust];
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
        name = "run-lazy-frontier";
        script = ''
          set -eu
          : "$DEPENDENCY_PATHS"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/lazy-frontier-target"
          run_exact_lib_test() {
            package="$1"
            expected="$2"
            list_output=$(cargo test --frozen --offline \
              --manifest-path crates/Cargo.toml --target-dir "$target" \
              -p "$package" --lib "$expected" -- --exact --list 2>&1)
            exact_count=$(printf '%s\n' "$list_output" | grep -Fxc "$expected: test" || true)
            if [ "$exact_count" -ne 1 ]; then
              printf '%s\n' "$list_output" >&2
              echo "expected exactly one test named $expected, found $exact_count" >&2
              exit 1
            fi

            test_output=$(cargo test --frozen --offline \
              --manifest-path crates/Cargo.toml --target-dir "$target" \
              -p "$package" --lib "$expected" -- \
              --exact --test-threads=1 2>&1)
            printf '%s\n' "$test_output"
            if ! printf '%s\n' "$test_output" \
              | grep -F "test result: ok. 1 passed;" >/dev/null; then
              echo "exact test $expected did not report one passed test" >&2
              exit 1
            fi
          }

          run_exact_lib_test \
            crucible-campaign \
            merkle::bulk::tests::million_dormant_continuations_use_bounded_production_frontier_pages
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$target" -p crucible-campaign \
            --test gate_lazy_frontier -- --test-threads=1
          run_exact_lib_test \
            crucible-daemon \
            executor_pool::tests::campaign_controls_remain_responsive_while_every_executor_slot_is_busy
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'gate=gate:lazy-frontier\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'scope=bounded-generated-polling,allocation-scaling,finite-backpressure,exhaustive-ceiling,frontier-pagination,feedback-recovery,restart,strict-streaming-order,daemon-control-responsiveness\n'
            printf 'open_scope=\n'
          } > "$out/result"
        '';
      }
    ];
  }
