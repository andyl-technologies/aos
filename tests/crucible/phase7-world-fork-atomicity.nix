{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.worldForkAtomicity.rawGate",
  taskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-world-fork-atomicity";
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
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
        '';
      }
      {
        name = "run-world-fork-atomicity";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/world-fork-atomicity-target"
          run_exact_test() {
            exact_test="$1"
            if list_output=$(cargo test --frozen --offline --release \
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

            if test_output=$(cargo test --frozen --offline --release \
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
          }

          run_exact_test qemu_hot_fork_world_factory::tests::world_fork_atomicity::production_three_node_clean_rejection_is_atomic_at_every_launch_index
          run_exact_test qemu_hot_fork_world_factory::tests::world_fork_atomicity::production_three_node_ambiguous_launch_is_fail_closed_at_every_index
          run_exact_test qemu_hot_fork_world_factory::tests::world_fork_atomicity::production_three_node_adoption_failure_retains_the_complete_world
          run_exact_test qemu_hot_fork_world_factory::tests::world_fork_atomicity::production_aggregate_release_failure_blocks_source_restore
          run_exact_test qemu_hot_fork_world_factory::tests::world_fork_atomicity::production_source_identity_drift_blocks_restore_after_complete_rollback
          run_exact_test qemu_hot_fork_world_factory::tests::world_fork_atomicity::rollback_retains_every_unfinished_owner_on_termination_failure
          run_exact_test qemu_hot_fork_world_factory::tests::world_fork_atomicity::rollback_deadline_covers_reap_private_release_and_cancellation_progress
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'gate=gate:world-fork-atomicity\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'dependency_count=%s\n' "$DEPENDENCY_COUNT"
            printf 'tier=model\n'
            printf 'factory=production-whole-world\n'
            printf 'source=three-running-nodes\n'
            printf 'failure_indices=0,1,2\n'
            printf 'clean_rejection=rollback-reap-release-reauth-retry\n'
            printf 'fail_closed=indeterminate,adoption,termination,reap,private-release,aggregate-release,source-identity\n'
            printf 'qemu=not-launched\n'
            printf 'open_scope=native-real-qemu-matrix,T-CAM-7.4\n'
          } > "$out/result"
        '';
      }
    ];
  }
