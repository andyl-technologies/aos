{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.hotForkIsolation.rawGate",
  taskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-hot-fork-isolation";
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
        name = "run-hot-fork-isolation";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/crucible-phase7-hot-fork-isolation-target"
          run_exact_lib_test() {
            package="$1"
            expected="$2"
            if list_output=$(cargo test --frozen --offline \
              --manifest-path crates/Cargo.toml --target-dir "$target" \
              -p "$package" --lib "$expected" -- --exact --list 2>&1); then
              :
            else
              cargo_status=$?
              printf '%s\n' "$list_output" >&2
              exit "$cargo_status"
            fi
            exact_count=$(printf '%s\n' "$list_output" | grep -Fxc "$expected: test" || true)
            if [ "$exact_count" -ne 1 ]; then
              printf '%s\n' "$list_output" >&2
              echo "expected exactly one test named $expected, found $exact_count" >&2
              exit 1
            fi

            if test_output=$(cargo test --frozen --offline \
              --manifest-path crates/Cargo.toml --target-dir "$target" \
              -p "$package" --lib "$expected" -- \
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
              echo "exact test $expected did not report one passed test" >&2
              exit 1
            fi
          }

          run_exact_lib_test \
            crucible-shmem \
            mapped_setup_region::tests::hot_fork_child_installs_private_mapping_at_exact_source_address
          run_exact_lib_test \
            crucible-qemu \
            node::tests::hot_fork::gate_hot_fork_isolation_keeps_two_resource_generations_physically_private
          run_exact_lib_test \
            crucible-daemon \
            qemu_hot_fork_world_factory::tests::two_running_nodes_install_shutdown_reconcile_and_reuse_one_source_world
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:hot-fork-isolation
          tasks=${builtins.concatStringsSep "," taskIds}
          scope=component-production
          private_rings=fault-command,fault-event,network,block,9p,coverage,doorbell
          private_sockets=plugin-control,qmp,console,diagnostics
          private_files=vmstate-destination
          host_continuation=one-sided-mutation-isolated
          sibling_liveness=simultaneous-component-generations
          hostile_alias=source-backing,foreign-identity,wrong-length,occupied-address-refused
          production_factory=two-generations-from-one-retained-source
          cleanup=run-directories-removed,child-pids-reaped
          full_native_required=true
          native_status=held
          open_scope=native-network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation
          RESULT
        '';
      }
    ];
  }
