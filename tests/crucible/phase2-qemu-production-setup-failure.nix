# Current host/plugin setup failures must return before scheduler construction
# and reap the real child through the production launch cleanup boundary.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuProductionSetupFailure",
  taskIds ? ["T-PROTO-8"],
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  taskList = builtins.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-qemu-production-setup-failure";
    version = "0";
    src = source;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust];
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;

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
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "run-production-setup-failures";
        script = ''
          set -eu
          qemu_tests="$TMPDIR/crucible-qemu-tests"
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" -p crucible-qemu --lib -- --list \
            > "$qemu_tests"

          run_exact_test() {
            name="$1"
            grep -Fqx "$name: test" "$qemu_tests"
            cargo test --frozen --offline --manifest-path crates/Cargo.toml \
              --target-dir "$TMPDIR/target" -p crucible-qemu --lib \
              "$name" -- --exact --test-threads=1
          }

          run_exact_test \
            host_setup::tests::qemu_host_plugin_setup_rejects_nonready_ack_after_descriptor_handoff
          run_exact_test \
            host_setup::tests::qemu_host_plugin_setup_rejects_peer_close_during_descriptor_handoff
          run_exact_test \
            host_setup::tests::qemu_host_plugin_setup_rejects_plugin_detected_real_region_corruption
          run_exact_test \
            supervision::node_step_gate::setup_failure_tests::invalid_region_setup_reaps_real_child_before_scheduler_admission
          run_exact_test \
            supervision::node_step_gate::setup_failure_tests::nonready_ack_after_descriptor_handoff_reaps_real_child_before_scheduler_admission

          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'check=%s\n' "$ATTR_PATH"
            printf 'tasks=%s\n' "$TASK_IDS"
            printf 'descriptor_handoff=fail-closed\n'
            printf 'setup_ack=non-ready-rejected\n'
            printf 'real_region_validation=corruption-rejected\n'
            printf 'invalid_region_child=reaped-before-scheduler-admission\n'
            printf 'nonready_ack_child=reaped-before-scheduler-admission\n'
          } > "$out/result"
        '';
      }
    ];
  }
