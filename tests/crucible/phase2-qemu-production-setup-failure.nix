# Current host/plugin setup failures must return before scheduler construction
# and reap the real child through the production launch cleanup boundary.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuProductionSetupFailure",
  taskIds ? ["T-PROTO-8"],
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
  taskList = builtins.concatStringsSep "," taskIds;
in
  mkCrucibleTestGate {
    pname = "crucible-qemu-production-setup-failure";
    src = source;
    buildDeps = [pkgs.coreutils pkgs.grep];
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;

    phases = [
      {
        name = "run-production-setup-failures";
        script = ''
          set -eu
          # The tests run real child processes, so they keep one thread, but
          # share one listing and one exact invocation.
          crucible-exact-tests -p crucible-qemu-host --lib -- --test-threads=1 \
            host_setup::tests::qemu_host_plugin_setup_rejects_nonready_ack_after_descriptor_handoff \
            host_setup::tests::qemu_host_plugin_setup_rejects_peer_close_during_descriptor_handoff \
            host_setup::tests::qemu_host_plugin_setup_rejects_plugin_detected_real_region_corruption \
            supervision::node_step_gate::setup_failure_tests::invalid_region_setup_reaps_real_child_before_scheduler_admission \
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
