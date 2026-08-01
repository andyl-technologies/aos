{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuShutdownEscalation",
  taskIds ? ["T-QEMU-8"],
}: let
  protocolShutdown = import ./phase2-protocol-shutdown-escalation.nix {
    inherit pkgs lib;
    attrPath = "${attrPath}.protocol";
    taskIds = ["T-QEMU-8" "T-PROTO-7"];
  };
  lifecycle = import ./phase0-lifecycle.nix {inherit pkgs lib;};

  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;
  shutdownTest = builtins.readFile ../../crates/crucible-qemu/tests/shutdown.rs;
  lifecycleSource = builtins.readFile ./phase0-lifecycle.c;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "QEMU-30 shutdown order requirement";
        needle = "**[QEMU-30]** Graceful shutdown MUST follow the escalation order";
      }
      {
        label = "QEMU-31 no-leak requirement";
        needle = "**[QEMU-31]** The host MUST `waitpid`/reap every QEMU child";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/shutdown.rs" shutdownTest [
      {
        label = "shutdown order test";
        needle = "shutdown_order_matches_protocol_spec";
      }
      {
        label = "unresponsive shutdown reaches SIGKILL";
        needle = "shutdown_escalates_to_sigkill_and_reaps_unresponsive_child";
      }
      {
        label = "real qemu child reaped";
        needle = "unix_adapter_reaps_real_qemu_child_when_polite_channels_fail";
      }
      {
        label = "leak error path";
        needle = "shutdown_reports_leak_when_reap_cannot_collect_child";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-lifecycle.c" lifecycleSource [
      {
        label = "clean stop path";
        needle = "run_clean_stop(qemu, tmpdir, &counters)";
      }
      {
        label = "control stop path";
        needle = "run_signal_stop(qemu, SIGTERM, &counters.control_stop, &counters)";
      }
      {
        label = "guest crash path";
        needle = "run_guest_crash(qemu, vmlinuz, rootfs, serial_log, &counters)";
      }
      {
        label = "plugin hang path";
        needle = "run_plugin_hang(qemu, plugin, &counters)";
      }
      {
        label = "setup failure path";
        needle = "run_setup_failure(qemu, &counters)";
      }
      {
        label = "host sigkill path";
        needle = "run_signal_stop(qemu, SIGKILL, &counters.host_sigkill, &counters)";
      }
      {
        label = "parent death path";
        needle = "run_parent_death(qemu, &counters)";
      }
      {
        label = "survivor assertion";
        needle = "if (counters.survivors != 0)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu shutdown-escalation check";
        needle = "qemuShutdownEscalation = import ./phase2-qemu-shutdown-escalation.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu shutdown-escalation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-shutdown-escalation";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ];

      phases = [
        {
          name = "aggregate-qemu-shutdown-escalation";
          script = ''
            set -eu

            mkdir -p "$out"
            protocol_result="${protocolShutdown}/result"
            lifecycle_result="${lifecycle}/result"

            grep -q '^PASS$' "$protocol_result"
            grep -q '^gate=gate:control-responsive$' "$protocol_result"
            grep -q '^order=Quit,QMP-quit,SIGTERM,SIGKILL,reap$' "$protocol_result"
            grep -q '^no_leak=real-qemu-child-reaped$' "$protocol_result"

            grep -q '^PASS$' "$lifecycle_result"
            grep -q '^spike=no-leak-lifecycle$' "$lifecycle_result"
            grep -q '^clean_stop=1$' "$lifecycle_result"
            grep -q '^control_stop=1$' "$lifecycle_result"
            grep -q '^guest_crash=1$' "$lifecycle_result"
            grep -q '^plugin_hang=1$' "$lifecycle_result"
            grep -q '^setup_failure=1$' "$lifecycle_result"
            grep -q '^host_sigkill=1$' "$lifecycle_result"
            grep -q '^parent_death=1$' "$lifecycle_result"
            grep -q '^survivors=0$' "$lifecycle_result"

            cp "$protocol_result" "$out/protocol-shutdown.result"
            cp "$lifecycle_result" "$out/no-leak-lifecycle.result"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:control-responsive
            shutdown_order=Quit,QMP-quit,SIGTERM,SIGKILL,reap
            bounded_rungs=control-quit,qmp-quit,sigterm,sigkill,reap
            no_leak_paths=clean-stop,control-stop,guest-crash,plugin-hang,setup-failure,host-sigkill,parent-death
            real_qemu_lifecycle=checks.crucible.phase0.lifecycle
            protocol_shutdown=checks.crucible.phase2.protocolShutdownEscalation
            RESULT
          '';
        }
      ];
    }
