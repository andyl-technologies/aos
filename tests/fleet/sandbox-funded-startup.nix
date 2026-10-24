# Qualifies the installed startup enclosure before external owner provisioning.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  fundedSystem = import ./_sandbox-funded-system.nix {inherit lib pkgs systems;};
  system = fundedSystem.extendModules {
    modules = [{environment.systemPackages = [pkgs.python3];}];
  };
  enrolledFirmwareVars = import ./_secure-boot-enrolled-vars.nix {
    inherit lib pkgs systems;
  };
in {
  name = "sandbox-funded-startup";
  timeout = 1800;
  bootTimeout = 300;

  machines.vm = {
    inherit system;
    bootMode = "image";
    firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
    tpm = true;
    vcpuCount = 16;
    # Leave kernel and firmware overhead outside the advertised 32 GiB bank.
    memoryMiB = 36864;
    varSizeMiB = 65536;
    imageDiskMiB = 98304;
  };

  testScript =
    # python
    ''
      def check_startup_enclosure():
          # Overlay roots must remain traversable by confined roles after both
          # boot and native activation, without flattening store inode labels.
          root_labels = (
              "import os; "
              "expected = {'/etc': 'etc_t', '/nix': 'usr_t', '/nix/store': 'usr_t', "
              "'${pkgs.glibc}/lib/libm.so.6': 'lib_t'}; "
              "observed = {path: os.getxattr(path, 'security.selinux').rstrip(b'\\0').decode().split(':')[2] "
              "for path in expected}; "
              "assert observed == expected, observed"
          )
          vm.succeed("${pkgs.python3}/bin/python3 -c \"" + root_labels + "\"")
          vm.wait_for_unit("multi-user.target", timeout=300)
          vm.wait_for_unit("aos-activate.service", timeout=60)
          vm.succeed("${pkgs.python3}/bin/python3 -c \"" + root_labels + "\"")
          vm.succeed("test -c /dev/tpmrm0; test $(cat /sys/fs/selinux/enforce) = 1")
          assert int(vm.succeed("nproc --all").strip()) == 16
          memory = dict(line.split(":", 1) for line in vm.succeed("cat /proc/meminfo").splitlines())
          assert int(memory["MemTotal"].split()[0]) >= 32 * 1024 * 1024
          assert "[confidentiality]" in vm.succeed("cat /sys/kernel/security/lockdown")

          # These are the real kernel controls installed before generators,
          # rather than systemd's configured values or a synthetic receipt.
          controls = {
              "init.scope": (100000, 4294967296, 64),
              "aoscomponents.slice": (300000, 4294967296, 128),
          }
          for group, (quota, memory, tasks) in controls.items():
              root = f"/sys/fs/cgroup/{group}"
              assert vm.succeed(f"cat {root}/cpu.max").strip() == f"{quota} 100000"
              assert int(vm.succeed(f"cat {root}/memory.max").strip()) == memory
              assert int(vm.succeed(f"cat {root}/pids.max").strip()) == tasks

          # No external credentials or operation authority are provisioned by
          # this frontier. Starting from the bank cannot enable public Create.
          assert vm.succeed(
              "cat /etc/aos/method46-tpm-floor/controller-mode"
          ).strip() == "legacy-closed-v1"
          assert vm.succeed(
              "cat /etc/aos/method46-tpm-floor/storage-mode"
          ).strip() == "legacy-closed-v1"

      def check_startup_with_diagnostics():
          try:
              check_startup_enclosure()
          except Exception:
              # Preserve bounded startup evidence before the driver tears down
              # the guest. Serial audit backlogs can overflow before a failure.
              for command in (
                  "systemctl --failed --no-pager",
                  "journalctl -b --no-pager -n 160",
                  "tail -c 65536 /var/log/audit/audit.log",
              ):
                  try:
                      status, stdout, stderr = vm.execute(command, timeout=15)
                      output = (stdout + stderr).decode("utf-8", errors="replace")
                      print(f"startup diagnostic ({status}): {command}\n{output}", flush=True)
                  except Exception as error:
                      print(f"startup diagnostic unavailable: {error}", flush=True)
              raise

      check_startup_with_diagnostics()
      vm.reboot()
      check_startup_with_diagnostics()
    '';
}
