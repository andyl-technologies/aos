# Qualifies the installed startup enclosure before external owner provisioning.
{
  lib,
  pkgs,
  systems,
  expectedFloorMode ? "legacy-closed-v1",
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
    builtins.readFile ./_sandbox-startup-diagnostics.py
    + builtins.readFile ./_sandbox-cold-boot.py
    +
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

          # Native activation succeeding does not prove that early socket
          # owners exist: PID 1 can reach multi-user with failed socket units.
          for principal, identity in (
              ("aos-sandboxd", 811),
              ("aos-source-signer", 814),
              ("aos-sandbox-zfs-worker", 992),
          ):
              row = vm.succeed(f"getent passwd {principal}").strip().split(":")
              assert len(row) == 7 and row[0] == principal, row
              assert row[2:4] == [str(identity)] * 2, row
              assert row[6] == "${pkgs.util-linux}/sbin/nologin", row

          for socket in (
              "aos-sandbox-hostd.socket",
              "aos-sandbox-mountd.socket",
              "aos-netd.socket",
              "aos-sandbox-ownershipd.socket",
              "aos-storaged.socket",
          ):
              vm.wait_for_unit(socket, timeout=30)

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
          ).strip() == "${expectedFloorMode}"
          assert vm.succeed(
              "cat /etc/aos/method46-tpm-floor/storage-mode"
          ).strip() == "${expectedFloorMode}"

      with startup_diagnostics(vm):
          check_startup_enclosure()
          power_cycle_and_require_new_boot(vm)
          check_startup_enclosure()
    '';
}
