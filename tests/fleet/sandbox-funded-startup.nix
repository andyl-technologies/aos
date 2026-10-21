# Qualifies the installed startup enclosure before external owner provisioning.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  system = import ./_sandbox-funded-system.nix {inherit lib pkgs systems;};
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
          vm.wait_for_unit("multi-user.target", timeout=300)
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

      check_startup_enclosure()
      vm.reboot()
      check_startup_enclosure()
    '';
}
