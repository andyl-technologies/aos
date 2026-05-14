##! modules/tests/boot.nix — Core boot verification checks
##!
##! Verifies that the system boots to multi-user.target with systemd as PID 1,
##! essential filesystems are mounted, and the system identity is correct.
{
  config,
  lib,
  ...
}: {
  system.checks.system-boot = {
    description = "Core system boot verification";
    checks = [
      {
        name = "systemd-pid1";
        description = "systemd is running as PID 1";
        script = ''
          assert "systemd" in vm.succeed("cat /proc/1/comm")
        '';
      }
      {
        name = "multi-user-target";
        description = "system reached multi-user.target";
        script = ''
          vm.succeed("systemctl is-active multi-user.target")
        '';
      }
      {
        name = "os-release";
        description = "/etc/os-release identifies ANDYL OS";
        script = ''
          assert "ANDYL OS" in vm.succeed("cat /etc/os-release")
        '';
      }
      {
        name = "hostname";
        description = "hostname is set";
        script = ''
          vm.succeed("test -s /etc/hostname")
        '';
      }
      {
        name = "nix-store-present";
        description = "/nix/store contains system packages";
        script = ''
          vm.succeed("test -d /nix/store")
          vm.succeed("test -e /sbin/init")
        '';
      }
      {
        name = "essential-filesystems";
        description = "proc, sys, dev are mounted";
        script = ''
          vm.succeed("test -d /proc/1")
          vm.succeed("test -d /sys/class")
          vm.succeed("test -c /dev/null")
        '';
      }
      {
        name = "root-read-only";
        description = "root filesystem is mounted read-only (immutable OS design)";
        script = ''
          # The immutable OS design mounts / as ext4 ro; mutable state
          # lives on /var (rw) and /etc is an overlayfs with a tmpfs
          # upper layer. A writable / would undermine the model.
          #
          # `findmnt -O ro /` filters by mount option: exit 0 iff `/`
          # actually carries the `ro` flag. We previously substring-
          # grepped the OPTIONS column for "ro", which silently passed
          # on a writable ext4 root because `errors=remount-ro` (the
          # ext4 default) contains the literal "ro" — exactly the
          # regression we were trying to catch.
          vm.succeed("findmnt -O ro /")
        '';
      }
    ];
  };
}
