##! modules/tests/boot.nix — Core boot verification checks
##!
##! Verifies that the system boots to multi-user.target with systemd as PID 1,
##! essential filesystems are mounted, and the system identity is correct.
{ config, lib, ... }:
{
  system.checks.system-boot = {
    description = "Core system boot verification";
    checks = [
      {
        name = "systemd-pid1";
        description = "systemd is running as PID 1";
        script = ''
          assert_output_contains "cat /proc/1/comm" "systemd" "PID 1 is systemd"
        '';
      }
      {
        name = "multi-user-target";
        description = "system reached multi-user.target";
        script = ''
          assert_success "systemctl is-active multi-user.target" "multi-user.target is active"
        '';
      }
      {
        name = "os-release";
        description = "/etc/os-release identifies ANDYL OS";
        script = ''
          assert_output_contains "cat /etc/os-release" "ANDYL OS" "/etc/os-release contains ANDYL OS"
        '';
      }
      {
        name = "hostname";
        description = "hostname is set";
        script = ''
          assert_success "test -s /etc/hostname" "/etc/hostname is non-empty"
        '';
      }
      {
        name = "nix-store-present";
        description = "/nix/store contains system packages";
        script = ''
          assert_success "test -d /nix/store" "/nix/store exists"
          assert_success "test -e /sbin/init" "/sbin/init exists"
        '';
      }
      {
        name = "essential-filesystems";
        description = "proc, sys, dev are mounted";
        script = ''
          assert_success "test -d /proc/1" "/proc is mounted"
          assert_success "test -d /sys/class" "/sys is mounted"
          assert_success "test -c /dev/null" "/dev/null exists"
        '';
      }
      {
        name = "root-read-only";
        description = "root filesystem is mounted read-only (immutable OS design)";
        script = ''
          # The immutable OS design mounts / as ext4 ro; mutable state
          # lives on /var (rw) and /etc is an overlayfs with a tmpfs
          # upper layer. A writable / would undermine the model.
          assert_output_contains "findmnt -n -o OPTIONS /" "ro" \
            "root filesystem is mounted read-only"
        '';
      }
    ];
  };
}
