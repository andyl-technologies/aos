# systems/tests/boot.nix — Core boot verification
#
# Verifies that the system boots to multi-user.target with systemd as PID 1,
# essential filesystems are mounted, and the system identity is correct.
{ lib }:
{
  name = "boot";
  description = "Core system boot verification";
  type = "vm";
  appliesTo = [
    "server"
    "edge"
  ];

  checks =
    { config, lib }:
    [
      (lib.mkCheck {
        name = "systemd-pid1";
        description = "systemd is running as PID 1";
        script = ''
          assert_output_contains "cat /proc/1/comm" "systemd" "PID 1 is systemd"
        '';
      })
      (lib.mkCheck {
        name = "multi-user-target";
        description = "system reached multi-user.target";
        script = ''
          assert_success "systemctl is-active multi-user.target" "multi-user.target is active"
        '';
      })
      (lib.mkCheck {
        name = "os-release";
        description = "/etc/os-release identifies ANDYL OS";
        script = ''
          assert_output_contains "cat /etc/os-release" "ANDYL OS" "/etc/os-release contains ANDYL OS"
        '';
      })
      (lib.mkCheck {
        name = "hostname";
        description = "hostname is set";
        script = ''
          assert_success "test -s /etc/hostname" "/etc/hostname is non-empty"
        '';
      })
      (lib.mkCheck {
        name = "nix-store-present";
        description = "/nix/store contains system packages";
        script = ''
          assert_success "test -d /nix/store" "/nix/store exists"
          assert_success "test -e /sbin/init" "/sbin/init exists"
        '';
      })
      (lib.mkCheck {
        name = "essential-filesystems";
        description = "proc, sys, dev are mounted";
        script = ''
          assert_success "test -d /proc/1" "/proc is mounted"
          assert_success "test -d /sys/class" "/sys is mounted"
          assert_success "test -c /dev/null" "/dev/null exists"
        '';
      })
      (lib.mkCheck {
        name = "root-writable";
        description = "root filesystem is mounted read-write";
        script = ''
          assert_success "test -w /" "root filesystem is writable"
        '';
      })
    ];
}
