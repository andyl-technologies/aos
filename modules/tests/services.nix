##! modules/tests/services.nix — Core services verification checks
##!
##! Verifies that essential system services (SSH, chrony, systemd-networkd,
##! systemd-journald) are configured correctly.
{
  config,
  lib,
  ...
}: {
  system.checks.system-services = {
    description = "Core system services verification";
    checks = [
      {
        name = "journald-running";
        description = "systemd-journald is active";
        script = ''
          vm.succeed("systemctl is-active systemd-journald")
        '';
      }
      {
        name = "networkd-unit";
        description = "systemd-networkd unit is installed";
        script = ''
          vm.succeed("systemctl cat systemd-networkd.service")
        '';
      }
      {
        name = "sshd-unit-exists";
        description = "sshd service unit is installed";
        script = ''
          vm.succeed("systemctl cat sshd.service")
        '';
      }
      {
        name = "sshd-config";
        description = "sshd configuration file is present";
        script = ''
          vm.succeed("test -f /etc/ssh/sshd_config")
        '';
      }
      {
        name = "chrony-unit-exists";
        description = "chronyd service unit is installed";
        script = ''
          vm.succeed("systemctl cat chronyd.service")
        '';
      }
      {
        name = "chrony-config";
        description = "chrony configuration file is present";
        script = ''
          vm.succeed("test -f /etc/chrony.conf")
        '';
      }
    ];
  };
}
