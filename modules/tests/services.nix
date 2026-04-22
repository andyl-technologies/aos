##! modules/tests/services.nix — Core services verification checks
##!
##! Verifies that essential system services (SSH, chrony, systemd-networkd,
##! systemd-journald) are configured correctly.
{ config, lib, ... }:
{
  system.checks.system-services = {
    description = "Core system services verification";
    checks = [
      {
        name = "journald-running";
        description = "systemd-journald is active";
        script = ''
          assert_success "systemctl is-active systemd-journald" "journald is running"
        '';
      }
      {
        name = "networkd-unit";
        description = "systemd-networkd unit is installed";
        script = ''
          assert_success "systemctl cat systemd-networkd.service" "networkd unit exists"
        '';
      }
      {
        name = "sshd-unit-exists";
        description = "sshd service unit is installed";
        script = ''
          assert_success "systemctl cat sshd.service" "sshd.service unit exists"
        '';
      }
      {
        name = "sshd-config";
        description = "sshd configuration file is present";
        script = ''
          assert_success "test -f /etc/ssh/sshd_config" "sshd_config exists"
        '';
      }
      {
        name = "chrony-unit-exists";
        description = "chronyd service unit is installed";
        script = ''
          assert_success "systemctl cat chronyd.service" "chronyd.service unit exists"
        '';
      }
      {
        name = "chrony-config";
        description = "chrony configuration file is present";
        script = ''
          assert_success "test -f /etc/chrony.conf" "chrony.conf exists"
        '';
      }
    ];
  };
}
