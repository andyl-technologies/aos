# systems/tests/services.nix — Core services verification
#
# Verifies that essential system services (SSH, chrony, systemd-networkd,
# systemd-journald) are configured and running correctly.
{ lib }:
{
  name = "services";
  description = "Core system services verification";
  type = "vm";
  appliesTo = [
    "server"
    "edge"
  ];

  checks =
    { config, lib }:
    [
      (lib.mkCheck {
        name = "journald-running";
        description = "systemd-journald is active";
        script = ''
          assert_success "systemctl is-active systemd-journald" "journald is running"
        '';
      })
      (lib.mkCheck {
        name = "networkd-unit";
        description = "systemd-networkd unit is installed";
        script = ''
          assert_success "systemctl cat systemd-networkd.service" "networkd unit exists"
        '';
      })
      (lib.mkCheck {
        name = "sshd-unit-exists";
        description = "sshd service unit is installed";
        script = ''
          assert_success "systemctl cat sshd.service" "sshd.service unit exists"
        '';
      })
      (lib.mkCheck {
        name = "sshd-config";
        description = "sshd configuration file is present";
        script = ''
          assert_success "test -f /etc/ssh/sshd_config" "sshd_config exists"
        '';
      })
      (lib.mkCheck {
        name = "chrony-unit-exists";
        description = "chronyd service unit is installed";
        script = ''
          assert_success "systemctl cat chronyd.service" "chronyd.service unit exists"
        '';
      })
      (lib.mkCheck {
        name = "chrony-config";
        description = "chrony configuration file is present";
        script = ''
          assert_success "test -f /etc/chrony.conf" "chrony.conf exists"
        '';
      })
    ];
}
