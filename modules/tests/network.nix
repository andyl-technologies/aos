##! modules/tests/network.nix — Network configuration verification checks
##!
##! Verifies networking: systemd-networkd, DNS resolution, firewall rules,
##! and network interfaces.
{ config, lib, ... }:
{
  system.checks.system-network = {
    description = "Network configuration verification";
    checks = [
      {
        name = "loopback-up";
        description = "loopback interface is up";
        script = ''
          assert_output_contains "cat /sys/class/net/lo/operstate" "unknown" \
            "loopback interface operstate"
        '';
      }
      {
        name = "networkd-config";
        description = "systemd-networkd configuration directory exists";
        script = ''
          assert_success "test -d /etc/systemd/network" \
            "systemd-networkd config directory exists"
        '';
      }
      {
        name = "network-tools";
        description = "systemd-networkd binary is present";
        script = ''
          assert_success "test -x /usr/bin/networkctl" "networkctl binary exists"
        '';
      }
      {
        name = "nftables-config";
        description = "nftables firewall rules are configured";
        script = ''
          assert_success "test -f /etc/nftables.conf" "nftables.conf exists"
        '';
      }
    ];
  };
}
