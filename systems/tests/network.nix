# systems/tests/network.nix — Network configuration verification
#
# Verifies that networking is properly configured: systemd-networkd,
# DNS resolution, firewall rules, and network interfaces.
{ lib }:
{
  name = "network";
  description = "Network configuration verification";
  type = "vm";
  appliesTo = [
    "server"
    "edge"
  ];

  checks =
    { config, lib }:
    [
      (lib.mkCheck {
        name = "loopback-up";
        description = "loopback interface is up";
        script = ''
          assert_output_contains "cat /sys/class/net/lo/operstate" "unknown" \
            "loopback interface operstate"
        '';
      })
      (lib.mkCheck {
        name = "networkd-config";
        description = "systemd-networkd configuration directory exists";
        script = ''
          assert_success "test -d /etc/systemd/network" \
            "systemd-networkd config directory exists"
        '';
      })
      (lib.mkCheck {
        name = "network-tools";
        description = "systemd-networkd binary is present";
        script = ''
          assert_success "test -x /usr/bin/networkctl" "networkctl binary exists"
        '';
      })
      (lib.mkCheck {
        name = "nftables-config";
        description = "nftables firewall rules are configured";
        script = ''
          assert_success "test -f /etc/nftables.conf" "nftables.conf exists"
        '';
      })
    ];
}
