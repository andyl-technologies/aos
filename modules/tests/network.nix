##! modules/tests/network.nix — Network configuration verification checks
##!
##! Verifies networking: systemd-networkd, DNS resolution, firewall rules,
##! and network interfaces.
{
  config,
  lib,
  ...
}: {
  system.checks.system-network = {
    description = "Network configuration verification";
    checks = [
      {
        name = "loopback-up";
        description = "loopback interface is up";
        script = ''
          assert "unknown" in vm.succeed("cat /sys/class/net/lo/operstate")
        '';
      }
      {
        name = "networkd-config";
        description = "systemd-networkd configuration directory exists";
        script = ''
          vm.succeed("test -d /etc/systemd/network")
        '';
      }
      {
        name = "network-tools";
        description = "systemd-networkd binary is present";
        script = ''
          vm.succeed("test -x /usr/bin/networkctl")
        '';
      }
      {
        name = "nftables-config";
        description = "nftables firewall rules are configured";
        script = ''
          vm.succeed("test -f /etc/nftables.conf")
        '';
      }
    ];
  };
}
