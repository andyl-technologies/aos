##! lib/testing/package-firewall-reload.nix — package firewall reload coherence.
{
  pkgs,
  mkSystem,
  testing,
}: let
  package = pkgs.expose-smoke;
  expose = package.expose;
  firewallUnit = "aos-pkg-expose-smoke-firewall.service";
  testSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      ({...}: {
        environment.etc."systemd/system/${firewallUnit}".source = "${expose}/units/${firewallUnit}";
        environment.etc."systemd/system/nftables.service.d/50-aos-package-firewall-reload.conf".text = ''
          [Unit]
          X-RestartIfChanged=false
          PropagatesReloadTo=${firewallUnit}
        '';
      })
    ];
  };
in
  testing.mkVMTest {
    name = "package-firewall-reload";
    system = testSystem;
    timeout = 120;
    testScript = ''
      import time

      def assert_package_ports():
          ruleset = vm.succeed("${pkgs.nftables}/sbin/nft list ruleset")
          assert "5353" in ruleset, ruleset
          assert "aos-pkg-expose-smoke-forward" in ruleset, ruleset

      def wait_package_ports():
          last_ruleset = ""
          for _ in range(50):
              last_ruleset = vm.succeed("${pkgs.nftables}/sbin/nft list ruleset")
              if "5353" in last_ruleset and "aos-pkg-expose-smoke-forward" in last_ruleset:
                  return
              time.sleep(0.1)
          assert "5353" in last_ruleset, last_ruleset
          assert "aos-pkg-expose-smoke-forward" in last_ruleset, last_ruleset

      def assert_package_ports_absent():
          ruleset = vm.succeed("${pkgs.nftables}/sbin/nft list ruleset")
          assert "5353" not in ruleset, ruleset
          assert "aos-pkg-expose-smoke-forward" not in ruleset, ruleset

      vm.succeed("systemctl is-active nftables.service")
      vm.succeed("systemctl daemon-reload")
      vm.succeed("systemctl cat ${firewallUnit} | grep -F '# /etc/systemd/system/${firewallUnit}'")
      vm.succeed("grep -q '^ReloadPropagatedFrom=nftables.service$' /etc/systemd/system/${firewallUnit}")
      vm.succeed("systemctl cat nftables.service | grep -F 'X-RestartIfChanged=false'")
      vm.succeed("systemctl cat nftables.service | grep -F 'PropagatesReloadTo=${firewallUnit}'")
      vm.succeed("systemctl start ${firewallUnit}")
      assert_package_ports()
      vm.succeed("${pkgs.nftables}/sbin/nft -f /etc/nftables.conf")
      assert_package_ports_absent()
      vm.succeed("systemctl reload ${firewallUnit}")
      assert_package_ports()
      vm.succeed("${pkgs.nftables}/sbin/nft -f /etc/nftables.conf")
      assert_package_ports_absent()
      vm.succeed("systemctl reload nftables.service")
      wait_package_ports()
      vm.succeed("systemctl reload nftables.service")
      wait_package_ports()
    '';
  }
