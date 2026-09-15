##! Selects the package-owned nftables firewall module for static systems.
{
  config,
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.nftables];

  system.checks.firewall = lib.mkIf config.aos.firewall.enable {
    description = "nftables firewall checks";
    checks = [
      {
        name = "nftables-active";
        description = "nftables service is active";
        script = ''
          vm.succeed("systemctl is-active nftables")
        '';
      }
      {
        name = "ruleset-loaded";
        description = "nftables ruleset is loaded";
        script = ''
          vm.succeed("${pkgs.nftables}/sbin/nft list ruleset")
        '';
      }
    ];
  };
}
