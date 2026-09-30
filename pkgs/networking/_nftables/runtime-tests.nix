##! Focused VM checks for the installed host firewall policy.
{}: {
  description = "nftables firewall checks";
  checks = [
    {
      name = "ruleset-loaded";
      description = "nftables ruleset is loaded";
      script = ''
        vm.succeed("nft list ruleset")
      '';
    }
  ];
}
