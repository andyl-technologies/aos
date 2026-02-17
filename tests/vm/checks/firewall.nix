{
  mkCheck,
  mkCheckGroup,
}:
mkCheckGroup {
  name = "firewall";
  description = "nftables firewall checks";
  checks = [
    (mkCheck {
      name = "nftables-active";
      description = "nftables service is active";
      script = ''
        assert_success "systemctl is-active nftables" \
          "nftables service is active"
      '';
    })
    (mkCheck {
      name = "ruleset-loaded";
      description = "nftables ruleset is loaded";
      script = ''
        assert_success "nft list ruleset" \
          "nftables ruleset is loaded"
      '';
    })
  ];
}
