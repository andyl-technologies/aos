##! Preserves the DNS runtime query check.
{cfg}: {
  description = "dnsmasq service checks";
  checks = [
    {
      name = "local-dns-query";
      description = "dnsmasq answers a local DNS request";
      script = ''
        vm.wait_until_succeeds(
            "dig -p ${toString cfg.port} @127.0.0.1 localhost A +short | grep -Fx 127.0.0.1",
            timeout=30,
        )
      '';
    }
  ];
}
