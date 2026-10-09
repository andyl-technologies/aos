##! Preserves the DNS runtime query check.
{cfg}: {
  description = "BIND DNS service checks";
  checks = [
    {
      name = "dns-query";
      description = "named answers a DNS request through its configured listener";
      script = ''
        vm.wait_until_succeeds(
            "dig -p ${toString cfg.port} @127.0.0.1 version.bind TXT CH +short",
            timeout=30,
        )
      '';
    }
  ];
}
