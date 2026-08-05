{config, ...}: {
  environment.etc."rfc0011/parity" = {
    text = "providers=${config.telemetry.summary}\n";
    mode = "0644";
  };
}
