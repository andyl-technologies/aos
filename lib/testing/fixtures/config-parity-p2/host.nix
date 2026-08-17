{config, ...}: {
  environment.etc."config-parity/p2" = {
    text = "providers=${config.telemetry.summary}\n";
    mode = "0644";
  };
}
