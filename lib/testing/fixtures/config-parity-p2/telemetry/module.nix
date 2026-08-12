{config, lib, ...}: {
  options.telemetry.summary = lib.mkOption {
    type = lib.types.str;
  };
  config.telemetry.summary = builtins.concatStringsSep ":" [
    (builtins.toString config.firewall.port)
    (builtins.toString config.web.port)
    (builtins.toString config.database.port)
  ];
}
