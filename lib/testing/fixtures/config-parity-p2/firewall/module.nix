{lib, ...}: {
  options.firewall.port = lib.mkOption {
    type = lib.types.int;
  };
  config.firewall.port = 8080;
}
