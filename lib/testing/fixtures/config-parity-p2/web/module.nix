{config, lib, ...}: let
  readFirewallPort = import ./read-firewall-port.nix;
in {
  options.web.port = lib.mkOption {
    type = lib.types.int;
  };
  config.web.port = readFirewallPort config;
}
