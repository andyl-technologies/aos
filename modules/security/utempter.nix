##! modules/security/utempter.nix — Privileged terminal accounting helper
{
  config,
  lib,
  pkgs,
  ...
}: {
  options.aos.security.utempter.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Allow terminal programs to update utmp through libutempter.";
  };

  config.environment.systemPackages =
    lib.mkIf config.aos.security.utempter.enable [pkgs.libutempter];
}
