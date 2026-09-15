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

  config = lib.mkIf config.aos.security.utempter.enable {
    aos.security.wrappers.utempter = {
      source = {
        artifact = lib.abilities.packageOutput {package = "libutempter";};
        path = "lib/utempter/utempter";
      };
      group = "utmp";
      mode = "2711";
    };
  };
}
