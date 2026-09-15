##! Selects the package-owned AOS registry hub module.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.registry-hub;
in {
  options.aos.registry-hub.package = lib.mkOption {
    type = lib.types.package;
    default = pkgs.aos-hub;
    defaultText = "pkgs.aos-hub";
    description = "The package that owns and runs the AOS registry hub service.";
  };

  config.environment.systemPackages = [cfg.package];
}
