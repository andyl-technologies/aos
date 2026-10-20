##! Package-owned configuration that lowers to a deferred operation.
{
  config,
  lib,
  ...
}: {
  imports = [
    ({lib, ...}: {
      options.aos.packages.echo.message = lib.mkOption {
        type = lib.types.str;
        default = "package-scoped";
      };
    })
  ];
  options.aos.packages.echo = {
    enable = lib.mkEnableOption "the echo fixture";
  };
  config = lib.mkIf config.aos.packages.echo.enable {
    aos.abilities.echo.operations.run.effects.main.input.message = config.aos.packages.echo.message;
  };
}
