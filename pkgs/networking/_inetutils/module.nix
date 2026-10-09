##! Configures optional privileged GNU ping executables through filesystem effects.
{
  config,
  lib,
  package,
  ...
}: {
  options.aos.inetutils.privilegedPing.enable = lib.mkEnableOption "privileged ping and ping6 wrappers";

  config.aos.abilities.filesystem.operations.privilegedExecutable.effects = lib.mkIf config.aos.inetutils.privilegedPing.enable (
    builtins.listToAttrs (map (name: {
      name = "inetutils-${name}";
      value.input = {
        inherit name;
        source = "${package}/bin/${name}";
        owner = "root";
        group = "root";
        mode = "4755";
      };
    }) ["ping" "ping6"])
  );
}
