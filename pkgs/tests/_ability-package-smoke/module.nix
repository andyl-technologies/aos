##! Exercises native package schema projection and retained handler closures.
{
  lib,
  dependencies,
  ...
}: {
  aos.abilities.packageSmoke.operations.echo = {
    input.options = {
      enabled = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Requested fixture value.";
      };
      label = lib.mkOption {
        type = lib.types.str;
        default = "café 東京 😀";
        description = "Unicode boundary value.";
      };
      maximum = lib.mkOption {
        type = lib.types.ints.between (-9007199254740991) 9007199254740991;
        default = 9007199254740991;
        description = "Largest portable integer.";
      };
      minimum = lib.mkOption {
        type = lib.types.ints.between (-9007199254740991) 9007199254740991;
        default = -9007199254740991;
        description = "Smallest portable integer.";
      };
    };
    result.options = {
      enabled = lib.mkOption {
        type = lib.types.bool;
        description = "Echoed fixture value.";
      };
      label = lib.mkOption {
        type = lib.types.str;
        description = "Exact Unicode echo.";
      };
      maximum = lib.mkOption {
        type = lib.types.int;
        description = "Exact maximum integer.";
      };
      minimum = lib.mkOption {
        type = lib.types.int;
        description = "Exact minimum integer.";
      };
    };
    handler.program = dependencies.ability-package-smoke-provider;
  };
}
