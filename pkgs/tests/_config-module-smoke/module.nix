##! Package config-output smoke module.
{
  lib,
  config,
  ...
}: let
  private = import ./private.nix {inherit lib;};
in {
  options.configModuleSmoke.enable = lib.mkOption {
    type = lib.types.bool;
    default = private.enabledByDefault;
    description = "Enable the config-output smoke fixture.";
  };

  options.configModuleSmoke.command = lib.mkOption {
    type = lib.abilities.types.executableReference;
    default = {
      artifact = lib.abilities.packageOutput {package = "bash";};
      entry_point = "bin/bash";
      arguments = [];
    };
    description = "Symbolic dependency-backed command for the package-module smoke fixture.";
  };

  options.configModuleSmoke.privateMessage = lib.mkOption {
    type = lib.types.str;
    default = private.assertionMessage;
    description = "Value imported from the config output's private helper.";
  };

  config = lib.mkIf config.configModuleSmoke.enable {};
}
