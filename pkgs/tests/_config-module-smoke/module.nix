##! Package config-output smoke module.
{
  lib,
  config,
  outputs,
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
    type = lib.types.str;
    default = "${outputs.dependencies.bash}/bin/bash";
    description = "Resolved dependency-backed command for the config-output smoke fixture.";
  };

  options.configModuleSmoke.privateMessage = lib.mkOption {
    type = lib.types.str;
    default = private.assertionMessage;
    description = "Value imported from the config output's private helper.";
  };

  config = lib.mkIf config.configModuleSmoke.enable {};
}
