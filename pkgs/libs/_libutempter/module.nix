##! Owns the privileged terminal-accounting helper and its utmp group.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.security.utempter;
  group = config.aos.abilities.identity.operations.group.effects.utempter;
in {
  options.aos.security.utempter.enable = lib.mkEnableOption "terminal accounting through libutempter";
  config = lib.mkIf cfg.enable {
    aos.abilities = {
      identity.operations.group.effects.utempter.input = {
        name = "utmp";
        requested_id = 22;
      };
      filesystem.operations.privilegedExecutable.effects.utempter = {
        after = [group.outputs.name];
        input = {
          name = "utempter";
          source = "${package}/libexec/utempter/utempter";
          owner = "root";
          group = "utmp";
          mode = "2711";
        };
      };
    };
  };
}
