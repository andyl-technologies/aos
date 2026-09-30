##! Replays optional native profile policies from their retained operator sources.
{
  lib,
  system,
}: let
  debug = system.extendModules {
    modules = [
      {
        aos.profiles.debug = {
          enable = true;
          autologin = true;
        };
      }
    ];
  };
  crucible = system.extendModules {
    modules = [{aos.profiles.abilityCrucible.enable = true;}];
  };
  replay = selected:
    import ./native-stage-replay.nix {
      inherit lib;
      inherit (selected) config;
    };
in {
  debug = replay debug;
  crucible = replay crucible;
  debugPolicy = assert debug.config.aos.getty.autologin.enable;
  assert debug.config.aos.security.level == "debug"; true;
  cruciblePolicy = assert crucible.config.aos.abilityCrucible.enable; true;
}
