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
  localeOverride = system.extendModules {
    runtimeModules = [./_native-locale-override.nix];
  };
  localeEffects = localeOverride.config.aos.abilities.configuration.operations.file.effects;
  localeSession = localeOverride.config.environment.sessionVariables;
  replay = selected:
    import ./native-stage-replay.nix {
      inherit lib;
      inherit (selected) config;
    };
in {
  debug = replay debug;
  localeOverride = replay localeOverride;
  crucible = replay crucible;
  debugPolicy = assert debug.config.aos.getty.autologin.enable;
  assert debug.config.aos.security.level == "debug"; true;
  localeOverridePolicy = assert localeOverride.config.aos.system.locale == "de_DE.UTF-8";
  assert localeSession.LANG == "en_US.UTF-8";
  assert localeEffects.host-locale-profile.input.content == "export LANG=${lib.escapeShellArg localeSession.LANG}\nexport LOCPATH=${lib.escapeShellArg localeSession.LOCPATH}\n";
  assert localeEffects.host-locale-conf.input.content == "LANG=${lib.escapeShellArg localeSession.LANG}\n";
  assert localeOverride.config.aos.configurationLower.files."profile.d/20-locale.sh".text == localeEffects.host-locale-profile.input.content;
  assert localeOverride.config.aos.configurationLower.files."locale.conf".text == localeEffects.host-locale-conf.input.content; true;
  cruciblePolicy = assert crucible.config.aos.abilityCrucible.enable; true;
}
