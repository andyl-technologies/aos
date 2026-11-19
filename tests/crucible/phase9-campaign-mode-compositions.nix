{baseSystem}: let
  mkComposition = mode: let
    enabled = mode == "enabled";
    system = baseSystem.extendModules {
      modules = [
        {
          aos.crucible.campaign = {
            enable = enabled;
          };
        }
      ];
    };
  in {
    inherit mode system;
    configurationIdentity = system.config.aos.crucible.campaign._runtimeIdentity;
    toplevel = system.config.system.build.toplevel;
  };
in {
  disabled = mkComposition "disabled";
  enabled = mkComposition "enabled";
}
