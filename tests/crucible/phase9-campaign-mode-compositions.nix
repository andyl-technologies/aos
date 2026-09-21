{baseSystem}: let
  mkComposition = mode: let
    enabled = mode == "enabled";
    system = baseSystem.extendModules {
      modules = [
        {
          aos.services.crucibleCampaign = {
            enable = enabled;
          };
        }
      ];
    };
  in {
    inherit mode system;
    configurationIdentity = system.config.aos.services.crucibleCampaign._runtimeIdentity;
    toplevel = system.config.system.build.toplevel;
  };
in {
  disabled = mkComposition "disabled";
  enabled = mkComposition "enabled";
}
