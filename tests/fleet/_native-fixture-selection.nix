##! Binds fixture qualification to the same retained sources as its host stage.
{lib}: {
  runtimeSystem,
  scenarioSources,
  adoptionSystem ? runtimeSystem,
  adoptionSources ? scenarioSources,
}: let
  retain = source:
    if lib.hasPrefix "/nix/store/" (builtins.toString source)
    then source
    else
      builtins.path {
        path = source;
        name = builtins.baseNameOf source;
      };
  sources = map retain scenarioSources;
  bundle = runtimeSystem.config.system.build.hostDeploymentBundle;
  adoptedSources = map retain adoptionSources;
  adoptionBundle = adoptionSystem.config.system.build.hostDeploymentBundle;
in
  assert sources != []; {
    inherit sources;
    qualification = assert adoptedSources != []; {
      selectedEvaluation = {
        role = "scenario";
        locator = builtins.toString bundle;
        scenario_sources = map builtins.toString sources;
      };
      adoptionEvaluation = {
        role = "scenario";
        locator = builtins.toString adoptionBundle;
        scenario_sources = map builtins.toString adoptedSources;
      };
      candidateRuntimeCompanions = map (evaluation: {inherit evaluation;}) (lib.unique [
        (builtins.toString bundle)
        (builtins.toString adoptionBundle)
      ]);
      # Fleet closure fields accept packages, while the bundle already retains
      # these exact source roots. The collector also pins their original bytes.
      extraClosures = lib.unique [bundle adoptionBundle];
      setupBody = "";
    };
  }
